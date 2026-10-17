import ast
import copy
import datetime
import hashlib
import json
import logging
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

import matter.clusters as Clusters
from matter.clusters.Attribute import DataVersion

from matter_qa.library.helper_libs.exceptions import IterationError
from matter_qa.scripts.reliability_scripts import TC_RT_1_2 as production


ROOT = Path(__file__).resolve().parent
PUBLISHED = Path('/home/feasel/qa-mar6/matter-qa-read-consistency')
RELATIVE = 'src/matter_qa/scripts/reliability_scripts/TC_RT_1_2.py'
OBSERVATIONS = []


def method_node(path):
    tree = ast.parse(path.read_text())
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'TC_RT_1_2')
    return next(node for node in owner.body if isinstance(node, ast.AsyncFunctionDef)
                and node.name == 'perform_concurrent_read_attributes')


def compile_method(node):
    namespace = dict(vars(production))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                 'preserved-read-alternative', 'exec'), namespace)
    return namespace[node.name]


archived_node = method_node(ROOT / 'matter-qa-527/working' / RELATIVE)
assert ast.dump(archived_node) == ast.dump(method_node(ROOT / 'matter-qa-527-integration/working' / RELATIVE))
alternative = compile_method(archived_node)
combined_node = copy.deepcopy(method_node(PUBLISHED / RELATIVE))
combined_node.name = 'combined_read_verification'
loop = next(node for node in archived_node.body if isinstance(node, ast.For)
            and isinstance(node.target, ast.Name) and node.target.id == 'result')
position = next(index for index, node in enumerate(combined_node.body)
                if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                                                       and target.id == 'reference_result' for target in node.targets))
assert isinstance(combined_node.body[position + 1], ast.Expr)
combined_node.body[position:position + 2] = [copy.deepcopy(loop)]
combined = compile_method(combined_node)


def response(on=True, feature=1, omit_written=False, omit_feature=False):
    attributes = {}
    if not omit_written:
        attributes[Clusters.OnOff.Attributes.StartUpOnOff] = (
            Clusters.OnOff.Enums.StartUpOnOffEnum.kOn if on else Clusters.OnOff.Enums.StartUpOnOffEnum.kOff)
    if not omit_feature:
        attributes[Clusters.OnOff.Attributes.FeatureMap] = feature
    return {1: {Clusters.OnOff: attributes}}


def attribute_info(attribute, name, value):
    return SimpleNamespace(attribute_obj=attribute, attribute_id=attribute.attribute_id,
                           attribute_name=name, value=value, quieter_reporting=False)


def make_case(results):
    case = object.__new__(production.TC_RT_1_2)
    written = attribute_info(Clusters.OnOff.Attributes.StartUpOnOff, 'StartUpOnOff',
                             Clusters.OnOff.Enums.StartUpOnOffEnum.kOn)
    feature = attribute_info(Clusters.OnOff.Attributes.FeatureMap, 'FeatureMap', 1)
    case.endpoint_map = {1: SimpleNamespace(server_clusters=[SimpleNamespace(
        cluster_obj=Clusters.OnOff, cluster_id=Clusters.OnOff.id, cluster_name='OnOff', Attributes=[written, feature])])}
    case._writable_attributes = [(1, written)]
    case._read_write_list = None
    case._write_payload = [(1, Clusters.OnOff.Attributes.StartUpOnOff(Clusters.OnOff.Enums.StartUpOnOffEnum.kOn))]
    case._write_timestamp = datetime.datetime.now()
    case.write_result = []
    case._execute_read_task = AsyncMock(side_effect=copy.deepcopy(results))
    return case


SCENARIOS = {
    'matching_written_and_stable_values': ([response(), response()], (False, False, False)),
    'unwritten_feature_mismatch': ([response(feature=1), response(feature=2)], (True, False, True)),
    'unwritten_feature_missing': ([response(), response(omit_feature=True)], (True, False, True)),
    'written_value_mismatch': ([response(on=True), response(on=False)], (True, True, True)),
    'both_written_values_wrong': ([response(on=False), response(on=False)], (True, True, True)),
    'all_responses_omit_written_attribute': ([response(omit_written=True), response(omit_written=True)],
                                              (False, True, True)),
    'read_operation_error': ([response(), IterationError('synthetic read failure')], (True, True, True)),
    'cache_metadata_difference': ([response(), response()], (False, False, False)),
}
SCENARIOS['cache_metadata_difference'][0][0][1][Clusters.OnOff][DataVersion] = 1
SCENARIOS['cache_metadata_difference'][0][1][1][Clusters.OnOff][DataVersion] = 2


class ReadAlternativeControls(unittest.IsolatedAsyncioTestCase):
    async def check_variant(self, variant):
        functions = {'published': production.TC_RT_1_2.perform_concurrent_read_attributes,
                     'alternative': alternative, 'combined': combined}
        position = ('published', 'alternative', 'combined').index(variant)
        for name, (results, expected) in SCENARIOS.items():
            with self.subTest(variant=variant, scenario=name):
                case = make_case(results)
                controllers = [(SimpleNamespace(name='TH1', GetCompressedFabricId=lambda: 1), 1),
                               (SimpleNamespace(name='TH2', GetCompressedFabricId=lambda: 2), 2)]
                rejected = False
                try:
                    await functions[variant](case, controllers)
                    if variant == 'published':
                        case.verify_bulk_attributes_write_results()
                except IterationError:
                    rejected = True
                OBSERVATIONS.append({'variant': variant, 'scenario': name, 'rejected': rejected,
                                     'expected_rejected': expected[position]})
                self.assertEqual(rejected, expected[position])

    async def test_published_controls(self):
        await self.check_variant('published')

    async def test_alternative_controls(self):
        await self.check_variant('alternative')

    async def test_combined_controls(self):
        await self.check_variant('combined')


def archived_tests():
    path = ROOT / 'matter-qa-527/working/src/matter_qa/unit_tests/test_pairing_cleanup.py'
    tree = ast.parse(path.read_text())
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'PairingCleanupTest')
    methods = [node for node in owner.body if isinstance(node, ast.AsyncFunctionDef)
               and node.name.startswith(('test_rt12_concurrent_', 'test_rt12_missing_'))]
    assert len(methods) == 3
    extracted = ast.ClassDef(name='ArchivedReadTests', bases=[ast.Attribute(value=ast.Name(id='unittest', ctx=ast.Load()),
                                                                        attr='IsolatedAsyncioTestCase', ctx=ast.Load())],
                             keywords=[], body=methods, decorator_list=[])
    from unittest.mock import MagicMock, call
    namespace = {'unittest': unittest, 'MagicMock': MagicMock, 'AsyncMock': AsyncMock, 'call': call,
                 'SimpleNamespace': SimpleNamespace, 'IterationError': IterationError,
                 'TC_RT_1_2': SimpleNamespace(perform_concurrent_read_attributes=alternative)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[extracted], type_ignores=[])),
                 'archived-three-read-tests', 'exec'), namespace)
    return unittest.defaultTestLoader.loadTestsFromTestCase(namespace['ArchivedReadTests'])


if __name__ == '__main__':
    logging.disable(logging.CRITICAL)
    assert Path(production.__file__).resolve() == PUBLISHED / RELATIVE
    published_head = subprocess.check_output(['git', '-C', str(PUBLISHED), 'rev-parse', 'HEAD'], text=True).strip()
    assert not subprocess.check_output(['git', '-C', str(PUBLISHED), 'status', '--porcelain'], text=True)
    source_sha256 = hashlib.sha256((PUBLISHED / RELATIVE).read_bytes()).hexdigest()
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(ReadAlternativeControls), archived_tests()])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    assert not subprocess.check_output(['git', '-C', str(PUBLISHED), 'status', '--porcelain'], text=True)
    assert source_sha256 == hashlib.sha256((PUBLISHED / RELATIVE).read_bytes()).hexdigest()
    proof = {'published_source': str(PUBLISHED / RELATIVE), 'published_head': published_head,
             'published_source_sha256': source_sha256, 'archived_three_tests_preserved': True,
             'both_archived_read_methods_ast_equal': True,
             'all_production_sources_unchanged': True, 'synthetic_cpu_only_no_hardware': True,
             'combined_variant_in_memory_only': True, 'tests_run': result.testsRun,
             'subcase_comparisons': OBSERVATIONS, 'failures': len(result.failures),
             'errors': len(result.errors), 'successful': result.wasSuccessful()}
    (ROOT / 'read-alternative-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    sys.exit(0 if result.wasSuccessful() else 1)
