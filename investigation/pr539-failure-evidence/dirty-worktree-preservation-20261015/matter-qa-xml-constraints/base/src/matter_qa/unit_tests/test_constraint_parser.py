import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, sentinel

from matter_qa.library.helper_libs.attribute_value_generator import AttributeValueGenerator
from matter_qa.library.helper_libs.constraint_parser import ConstraintParser
from matter_qa.library.helper_libs.exceptions import IterationError
from matter_qa.library.helper_libs.uint_tlv import UInt8


class ConstraintParserTest(unittest.IsolatedAsyncioTestCase):
    def make_cluster(self, value=3):
        return SimpleNamespace(
            cluster_obj=sentinel.cluster,
            Attributes=[SimpleNamespace(attribute_name="SupportedSensitivityLevels",
                                        attribute_obj=sentinel.attribute, value=value)])

    async def test_xml_expression_generates_value_within_attribute_bound(self):
        cluster = self.make_cluster()
        constraints = ConstraintParser.parse_constraint(
            {"min": {"@value": "0"}, "max": {"@value": "SupportedSensitivityLevels - 1"}}, cluster)
        attribute = SimpleNamespace(data_type=UInt8, constraints=constraints, attribute_obj=sentinel.current_attribute,
                                    value=None, attribute_name="CurrentSensitivityLevel")
        generator = AttributeValueGenerator()
        for attempt in range(10):
            with self.subTest(attempt=attempt):
                value = await generator.generate_value(attribute, SimpleNamespace(endpoint_id=1), cluster)
                self.assertIn(value, (0, 1, 2))

    async def test_expression_reads_uncached_reference(self):
        cluster = self.make_cluster(value=None)
        constraints = ConstraintParser.parse_constraint(
            {"max": {"@value": "SupportedSensitivityLevels - 1"}}, cluster)
        reader = AsyncMock(return_value=4)
        resolved = await ConstraintParser.resolve_constraint_value_async(
            constraints.max_value, SimpleNamespace(endpoint_id=1), cluster, reader)
        self.assertEqual(resolved, 3)
        reader.assert_awaited_once_with(cluster=sentinel.cluster, attribute=sentinel.attribute, endpoint=1)

    def test_numeric_literals_are_preserved(self):
        for literal, expected in (("0", 0), ("0x10", 16), ("1.5", 1.5), ("-2", -2)):
            with self.subTest(literal=literal):
                self.assertEqual(ConstraintParser._parse_literal_value(literal), expected)

    async def test_arithmetic_operations_resolve_in_both_paths(self):
        cluster = self.make_cluster()
        for expression, expected in (("SupportedSensitivityLevels + 2", 5),
                                     ("SupportedSensitivityLevels - 1", 2),
                                     ("SupportedSensitivityLevels * 2", 6),
                                     ("SupportedSensitivityLevels / 2", 1.5),
                                     ("SupportedSensitivityLevels - -1", 4),
                                     ("(SupportedSensitivityLevels - 1) * 2 + 1", 5)):
            with self.subTest(expression=expression):
                reference = ConstraintParser._parse_literal_value(expression)
                self.assertEqual(ConstraintParser.resolve_constraint_value(reference, None, cluster), expected)
                self.assertEqual(await ConstraintParser.resolve_constraint_value_async(reference, None, cluster), expected)

    def test_arithmetic_rejects_executable_and_unsupported_syntax(self):
        for expression in ("SupportedSensitivityLevels + __import__('os')",
                           "SupportedSensitivityLevels ** 2", "SupportedSensitivityLevels + '1'",
                           "SupportedSensitivityLevels + [1][0]"):
            with self.subTest(expression=expression):
                with self.assertRaisesRegex(ValueError, "Unsupported arithmetic constraint"):
                    ConstraintParser._parse_literal_value(expression)

    async def test_unresolved_reference_does_not_relax_numeric_bound(self):
        cluster = SimpleNamespace(Attributes=[])
        reference = ConstraintParser._parse_literal_value("SupportedSensitivityLevels - 1")
        with self.assertRaisesRegex(IterationError, "numeric values"):
            await ConstraintParser.resolve_constraint_value_async(reference, None, cluster)

    async def test_reference_read_failure_propagates(self):
        cluster = self.make_cluster(value=None)
        reader = AsyncMock(side_effect=RuntimeError("read failed"))
        reference = ConstraintParser._parse_literal_value("SupportedSensitivityLevels - 1")
        with self.assertRaisesRegex(IterationError, "read failed"):
            await ConstraintParser.resolve_constraint_value_async(reference, SimpleNamespace(endpoint_id=1), cluster, reader)

    async def test_existing_compute_xml_resolves_literal_operand(self):
        cluster = self.make_cluster()
        constraints = ConstraintParser.parse_constraint(
            {"max": {"compute": {"operation": "subtract",
                                  "left": {"attribute": {"@name": "SupportedSensitivityLevels"}},
                                  "right": {"@value": "1"}}}}, cluster)
        self.assertEqual(await ConstraintParser.resolve_constraint_value_async(constraints.max_value, None, cluster), 2)

    def test_unrelated_literal_text_is_not_interpreted_as_an_attribute(self):
        self.assertEqual(ConstraintParser._parse_literal_value("unbounded"), "unbounded")


if __name__ == "__main__":
    unittest.main()