"""Offline execution of pinned commissioning bodies with mocked native boundaries."""

import ast
import asyncio
import datetime
import os
import secrets
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock


def load_bodies(path, names, namespace, owner=None):
    """Compile selected original function bodies without importing a native SDK."""
    tree = ast.parse(path.read_text(), filename=str(path))
    nodes = tree.body
    if owner is not None:
        nodes = next(node for node in nodes if isinstance(node, ast.ClassDef) and node.name == owner).body
    selected = [node for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    if {node.name for node in selected} != set(names):
        raise AssertionError(f"Missing requested functions in {path}")
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    module = ast.fix_missing_locations(ast.Module(body=[future, *selected], type_ignores=[]))
    exec(compile(module, str(path), "exec"), namespace)


class ParsedPayload:
    def ParseQrCode(self, code):
        return SimpleNamespace(setup_passcode=20202021, short_discriminator=None, long_discriminator=3840)

    def ParseManualPairingCode(self, code):
        return SimpleNamespace(setup_passcode=20202021, short_discriminator=15)


class TestCommissioningPayloadPath(unittest.TestCase):
    def setUp(self):
        sdk = Path(os.environ["THREE_TRACK_SDK"])
        adapter = Path(os.environ["THREE_TRACK_QA_ADAPTER"])
        self.filter_types = SimpleNamespace(LONG_DISCRIMINATOR=1, SHORT_DISCRIMINATOR=2)
        self.namespace = {
            "SetupPayloadInfo": SimpleNamespace,
            "SetupPayload": ParsedPayload,
            "ChipStackError": RuntimeError,
            "discovery": SimpleNamespace(FilterType=self.filter_types),
            "DiscoveryFilterType": self.filter_types,
            "asserts": SimpleNamespace(assert_equal=self.assertEqual, fail=self.fail),
            "datetime": datetime,
            "secrets": secrets,
        }
        source = sdk / "src/python_testing/matter_testing_infrastructure/matter/testing/commissioning.py"
        load_bodies(source, ["get_setup_payload_info_config"], self.namespace)
        load_bodies(source, ["_find_or_establish_pase_if_needed"], self.namespace, owner="Commission")
        load_bodies(adapter, ["pair_device"], self.namespace, owner="ChipPythonControllerNode")
        self.controller = SimpleNamespace(
            CreateManualCode=Mock(return_value="synthetic-manual"),
            FindOrEstablishPASESession=AsyncMock(return_value=object()),
            CommissionOnNetwork=AsyncMock(return_value=object()),
            ResetCommissioningParameters=Mock(),
            _commissioning_context=SimpleNamespace(future=None),
        )
        self.original_pase = self.controller.FindOrEstablishPASESession
        self.commissioning_info = SimpleNamespace(commissioning_method="on-network")

        async def commission_device(dev_ctrl, node_id, info, commissioning_info):
            context = SimpleNamespace(dev_ctrl=dev_ctrl, node_id=node_id, info=info, commissioning_info=commissioning_info)
            await self.namespace["_find_or_establish_pase_if_needed"](context)
            return object()

        self.namespace["commission_device"] = commission_device
        self.adapter = SimpleNamespace(
            _controller=self.controller,
            _build_commissioning_info=lambda harness: self.commissioning_info,
        )

    def pair_with_config(self, config):
        infos = self.namespace["get_setup_payload_info_config"](config)
        self.assertEqual(len(infos), 1)
        harness = SimpleNamespace(
            get_setup_payload_info=lambda: infos,
            matter_test_config=SimpleNamespace(dut_node_ids=[0]),
            analytics_dict={},
        )
        asyncio.run(self.namespace["pair_device"](self.adapter, test_harness=harness, node_id=123))
        self.assertIs(self.controller.FindOrEstablishPASESession, self.original_pase)
        self.original_pase.assert_awaited_once()
        return infos[0], self.original_pase.call_args.kwargs

    def test_raw_discriminator_generates_manual_despite_long_filter_metadata(self):
        info, call = self.pair_with_config(SimpleNamespace(
            qr_code_content=[], manual_code=[], setup_passcodes=[20202021], discriminators=[3840]))
        self.assertEqual(info.filter_type, self.filter_types.LONG_DISCRIMINATOR)
        self.assertIsNone(info.setup_code)
        self.controller.CreateManualCode.assert_called_once_with(3840, 20202021)
        self.assertEqual(call, {"setupCode": "synthetic-manual", "nodeId": 123})

    def test_supplied_qr_string_is_preserved_without_manual_generation(self):
        info, call = self.pair_with_config(SimpleNamespace(
            qr_code_content=["MT:synthetic-qr"], manual_code=[], setup_passcodes=None, discriminators=None))
        self.assertEqual(info.filter_type, self.filter_types.LONG_DISCRIMINATOR)
        self.assertEqual(call["setupCode"], "MT:synthetic-qr")
        self.controller.CreateManualCode.assert_not_called()

    def test_supplied_manual_string_is_preserved(self):
        info, call = self.pair_with_config(SimpleNamespace(
            qr_code_content=[], manual_code=["synthetic-manual-input"], setup_passcodes=None, discriminators=None))
        self.assertEqual(info.filter_type, self.filter_types.SHORT_DISCRIMINATOR)
        self.assertEqual(call["setupCode"], "synthetic-manual-input")
        self.controller.CreateManualCode.assert_not_called()

    def test_direct_network_api_preserves_explicit_filter(self):
        asyncio.run(self.namespace["pair_device"](
            self.adapter, node_id=123, setup_pin_code=20202021,
            filter_type=self.filter_types.LONG_DISCRIMINATOR, filter_value=3840))
        self.controller.CommissionOnNetwork.assert_awaited_once_with(
            nodeId=123, setupPinCode=20202021, filterType=self.filter_types.LONG_DISCRIMINATOR, filter=3840)
        self.controller.CreateManualCode.assert_not_called()
        self.original_pase.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
