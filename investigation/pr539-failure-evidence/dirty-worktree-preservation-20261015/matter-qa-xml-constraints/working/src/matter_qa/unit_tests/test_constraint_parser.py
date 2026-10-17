import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch, sentinel

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

    async def test_valve_default_open_level_respects_live_level_step(self):
        cluster = SimpleNamespace(
            cluster_name="ValveConfigurationAndControl", cluster_obj=sentinel.cluster,
            Attributes=[SimpleNamespace(attribute_name="LevelStep", attribute_obj=sentinel.attribute, value=2)])
        constraints = ConstraintParser.parse_constraint(
            {"min": {"@value": "1"}, "max": {"@value": "100"}}, cluster)
        attribute = SimpleNamespace(data_type=UInt8, constraints=constraints, attribute_obj=sentinel.current_attribute,
                                    value=None, attribute_name="DefaultOpenLevel")
        with patch("matter_qa.library.helper_libs.attribute_value_generator.random.randint", return_value=77):
            value = await AttributeValueGenerator().generate_value(attribute, SimpleNamespace(endpoint_id=1), cluster)
        self.assertTrue(value == 100 or value % 2 == 0, f"Generated invalid valve level {value} for step 2")

    async def test_valve_default_open_level_reads_uncached_level_step(self):
        cluster = SimpleNamespace(
            cluster_name="ValveConfigurationAndControl", cluster_obj=sentinel.cluster,
            Attributes=[SimpleNamespace(attribute_name="LevelStep", attribute_obj=sentinel.attribute, value=None)])
        constraints = ConstraintParser.parse_constraint({"min": {"@value": "1"}, "max": {"@value": "100"}}, cluster)
        attribute = SimpleNamespace(data_type=UInt8, constraints=constraints, attribute_obj=sentinel.current_attribute,
                                    value=None, attribute_name="DefaultOpenLevel")
        reader = AsyncMock(return_value=3)
        with patch("matter_qa.library.helper_libs.attribute_value_generator.random.choice", side_effect=lambda values: values[-1]):
            value = await AttributeValueGenerator().generate_value(attribute, SimpleNamespace(endpoint_id=1), cluster, reader)
        self.assertEqual(value, 100)
        reader.assert_awaited_once_with(cluster=sentinel.cluster, attribute=sentinel.attribute, endpoint=1)

    async def test_valve_default_open_level_rejects_invalid_level_step(self):
        for step in (0, -1, 101, True, "2"):
            with self.subTest(step=step):
                cluster = SimpleNamespace(
                    cluster_name="ValveConfigurationAndControl", cluster_obj=sentinel.cluster,
                    Attributes=[SimpleNamespace(attribute_name="LevelStep", attribute_obj=sentinel.attribute, value=step)])
                constraints = ConstraintParser.parse_constraint({"min": {"@value": "1"}, "max": {"@value": "100"}}, cluster)
                attribute = SimpleNamespace(data_type=UInt8, constraints=constraints, attribute_obj=sentinel.current_attribute,
                                            value=None, attribute_name="DefaultOpenLevel")
                with self.assertRaisesRegex(IterationError, "Invalid LevelStep"):
                    await AttributeValueGenerator().generate_value(attribute, SimpleNamespace(endpoint_id=1), cluster)

    async def test_valve_default_open_level_reads_live_step_instead_of_xml_default(self):
        cluster = SimpleNamespace(
            cluster_name="ValveConfigurationAndControl", cluster_obj=sentinel.cluster,
            Attributes=[SimpleNamespace(attribute_name="LevelStep", attribute_obj=sentinel.attribute, value="1")])
        constraints = ConstraintParser.parse_constraint({"min": {"@value": "1"}, "max": {"@value": "100"}}, cluster)
        attribute = SimpleNamespace(data_type=UInt8, constraints=constraints, attribute_obj=sentinel.current_attribute,
                                    value=None, attribute_name="DefaultOpenLevel")
        reader = AsyncMock(return_value=2)
        with patch("matter_qa.library.helper_libs.attribute_value_generator.random.randint", return_value=77):
            value = await AttributeValueGenerator().generate_value(attribute, SimpleNamespace(endpoint_id=1), cluster, reader)
        self.assertTrue(value == 100 or value % 2 == 0)
        reader.assert_awaited_once_with(cluster=sentinel.cluster, attribute=sentinel.attribute, endpoint=1)

    async def test_valve_default_open_level_preserves_allowed_values_and_range(self):
        cluster = SimpleNamespace(
            cluster_name="ValveConfigurationAndControl", cluster_obj=sentinel.cluster,
            Attributes=[SimpleNamespace(attribute_name="LevelStep", attribute_obj=sentinel.attribute, value=2)])
        constraints = ConstraintParser.parse_constraint({"min": {"@value": "1"}, "max": {"@value": "99"},
                                                       "allowed": {"@value": "77"}}, cluster)
        attribute = SimpleNamespace(data_type=UInt8, constraints=constraints, attribute_obj=sentinel.current_attribute,
                                    value=None, attribute_name="DefaultOpenLevel")
        with self.assertRaisesRegex(IterationError, "No DefaultOpenLevel"):
            await AttributeValueGenerator().generate_value(attribute, SimpleNamespace(endpoint_id=1), cluster)
        self.assertEqual(constraints.allowed_values, [77])

    async def test_valve_without_optional_level_step_keeps_range_generation(self):
        cluster = SimpleNamespace(cluster_name="ValveConfigurationAndControl", cluster_obj=sentinel.cluster, Attributes=[])
        constraints = ConstraintParser.parse_constraint({"min": {"@value": "1"}, "max": {"@value": "100"}}, cluster)
        attribute = SimpleNamespace(data_type=UInt8, constraints=constraints, attribute_obj=sentinel.current_attribute,
                                    value=None, attribute_name="DefaultOpenLevel")
        with patch("matter_qa.library.helper_libs.attribute_value_generator.random.randint", return_value=77):
            value = await AttributeValueGenerator().generate_value(attribute, SimpleNamespace(endpoint_id=1), cluster)
        self.assertEqual(value, 77)

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