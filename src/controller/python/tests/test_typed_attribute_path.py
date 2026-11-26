import unittest
from types import SimpleNamespace
from unittest.mock import patch

import matter.clusters as Clusters
from matter.clusters import Attribute


class TestTypedAttributePath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Attribute._BuildAttributeIndex()

    def test_generated_paths_preserve_schema_names_and_ids(self):
        names = {}
        for (cluster_id, attribute_id), (attribute_type, cluster_type) in Attribute._AttributeIndex.items():
            if cluster_type not in names:
                names[cluster_type] = {entry.Tag: entry.Label for entry in cluster_type.descriptor.Fields}
            with self.subTest(cluster=cluster_id, attribute=attribute_id):
                path = Attribute.AttributePath(1, cluster_id, attribute_id)
                result = Attribute.TypedAttributePath(Path=path)
                self.assertIs(result.AttributeType, attribute_type)
                self.assertIs(result.ClusterType, cluster_type)
                self.assertEqual(result.AttributeName, names[cluster_type][attribute_id])
                self.assertEqual((result.ClusterId, result.AttributeId), (cluster_id, attribute_id))
                self.assertEqual(result.Path, path)

    def test_subscription_path_resolution_reuses_index_and_metadata(self):
        class NoScan(dict):
            def __iter__(self):
                raise AssertionError("Report callbacks must not scan the generated attribute index")

        class NoDescriptor:
            def __get__(self, obj, owner):
                raise AssertionError("Report callbacks must not reconstruct generated cluster metadata")

        with patch.object(Attribute, '_AttributeIndex', NoScan(Attribute._AttributeIndex)), \
                patch.object(Clusters.OnOff, 'descriptor', NoDescriptor()):
            for _ in range(100):
                resolved = Attribute.TypedAttributePath(Path=Attribute.AttributePath(1, Clusters.OnOff.id, 0))
                explicit = Attribute.TypedAttributePath(ClusterType=Clusters.OnOff,
                                                        AttributeType=Clusters.OnOff.Attributes.OnOff)
                self.assertEqual(resolved.AttributeName, 'onOff')
                self.assertEqual(explicit.AttributeName, resolved.AttributeName)

    def test_unknown_and_wildcard_paths_remain_errors(self):
        for path in (Attribute.AttributePath(1, 0x12345678, 0),
                     Attribute.AttributePath(1, Clusters.OnOff.id, 0x12345678),
                     Attribute.AttributePath(1, Clusters.OnOff.id, None)):
            with self.subTest(path=path), self.assertRaisesRegex(KeyError, 'No Schema found'):
                Attribute.TypedAttributePath(Path=path)

    def test_constructor_requires_one_path_representation(self):
        for arguments in ({}, {'ClusterType': Clusters.OnOff},
                          {'ClusterType': Clusters.OnOff, 'AttributeType': Clusters.OnOff.Attributes.OnOff,
                           'Path': Attribute.AttributePath(1, Clusters.OnOff.id, 0)}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                Attribute.TypedAttributePath(**arguments)

    def test_explicit_custom_cluster_metadata_and_missing_label(self):
        class CustomCluster:
            id = 0x12345678
            descriptor = SimpleNamespace(Fields=[SimpleNamespace(Tag=42, Label='CustomLabel')])

        class CustomAttribute:
            attribute_id = 42

        result = Attribute.TypedAttributePath(ClusterType=CustomCluster, AttributeType=CustomAttribute)
        self.assertEqual(result.AttributeName, 'CustomLabel')
        self.assertEqual((result.ClusterId, result.AttributeId), (CustomCluster.id, 42))
        CustomCluster.descriptor = SimpleNamespace(Fields=[])
        with self.assertRaisesRegex(KeyError, 'Unable to resolve name'):
            Attribute.TypedAttributePath(ClusterType=CustomCluster, AttributeType=CustomAttribute)


if __name__ == '__main__':
    unittest.main()
