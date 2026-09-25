"""Cloud provider adapters (spec §17): provider-independent discovery + attack
paths for AWS/Azure/GCP, Engagement scope-gated, reusing IAM privesc analysis.
"""
from core.cloud.providers.base import (
    CloudProvider, CloudInventory, CloudSource, SnapshotSource, cloud_path,
)
from core.cloud.providers.aws import AwsProvider
from core.cloud.providers.azure import AzureProvider
from core.cloud.providers.gcp import GcpProvider

PROVIDERS = {
    "aws": AwsProvider,
    "azure": AzureProvider,
    "gcp": GcpProvider,
}

__all__ = [
    "CloudProvider", "CloudInventory", "CloudSource", "SnapshotSource",
    "cloud_path", "AwsProvider", "AzureProvider", "GcpProvider", "PROVIDERS",
]
