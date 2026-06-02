"""Integration tests for AWS Secrets Manager adapter using LocalStack.

Start LocalStack:
  docker run --rm -p 4566:4566 localstack/localstack

Run with:  pytest -m integration tests/integration/test_aws_integration.py
"""

from __future__ import annotations

import os

import pytest

LOCALSTACK_ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")


@pytest.fixture(scope="module")
def aws():
    pytest.importorskip("boto3")
    from secretsmanager.adapters.aws import AwsSecretsManagerAdapter

    adapter = AwsSecretsManagerAdapter(
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        endpoint_url=LOCALSTACK_ENDPOINT,
    )
    if not adapter.health_check():
        pytest.skip("LocalStack not reachable")
    return adapter


@pytest.mark.integration
def test_aws_create_and_read(aws):
    aws.set_secret("integration/aws-key", "aws-secret-value")
    sv = aws.get_secret("integration/aws-key")
    assert sv.value == "aws-secret-value"
    assert sv.backend == "aws"


@pytest.mark.integration
def test_aws_update_secret(aws):
    aws.set_secret("integration/aws-updatable", "original")
    aws.set_secret("integration/aws-updatable", "updated")
    sv = aws.get_secret("integration/aws-updatable")
    assert sv.value == "updated"


@pytest.mark.integration
def test_aws_list_secrets_prefix(aws):
    aws.set_secret("integration/listed-aws", "v")
    names = aws.list_secrets("integration/listed")
    assert any("listed-aws" in n for n in names)


@pytest.mark.integration
def test_aws_delete_force(aws):
    from secretsmanager.interface import SecretNotFoundError

    aws.set_secret("integration/aws-delete-me", "bye")
    aws.delete_secret("integration/aws-delete-me", force=True)
    with pytest.raises((SecretNotFoundError, Exception)):
        aws.get_secret("integration/aws-delete-me")
