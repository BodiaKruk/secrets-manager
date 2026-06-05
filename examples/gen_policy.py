import json

import yaml

from secretsmanager.policy import PolicyTranslator

doc = yaml.safe_load("""
rules:
  - path: "prod/db-password"
    capabilities: ["read", "list"]
    description: "Read-only access to prod DB password"
    principals:
      - type: aws_iam_role
        id: "arn:aws:iam::123456789012:role/app-role"
""")
PolicyTranslator.validate_yaml(doc)

hcl = PolicyTranslator.toHCL(doc)
with open("policy.hcl", "w") as fh:
    fh.write(hcl)
print("=== HCL ===")
print(hcl)

print("=== IAM JSON ===")
print(
    json.dumps(
        PolicyTranslator.toIAMJson(doc, account_id="123456789012", region="us-east-1"), indent=2
    )
)
