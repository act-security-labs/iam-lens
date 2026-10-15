# `who-can` - Find who can perform an action on a resource

```bash
iam-lens who-can [options]
```

Lists all principals in your IAM data who are allowed to perform one or more specified actions on a resource (or account for wildcard only actions). If applicable it will check the resource policy to find cross-account permissions and AWS service principals.

This works by starting with the resource policy (if any) and looking for all principals, accounts, and organizations that have access to the resource. It will then check each principal for the specified actions and return a list of all principals that are allowed to perform the action.

## Anonymous Access

When a resource policy contains an Allow that may grant unsigned access, `who-can` also evaluates anonymous access. Allowed results use `"principal": "anonymous"`, including `allowedPatterns` when the request contains wildcard resources such as `arn:aws:s3:::public-bucket/*`.

Candidates include wildcard AWS principals and `NotPrincipal` Allows. Known service-only wildcard statements are excluded; arbitrary conditions and resource-side controls are evaluated by the simulator. Anonymous results may therefore be conditional. No anonymous simulation runs without a candidate statement, without a resource, or for wildcard-only actions.

For library callers, a supplied `principalScope` includes unsigned access only when `anonymous: true`. An empty scope (`{}`) excludes anonymous access; `{ anonymous: true }` checks only unsigned access. Omitting `principalScope` includes candidate anonymous checks as usual.

Anonymous simulations participate in `simulationCount`, optional grant details, and optional deny details (which also use `"principal": "anonymous"`).

## Conditional Access Output

Allowed results may include a `conditions` field when access depends on request-context values. This field is a structured expression from `iam-simulate` that describes the conditions under which the principal is allowed. Unconditional allows omit `conditions`.

Allowed results may also include `ignoredConditions`, which contains the discovery-mode condition diagnostics that older `iam-lens` versions returned in `conditions`.

**Breaking change:** if you were reading `conditions` as grouped ignored condition keys, migrate that usage to `ignoredConditions`.

## Wildcard Resource ARNs

You can pass a wildcard resource ARN (for example, an S3 object prefix like `arn:aws:s3:::my-bucket/reports/*`). When the resource contains wildcards, results include `allowedPatterns` instead of top-level resource details. Each `allowedPatterns` entry tells you which specific resource patterns allowed access for that principal/action and may include its own `conditions` and `ignoredConditions` fields.

Example output snippet:

```json
{
  "principal": "arn:aws:iam::123456789012:role/AnalyticsRole",
  "service": "s3",
  "action": "GetObject",
  "level": "read",
  "allowedPatterns": [
    {
      "pattern": "arn:aws:s3:::my-bucket/reports/*",
      "resourceType": "object"
    },
    {
      "pattern": "arn:aws:s3:::my-bucket/reports/2024/*",
      "resourceType": "object"
    }
  ]
}
```

## Options

| Flag                         | Description                                                                                                                                                                                                            |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--resource <arn>`           | The ARN of the resource to check permissions for. Ignore for wildcard-only actions such as `iam:ListRoles`.                                                                                                            |
| `--resource-account <id>`    | The account ID of the resource, only required if it cannot be determined from the resource ARN. Required for wildcard actions such as `ec2:DescribeInstances`.                                                         |
| `--actions <service:action>` | One or more actions to check such as `s3:GetObject`. Specify as many actions as you want. If omitted it will analyze all valid actions for the resource. If no `--resource` is specified then actions must be entered. |
| `--s3-abac-override`         | Override the S3 ABAC setting for S3 buckets. Defaults to the bucket setting stored in your iam-collect data. Valid values are `enabled` or `disabled`.                                                                 |
| `-s`, `--sort`               | Sort the results before outputting.                                                                                                                                                                                    |

You can also include any [Global CLI Options](docs/GlobalCliOptions.md).

## Examples

```bash
# Who can get this object?
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket/secret-file.txt \
  --actions s3:GetObject

# Who can list all IAM roles in this account? (wildcard action – no resource)
iam-lens who-can \
  --resource-account 555555555555 \
  --actions iam:ListRoles

# Check multiple actions at once
iam-lens who-can \
  --resource arn:aws:dynamodb:us-east-1:555555555555:table/Books \
  --actions dynamodb:Query dynamodb:UpdateItem

# Check a wildcard resource prefix and inspect allowed patterns
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket/reports/* \
  --actions s3:GetObject

# Check all actions for a bucket
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket
```
