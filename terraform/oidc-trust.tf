# terraform/oidc-trust.tf
#
# Keyless GitHub Actions -> AWS auth for the grc-gate pipeline.
# Adapted from the Lab 4.3 oidc-trust primitive. Unlike that primitive
# (ReadOnlyAccess only), THIS role has to actually run `terraform apply`
# and write to the evidence vault, so the permissions policy below is
# a TODO, not a copy-paste.
#
# Trust is scoped to var.github_repo. Never loosen the `sub` condition
# to a wildcard repo/org, that's the same lesson as GAP-07 (least
# privilege), applied to who can assume this role at all.

variable "github_org" {
  type    = string
  default = "grckdm"
}

variable "github_repo" {
  type = string
  # The fork kept the original starter repo's name, only the local
  # clone directory is "cgep-capstone". This must match the actual
  # GitHub repo or the OIDC trust policy's `sub` condition never matches
  # the token GitHub Actions sends, and AssumeRoleWithWebIdentity fails.
  default = "cgep-app-starter"
}

# GitHub's OIDC subject claim now includes immutable numeric IDs appended
# to the owner and repo name, "repo:OWNER@ownerID/REPO@repoID:ref:...",
# not the plain "repo:OWNER/REPO:..." most docs/tutorials still show. This
# is a real security hardening (a renamed/transferred repo can't inherit
# another repo's trust via name reuse), but it means a plain org/repo
# StringLike pattern silently never matches and AssumeRoleWithWebIdentity
# fails with "Not authorized" (discovered by decoding the actual token
# GitHub sent in a run, not from documentation). Confirmed via a run
# against this exact repo:
#   sub = "repo:grckdm@44270347/cgep-app-starter@1363237393:ref:refs/heads/main"
variable "github_owner_id" {
  type    = string
  default = "44270347"
}

variable "github_repo_id" {
  type    = string
  default = "1363237393"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "grc_gate" {
  name = "${local.name_prefix}-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}:*"
        }
      }
    }]
  })
}

# Scoped to exactly the resource types this stack's Terraform manages.
# Do NOT attach AdministratorAccess, that's the GAP-07 mistake at the
# pipeline-identity level instead of the Lambda level.
#
# NOTE ON A REAL LIMIT OF IAM SCOPING HERE: this role provisions the
# entire stack via `terraform apply`, including oidc-trust.tf itself,
# its own trust policy and this very permissions policy. That means
# grc_gate can, in principle, modify its own permissions/trust boundary
# if a merged change to main asked it to. No IAM policy on this role can
# close that self-modification path (you can't scope a role out of
# managing itself while still letting Terraform manage all of main.tf).
# The actual control here is process, not IAM: branch protection on
# main (required review before merge) is what prevents an untrusted
# change from ever reaching this role's apply step. Documented in
# WRITEUP.md rather than left as an unstated assumption.
resource "aws_iam_role_policy" "grc_gate_provisioning" {
  name = "grc-gate-provisioning"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Ec2Vpc"
        Effect = "Allow"
        Action = [
          # Read actions are broadened to Describe*/Get* rather than an
          # enumerated list: the AWS provider's refresh cycle calls many
          # read-only APIs per resource (e.g. DescribeVpcAttribute for
          # aws_vpc, separate from DescribeVpcs) that aren't documented
          # and vary by provider version. Discovered the hard way, the
          # first real pipeline run failed on a missing
          # ec2:DescribeVpcAttribute grant that a narrower list missed.
          "ec2:Describe*",
          "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet", "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable",
          "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints", "ec2:ModifyVpcEndpoint",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
          "ec2:CreateTags", "ec2:DeleteTags",
        ]
        # EC2 read/create actions on not-yet-existing resources generally
        # cannot be scoped to a specific ARN, this is the standard AWS
        # limitation, not a shortcut taken here.
        Resource = "*"
      },
      {
        Sid    = "Lambda"
        Effect = "Allow"
        Action = [
          "lambda:Get*", "lambda:List*",
          "lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
          "lambda:DeleteFunction", "lambda:AddPermission", "lambda:RemovePermission",
          "lambda:TagResource", "lambda:UntagResource",
        ]
        Resource = "arn:aws:lambda:*:*:function:${local.name_prefix}-*"
      },
      {
        Sid    = "DynamoDb"
        Effect = "Allow"
        Action = [
          "dynamodb:Describe*", "dynamodb:List*",
          "dynamodb:CreateTable", "dynamodb:UpdateTable", "dynamodb:DeleteTable",
          "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:UpdateTimeToLive",
          "dynamodb:UpdateContinuousBackups",
        ]
        Resource = "arn:aws:dynamodb:*:*:table/${local.name_prefix}-*"
      },
      {
        Sid    = "S3BucketManagement"
        Effect = "Allow"
        Action = [
          # Same reasoning as Ec2Vpc: the (legacy-compat) aws_s3_bucket
          # refresh path reads many sub-configurations (CORS, logging,
          # lifecycle, replication, notification, ownership controls...)
          # regardless of whether this stack sets them. Broadened after
          # the first pipeline run failed on a missing s3:GetBucketCORS.
          "s3:Get*", "s3:List*",
          "s3:CreateBucket", "s3:DeleteBucket",
          "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
          "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock", "s3:PutBucketObjectLockConfiguration",
          "s3:PutBucketTagging",
        ]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-*",
          "arn:aws:s3:::${local.name_prefix}-*/*",
        ]
      },
      {
        Sid      = "IamRoleManagement"
        Effect   = "Allow"
        Action   = ["iam:Get*", "iam:List*", "iam:CreateRole", "iam:UpdateRole", "iam:DeleteRole", "iam:TagRole", "iam:UntagRole"]
        Resource = "arn:aws:iam::*:role/${local.name_prefix}-*"
      },
      {
        Sid    = "IamRolePolicyManagement"
        Effect = "Allow"
        Action = [
          "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
        ]
        Resource = "arn:aws:iam::*:role/${local.name_prefix}-*"
      },
      {
        Sid      = "IamPassRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::*:role/${local.name_prefix}-lambda-*"
      },
      {
        Sid    = "IamOidcProvider"
        Effect = "Allow"
        Action = [
          "iam:GetOpenIDConnectProvider", "iam:CreateOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProviderThumbprint", "iam:TagOpenIDConnectProvider",
        ]
        Resource = "arn:aws:iam::*:oidc-provider/token.actions.githubusercontent.com"
      },
      {
        Sid    = "Kms"
        Effect = "Allow"
        Action = [
          "kms:Describe*", "kms:Get*", "kms:List*",
          "kms:CreateKey", "kms:EnableKeyRotation", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion",
          "kms:CreateAlias", "kms:DeleteAlias", "kms:TagResource", "kms:UpdateKeyDescription",
        ]
        # KMS key IDs are assigned by AWS at creation and can't be
        # predicted for a Resource ARN before the key exists.
        Resource = "*"
      },
      {
        Sid    = "CloudTrail"
        Effect = "Allow"
        Action = [
          "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
          "cloudtrail:CreateTrail", "cloudtrail:StartLogging", "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail", "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors",
          "cloudtrail:AddTags", "cloudtrail:RemoveTags",
        ]
        Resource = "arn:aws:cloudtrail:*:*:trail/${local.name_prefix}-*"
      },
      {
        Sid    = "ApiGateway"
        Effect = "Allow"
        Action = ["apigateway:GET", "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE"]
        # API Gateway's IAM model uses HTTP-verb actions on synthetic
        # /apis resource paths rather than per-resource ARNs; scoping
        # further requires resource policies API Gateway doesn't expose
        # the same way most services do.
        Resource = "arn:aws:apigateway:*::/apis*"
      },
      {
        Sid      = "Sqs"
        Effect   = "Allow"
        Action   = ["sqs:Get*", "sqs:List*", "sqs:CreateQueue", "sqs:SetQueueAttributes", "sqs:DeleteQueue", "sqs:TagQueue"]
        Resource = "arn:aws:sqs:*:*:${local.name_prefix}-*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:Describe*", "logs:Get*", "logs:List*",
          "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy",
          "logs:TagResource", "logs:PutResourcePolicy", "logs:DeleteResourcePolicy",
        ]
        # PutResourcePolicy/DescribeResourcePolicies (used by GAP-08's
        # apigw_access log resource policy) are account-scoped APIs with
        # no per-log-group Resource ARN support.
        Resource = "*"
      },
      {
        Sid      = "Sts"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
      {
        Sid    = "AccountWideListDescribe"
        Effect = "Allow"
        # A handful of List*/Describe* actions don't support resource-
        # level scoping at all (require Resource "*" specifically) even
        # though most of their sibling actions on the same service do,
        # nesting them inside an ARN-scoped statement above would
        # silently grant nothing for these specific calls. Kept separate
        # and explicit rather than folded into "*"-resource per-service
        # statements above, so it's clear these are a distinct category.
        Action = [
          "cloudtrail:DescribeTrails", "cloudtrail:ListTrails",
          "dynamodb:ListTables", "lambda:ListFunctions", "sqs:ListQueues", "s3:ListAllMyBuckets",
        ]
        Resource = "*"
      },
    ]
  })
}

# Narrower than the provisioning policy above: only what the workflow's
# "Upload to evidence vault" step actually calls (aws s3 cp, aws s3api
# head-object). Deliberately does not grant s3:GetObject/PutObject on
# any bucket other than the evidence vault.
resource "aws_iam_role_policy" "grc_gate_evidence_upload" {
  name = "grc-gate-evidence-upload"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EvidenceVaultWrite"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject"]
        Resource = "${aws_s3_bucket.evidence_vault.arn}/*"
      },
      {
        # Same gotcha as the Lambda's data-plane calls (GAP-01/02):
        # the evidence vault is SSE-KMS encrypted with the same CMK, so
        # PutObject/GetObject need explicit KMS permissions beyond the
        # S3 actions above, an S3-only grant isn't sufficient.
        Sid      = "EvidenceVaultKmsAccess"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.grc.arn
      }
    ]
  })
}

# Access to the remote state backend created by terraform/bootstrap/
# (a separate Terraform config, not this stack's resources, hence the
# hardcoded names rather than resource references). Without this, CI's
# `terraform init`/plan/apply can't read or lock the shared state.
resource "aws_iam_role_policy" "grc_gate_backend_access" {
  name = "grc-gate-backend-access"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "TfStateBucket"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::cgep-capstone-tfstate-4821931c", "arn:aws:s3:::cgep-capstone-tfstate-4821931c/cgep-capstone/*"]
      },
      {
        Sid      = "TfLockTable"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:*:*:table/cgep-capstone-tflock"
      }
    ]
  })
}

output "grc_gate_role_arn" {
  value       = aws_iam_role.grc_gate.arn
  description = "AWS_ROLE_ARN repo variable for the GitHub Actions workflow."
}
