# AWS Certified Security - Specialty

[Exam Guide](https://aws.amazon.com/certification/certified-security-specialty/)

IAM / Policy model
- SCPs define the maximum possible permissions
- Only identity + resource policies grant
- Boundaries + session policies only restrict
- Permissions boundary = max cap on role/user
- Session policy = temp shrink permissions on assume-role
- Region restriction → identity-based policy with aws:RequestedRegion
- NotAction for global services (IAM, STS, CloudFront)
- SCPs attach to OUs/accounts, NOT IAM groups

IAM Identity Center (formerly AWS SSO)
- Central SSO for multi-account access in AWS Organizations
- Permission Sets = collections of policies → assigned to users/groups per account
- Creates IAM roles behind the scenes in target accounts
- Identity source: built-in store OR external IdP (AD, Okta, SAML 2.0)
- For multi-account → use Identity Center, not IAM users per account
- Integrates with AD via AD Connector or AWS Managed Microsoft AD

IAM Identity Center vs Cognito
- Cognito User Pools = authentication (sign-up/sign-in, returns JWT)
- Cognito Identity Pools = authorization (exchange tokens for AWS credentials)

| Scenario                              | Answer              |
|---------------------------------------|---------------------|
| Employees need AWS Console access     | Identity Center     |
| Internal workforce SSO                | Identity Center     |
| Mobile app users need to sign in      | Cognito User Pools  |
| App users need AWS credentials        | Cognito Identity Pools |
| Customer-facing authentication        | Cognito             |

IAM Groups vs Roles
- Group = collection of IAM users, applies policies to all members
- Group CANNOT be principal in resource policies (S3 bucket policy can't reference group)
- Groups cannot contain other groups (no nesting)
- Groups don't provide credentials
- Role = assumable identity with temporary credentials (via STS)
- Role CAN be principal in resource policies
- Role has trust policy (who can assume) + permissions policy (what they can do)
- Cross-account access → use roles, not groups

IAM / access troubleshooting
- VPC endpoint policy can block even if IAM allows
- Check endpoint policy before IAM / boundaries
- Assumed role auth issues → check session policy (not just boundary)
- Session policy = passed at assume-role time, easy to overlook

Service control
- Service Catalog → launch constraint = force role to use

GuardDuty
- Trusted IPs:
    same Region only
    public IPv4 only
    one list per acct per Region
- Trusted IPs evaluated first → suppress threat list findings
- Exports findings to EventBridge + optionally S3
- Cannot directly invoke Lambda → must go via EventBridge
- Automated response:
    GuardDuty → EventBridge → Lambda
    (optional DynamoDB for dedupe/state)
    → remediation (WAF / NACL) + SNS alert
- Instance isolation → update SG to remove all inbound/outbound rules
- WAF = web traffic only, not instance-level isolation

EventBridge
- SES is NOT a supported target → use Lambda to call SES

Logging / governance
- CloudTrail prefix change → update S3 policy + trail config
- Delete Firewall Manager policy → Config rules + empty WAF ACLs deleted

EC2 / networking
- No cross-Region SG refs → use CIDR
- SG rule changes do NOT drop existing connections
- Isolation requires killing existing sessions (or moving to untracked flow)
- mTLS requires server to terminate TLS → use NLB with TCP listener (passthrough)
- ALB terminates TLS itself → cannot do true mTLS to backend

WAF / traffic
- User-Agent blocking → WAF custom rules
- Missing User-Agent → custom or managed rules
- WAF logging → Kinesis Firehose → S3

KMS / EBS
- EBS + CMK launch failure:
    IAM needs kms:CreateGrant
    with condition GrantIsForAWSResource = true

KMS / imported key material
- Imported key material ≠ auto-rotatable
- Rotation = create new CMK + import new material + repoint alias
- Cannot update/replace key material in-place
- Do NOT delete + recreate KMS keys to rotate (breaks references)

Organizations
- SCPs apply to all identities incl. root
- SCPs do NOT apply to the management account

STS / Federation
- AssumeRole needs trust policy + caller allow
- ExternalId prevents confused deputy

KMS
- Key policy evaluated before IAM
- Grants bypass key policy (scoped + temp)
- You can lock yourself out with key policy
- Key policy can grant access WITHOUT IAM policy
- If key policy allows principal directly → no IAM policy needed

S3
- Block Public Access overrides bucket policy
- ACLs legacy; Object Ownership can disable ACLs
- Object Lock Governance mode → can bypass with s3:BypassGovernanceRetention
- Object Lock Compliance mode → CANNOT be bypassed by anyone incl. root

CloudFront
- OAI (Origin Access Identity) = legacy, does NOT support SSE-KMS S3 buckets
- OAC (Origin Access Control) = newer, supports SSE-KMS encrypted S3 origins
- If an S3 origin uses SSE-KMS, CloudFront must use OAC, not OAI.

EFS
- EFS security = VPC security groups + IAM policies
- Security groups = control network access to mount targets
- NACLs = subnet level, not recommended for EFS access control

VPC / Network
- SG = instance-level, stateful firewall
    attached to ENI/instance
    allow rules only
    default deny inbound / allow outbound
    return traffic auto-allowed
- NACL = subnet-level, stateless filter
    attached to subnet
    allow + deny rules
    numbered rules, lowest wins
    must allow inbound AND outbound (e.g. ephemeral 1024-65535)

VPC Endpoints / PrivateLink
- PrivateLink = technology behind Interface Endpoints
- Interface Endpoint:
    creates ENI with private IP in your subnet
    powered by PrivateLink
    supports most AWS services (SQS, SNS, Secrets Manager, etc.)
    has endpoint policy (can restrict access)
    costs money (hourly + data)
- Gateway Endpoint:
    S3 and DynamoDB only
    route table entry, no ENI
    free
    NOT PrivateLink
- On-prem access to S3 via VPN/DX → need Interface Endpoint (not Gateway)
- Traffic stays on AWS network, never traverses public internet
- Flow Logs exclude 169.254.169.254 (IMDS = Instance Metadata Service)
- IMDSv2 = session-based + more secure
- Enforce IMDSv2:
    New instances → ec2:RunInstances with --metadata-options HttpTokens=required
    Existing instances → ec2 modify-instance-metadata-options --http-tokens required
- HttpEndpoint=disabled → turns off IMDS entirely (NOT the same as requiring v2)
- NACLs CANNOT block 169.254.169.254 (link-local, not routed through network)

CloudTrail
- One org trail per org
- Data events off by default
- Can send data, Insights, and management events to CloudWatch Logs

Inspector / Macie / GuardDuty
- Inspector = vuln scan + network reachability assessments
- Inspector detects EC2 port exposure violations → use with SNS for alerts
- GuardDuty = threat detection
- Macie = S3 data classification

ACM
- DaysToExpiry CloudWatch metric for cert expiration alerts
- Security Hub does NOT have built-in ACM cert expiration monitoring
- Expiry alerting: ACM metric → CloudWatch Alarm → Lambda → SNS

Secrets
- Secrets Manager rotates
- Parameter Store Standard does not rotate
