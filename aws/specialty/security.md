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
- Tag-based EC2 access → tag instances + IAM policy with Condition element
- Key policy with root principal → enables IAM policies to grant access

IAM Identity Center (formerly AWS SSO)
- Central SSO for multi-account access in AWS Organizations
- Permission Sets = collections of policies → assigned to users/groups per account
- Creates IAM roles behind the scenes in target accounts
- Identity source: built-in store OR external IdP (AD, Okta, SAML 2.0)
- For multi-account → use Identity Center, not IAM users per account
- Integrates with AD via AD Connector or AWS Managed Microsoft AD
- Multi-account AD SSO → Control Tower + Identity Center (NOT AD Connector per account)

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
- Explicit deny in ANY policy overrides allows in ALL other policies
- Deny-overrides-allow applies across identity + resource policies in same account

STS session policies
- Pass inline session policy during AssumeRole API call
- Effective permissions = intersection of role policy AND session policy
- Use to further restrict credentials for specific use cases

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
- WAF = web traffic only
- Severity is numeric (0.0-10.0), NOT strings like 'HIGH'
- Finding type includes resource prefix (e.g., CryptoCurrency:EC2/BitcoinTool.B)
- Exact match on 'type' field misses variations → use prefix matching
- Multi-account: EventBridge rules in delegated admin capture member findings
- Notification frequency (15 min, 1 hour, 6 hours default) → set from admin account only

EventBridge
- SES is NOT a supported target → use Lambda to call SES

Security Hub
- Cross-Region finding aggregation requires explicit configuration
- Designate aggregation Region + specify linked Regions
- Without cross-Region config, findings remain isolated in their Regions
- "Findings not aggregating across Regions" → enable cross-Region aggregation

Audit Manager
- Produces digest.txt file with each assessment report
- digest.txt = report file checksum for integrity validation
- Cryptographic proof that report contents NOT tampered with

Logging / governance
- CloudTrail prefix change → update S3 policy + trail config
- Delete Firewall Manager policy → Config rules + empty WAF ACLs deleted

EC2 / networking
- No cross-Region SG refs → use CIDR
- SG rule changes do NOT drop existing connections
- Isolation requires killing existing sessions (or moving to untracked flow)
- mTLS requires server to terminate TLS → use NLB with TCP listener (passthrough)
- ALB terminates TLS itself → cannot do true mTLS to backend
- "Secure even if private key compromised" → Forward Secrecy (FS) security policy on HTTPS listener
- HTTP → HTTPS redirect: HTTP listener with redirect rule + HTTPS listener with ACM cert
- Redirect rule goes on HTTP listener (NOT HTTPS listener)
- ALB → backend SG rules (SGs are stateful, no return rules needed):
    ALB-SG: inbound 80/443 from 0.0.0.0/0, outbound 80 to WebAppSG
    WebAppSG: inbound 80 from ALB-SG
- Three-tier SG best practice: chain SGs as sources
    AppSG: inbound from WebSG
    DBSG: inbound from AppSG
- Virtual appliance routing traffic between subnets → disable Source/Destination check on ENI
- Source/Dest check: required off for NAT instances, firewalls, any traffic forwarding
- EC2Rescue forensic analysis → /offline mode + device ID (NOT /online + instance ID)
- Replace EC2 key pair → connect and update ~/.ssh/authorized_keys (CANNOT change via console/API)
- Session Manager = no SSH/RDP, no inbound ports, logs to CloudWatch/S3
- EC2 Instance Connect = still uses SSH/RDP protocols
- EC2 role credentials from IMDS are temporary (auto-rotated)
- New credentials available at least 5 minutes before expiration
- App manually caching credentials → may use expired creds after rotation
- "Intermittent auth failures on EC2" → use SDK's built-in credential provider chain
- SDK credential provider chain handles automatic refresh

WAF / traffic
- User-Agent blocking → WAF custom rules
- Missing User-Agent → custom or managed rules
- WAF logging for analysis → Kinesis Firehose → S3
- WAF logging for simple storage → direct to S3 (most operationally efficient)

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
- SCP restricts service, need exception → move account to new OU without restrictive SCP

STS / Federation
- AssumeRole needs trust policy + caller allow
- ExternalId prevents confused deputy
- Cross-account role: update TRUST policy on TARGET account role (NOT IAM policy)
- MFA required for assume-role → aws:MultiFactorAuthPresent in TRUST policy (NOT session policy)
- Revoke compromised STS temp credentials → revoke sessions for IAM ROLE (NOT user)
- create-role CLI → requires trust policy (assume-role-policy-document)

KMS
- Key policy evaluated before IAM
- Grants bypass key policy (scoped + temp)
- You can lock yourself out with key policy
- Key policy can grant access WITHOUT IAM policy
- If key policy allows principal directly → no IAM policy needed
- kms:ViaService condition → restrict KMS key to specific AWS service (e.g., s3.amazonaws.com)
- Temporary/programmatic KMS access → use grants (NOT key policy updates)
- Grants = create/revoke without modifying policies
- KMS follows eventual consistency model
- Grants may take several minutes to propagate
- Grant token allows immediate use before grant fully propagates
- CreateGrant returns GrantToken → include in subsequent KMS API calls
- "Grant not working immediately" → use GrantToken returned from API until eventual consistency achieved

| Key Type            | Can Manage | Auto-Rotation              |
|---------------------|------------|----------------------------|
| Customer managed    | Yes        | Optional, every 365 days   |
| AWS managed         | No         | Required, every 1095 days  |
| AWS owned           | No         | Varies                     |

- Custom key store (CloudHSM-backed) → CANNOT import key material, CANNOT auto-rotate
- Imported key material → CANNOT auto-rotate
- "Rotate every 12 months" → customer managed + enable auto-rotation (NOT AWS managed)
- AWS managed rotation period is NOT customizable (always 1095 days)

S3
- Block Public Access overrides bucket policy
- ACLs legacy; Object Ownership can disable ACLs
- Object Lock Governance mode → can bypass with s3:BypassGovernanceRetention
- Object Lock Compliance mode → CANNOT be bypassed by anyone incl. root
- Deny + ArnNotEquals = allow ONLY listed principals (everyone else denied)
- Allow + IpAddress condition does NOT deny other IPs (only grants to matching IPs)
- To block non-matching IPs → need explicit Deny with NotIpAddress condition
- S3 cross-region replication with SSE-KMS:
    Source key policy → kms:Decrypt for replication role
    Destination key policy → kms:Encrypt for replication role
    Replication role needs: kms:Decrypt, kms:ReEncryptFrom, kms:Encrypt, kms:ReEncryptTo

CloudFront
- OAI (Origin Access Identity) = legacy, does NOT support SSE-KMS S3 buckets
- OAC (Origin Access Control) = newer, supports SSE-KMS encrypted S3 origins
- If an S3 origin uses SSE-KMS, CloudFront must use OAC, not OAI.
- MITM/security headers protection → SecurityHeadersPolicy managed response headers
- Add custom security headers → Lambda@Edge on origin response

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
- IPv6 private subnet outbound → Egress-only Internet Gateway (NOT NAT gateway)
- NAT Gateway = IPv4 only
- Direct Connect does NOT encrypt in transit
- Encrypt DX traffic → VPN over DX with Virtual Private Gateway (VGW)

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
- Gateway endpoint not working → associate with subnet's route table
- Private subnet → DynamoDB = Gateway endpoint, SQS = Interface endpoint
- Endpoint policies can restrict which resources are accessible
- On-prem access to S3 via VPN/DX → need Interface Endpoint (not Gateway)
- Traffic stays on AWS network, never traverses public internet
- Flow Logs exclude 169.254.169.254 (IMDS = Instance Metadata Service)
- IMDSv2 = session-based + more secure
- Enforce IMDSv2:
    New instances → ec2:RunInstances with --metadata-options HttpTokens=required
    Existing instances → ec2 modify-instance-metadata-options --http-tokens required
- HttpEndpoint=disabled → turns off IMDS entirely (NOT the same as requiring v2)
- NACLs CANNOT block 169.254.169.254 (link-local, not routed through network)

Route 53 VPC Resolver
- Caches DNS responses for VPCs
- Query logging only logs unique queries NOT served from cache
- "Fewer logs than expected DNS queries" → cache hits not logged (by design)

Route 53 DNS Firewall
- Rule groups evaluated starting with LOWEST numeric priority first

Transit Gateway
- Appliance mode on TGW VPC attachment → ensures symmetric routing
- Uses flow hash to select single network interface for life of flow
- Required for stateful firewalls that need both directions of traffic
- "Asymmetric routing with inspection VPC" → enable appliance mode

CloudTrail
- One org trail per org
- Data events off by default
- Can send data, Insights, and management events to CloudWatch Logs
- CloudTrail → S3 requires S3 bucket policy with s3:PutObject (NOT IAM role write access)
- Multi-region logging (simplest) → change existing trail to all regions + single S3 bucket

Inspector / Macie / GuardDuty / Detective / Systems Manager
- Inspector = vuln scan + network reachability assessments
- Inspector network reachability = inbound listening ports only (NOT outbound connections)
- Inspector detects EC2 port exposure violations → use with SNS for alerts
- GuardDuty = threat detection (NOT vulnerability scanning)
- Detective = security investigation visualizations
- Detective requires GuardDuty enabled first (no 48-hour wait needed)
- Macie = S3 data classification
- Systems Manager = software inventory + patching
- "Identify vulnerable software version" → Systems Manager

ACM
- DaysToExpiry CloudWatch metric for cert expiration alerts
- Security Hub does NOT have built-in ACM cert expiration monitoring
- Expiry alerting: ACM metric → CloudWatch Alarm → Lambda → SNS
- Auto-renewal for DNS-validated certs requires:
    Certificate in use (e.g., with ALB)
    CNAME validation records still in place
- Certificate ARN unchanged after renewal → no config changes needed
- "Certificate expiring, no action needed" → DNS-validated + in use + CNAME exists

Secrets
- Secrets Manager rotates
- Parameter Store Standard does not rotate
- Parameter Store SecureString + CMK errors:
    Missing kms:Encrypt permission
    CMK state = Disabled
- CMK CAN encrypt multiple parameters
- Key alias works fine (doesn't have to be key ID)
- InvalidKeyId error → KMS key is NOT enabled (disabled state)
- SSH key rotation + auditing → Secrets Manager + Lambda rotation + CloudTrail
- Alternating users rotation strategy:
    Maintains two valid credential sets
    Eliminates auth failures during rotation
    Use with exponential backoff retry for Aurora replica propagation delays
- "Zero downtime DB credential rotation" → alternating users + retry with backoff

AWS Config
- Detect unencrypted RDS → AWS Config rule + SNS (NOT Systems Manager State Manager)
- CANNOT create encrypted read replica from unencrypted RDS source
- Config → SNS requires:
    SNS topic policy: sns:Publish for config.amazonaws.com
    IAM role policy: write access to S3 bucket
- CANNOT deliver to S3 buckets with Object Lock default retention enabled
- Object Lock retention CANNOT be bypassed via bucket policies

RDS
- Encrypt existing unencrypted RDS → snapshot → copy snapshot with encryption → restore
- RDS encryption in transit (SSL/TLS) → download AWS root certificates, use in connection

API Gateway
- API usage analysis → enable access logging on stage + CloudWatch Logs Insights

ECS
- Container logging → awslogs log driver in LogConfiguration (awslogs-group, awslogs-region)
- NOT CloudWatch agent on container instances

VPC Traffic Mirroring
- Send copy of traffic to IDS/monitoring → Traffic Mirroring to NLB → target instance
- NOT Flow Logs (metadata only, no packet content)
- NOT disabling source/dest check (that's for routing, not mirroring)

VPC Flow Logs
- Detect port connection attempts → Flow Logs + metric filter + CloudWatch alarm
- Block detected bad actors → update NACLs (NOT SGs for automated blocking)
- Apache Parquet format → 10-100x faster queries, 20% less storage with Gzip
- Hourly partitions → reduce data scanned, lower Athena costs
- Hive-compatible S3 prefixes → automatic partition discovery in Athena (no ALTER TABLE)
- "Optimize flow logs for Athena analysis" → Parquet + hourly partitions + Hive prefixes

DDoS / Static Content Protection
- Static content DDoS protection → S3 + CloudFront + WAF
- DDoS attack response → WAF web ACL rules + Shield Advanced
- NOT NLB (layer 4 only, no WAF integration)

Lambda
- Code signing via AWS Signer - 4 checks:
    Integrity (required) → artifact not modified after signing
    Source mismatch → signature missing or wrong signing profile
    Expiry → signature past expiration
    Revocation → signing profile marked invalid
- Integrity check must pass or Lambda won't run
- Other 3 checks configurable: block or warn

DynamoDB
- Client-side encryption + tamper detection → DynamoDB Encryption Client
- NOT KMS alone (encryption at rest only, no signing)
- NOT AWS Encryption SDK (generic, not DynamoDB-specific)

Glacier
- Vault Lock policy error during InProgress → AbortVaultLock, update policy, initiate-vault-lock again
- Once vault lock completed → CANNOT modify

Incident Response
- Automated forensic environment + orchestration → CloudFormation + Step Functions
- NOT Shield (DDoS protection only)

Log Analytics
- Real-time analytics + replay + persistent → Kinesis + OpenSearch

Kinesis
- Encrypted in transit via private network → Interface VPC endpoint for Kinesis
- NOT VPN (traverses internet), NOT SSE-KMS alone (at rest only)
