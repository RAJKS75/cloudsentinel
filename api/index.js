const crypto = require('crypto');

// ============================================================
// IN-MEMORY STORE (replace with Azure Table Storage / Cosmos DB)
// ============================================================
const store = { accounts: [] };

// ============================================================
// ENCRYPTION HELPER
// ============================================================
function getEncryptionKey() {
  const key = process.env.ENCRYPTION_KEY || 'cloudsentinel-default-key-change-me-32b!';
  return crypto.scryptSync(key, 'salt', 32);
}

function encrypt(plaintext) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
}

function decrypt(ciphertext) {
  try {
    const key = getEncryptionKey();
    const [ivHex, tagHex, encrypted] = ciphertext.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch { return null; }
}

// ============================================================
// AWS SDK CLIENTS
// ============================================================
function getAwsClient(service, credentials, region) {
  const mod = require(`@aws-sdk/client-${service}`);
  return new mod[Object.keys(mod).find(k => k.endsWith('Client'))]({
    region: region || 'us-east-1',
    credentials: {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey
    }
  });
}

// ============================================================
// AZURE TOKEN ACQUISITION
// ================================================================
async function getAzureToken(credentials) {
  const res = await fetch(
    `https://login.microsoftonline.com/${credentials.tenantId}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        scope: 'https://management.azure.com/.default',
        grant_type: 'client_credentials'
      })
    }
  );
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error_description || `Azure auth failed: ${res.status}`);
  }
  const data = await res.json();
  return data.access_token;
}

async function azureRequest(token, method, url, body) {
  const opts = {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || `Azure API error: ${res.status}`);
  return data;
}

// ============================================================
// AWS TEST CONNECTION
// ============================================================
async function testAwsConnection(account) {
  const creds = account.credentials;
  const client = getAwsClient('sts', creds, account.region);
  const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
  const stsClient = new STSClient({
    region: account.region || 'us-east-1',
    credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey }
  });
  const response = await stsClient.send(new GetCallerIdentityCommand({}));
  return { accountId: response.Account, arn: response.Arn, userId: response.UserId };
}

// ============================================================
// AZURE TEST CONNECTION
// ============================================================
async function testAzureConnection(account) {
  const token = await getAzureToken(account.credentials);
  const data = await azureRequest(token, 'GET',
    `https://management.azure.com/subscriptions/${account.subscriptionId}?api-version=2022-12-01`
  );
  return { subscriptionId: data.subscriptionId, subscriptionDisplayName: data.displayName };
}

// ============================================================
// AWS SECURITY SCANNERS
// ============================================================
function awsFinding(severity, title, resource, resourceType, region, description, remediation, impact, frameworks) {
  return { id: Math.random().toString(36).substr(2, 9), severity, status: 'open', title, resource, resourceType, region, description, remediation, impact, frameworks, accountProvider: 'aws' };
}

async function scanAwsIam(account) {
  const findings = [];
  const { IAMClient, ListUsersCommand, ListAccessKeysCommand, GetAccountPasswordPolicyCommand, ListPoliciesCommand, GetPolicyVersionCommand, ListEntitiesForPolicyCommand, ListAttachedUserPoliciesCommand, ListUserPoliciesCommand } = require('@aws-sdk/client-iam');
  const client = new IAMClient({
    region: 'us-east-1',
    credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey }
  });

  // Check root account access keys
  try {
    const { IAMClient: STSClient2, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
    const sts = new STSClient2({ region: account.region, credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey } });
    const identity = await sts.send(new GetCallerIdentityCommand({}));
    if (identity.UserId && identity.UserId.startsWith('AIDA')) {
      // Not root, good
    } else {
      // Check if root has access keys via credential report or summary
    }
  } catch {}

  // Check password policy
  try {
    const policy = await client.send(new GetAccountPasswordPolicyCommand({}));
    if (!policy.PasswordPolicy) {
      findings.push(awsFinding('medium', 'No IAM Password Policy Set', 'Account Password Policy', 'IAM Policy', 'global',
        'No custom password policy is set. Default AWS policy allows 8-char passwords without complexity.',
        'Set a password policy with MinimumPasswordLength=14, RequireSymbols=true, RequireNumbers=true, RequireUppercaseCharacters=true, RequireLowercaseCharacters=true.',
        'Weak passwords susceptible to brute-force.',
        [{ name: 'NIST', id: 'IA-5', label: 'Authenticator Management' }, { name: 'ISO', id: 'A.9.4', label: 'System Access Control' }, { name: 'CIS', id: '1.10', label: 'Password policy min 14 chars' }, { name: 'CCM', id: 'IAM-01', label: 'Identity & Access' }]
      ));
    } else if (policy.PasswordPolicy.MinimumPasswordLength < 14) {
      findings.push(awsFinding('medium', `IAM Password Policy Too Short (${policy.PasswordPolicy.MinimumPasswordLength} chars)`, 'Account Password Policy', 'IAM Policy', 'global',
        `Minimum password length is ${policy.PasswordPolicy.MinimumPasswordLength}. Best practice requires 14+.`,
        'Update password policy to require minimum 14 characters.',
        'Weak passwords susceptible to brute-force.',
        [{ name: 'NIST', id: 'IA-5', label: 'Authenticator Management' }, { name: 'CIS', id: '1.10', label: 'Password policy min 14 chars' }, { name: 'CCM', id: 'IAM-01', label: 'Identity & Access' }]
      ));
    }
    if (!policy.PasswordPolicy.RequireSymbols || !policy.PasswordPolicy.RequireNumbers || !policy.PasswordPolicy.RequireUppercaseCharacters) {
      findings.push(awsFinding('low', 'IAM Password Policy Missing Complexity Requirements', 'Account Password Policy', 'IAM Policy', 'global',
        'Password policy does not require all of: symbols, numbers, uppercase characters.',
        'Enable all complexity requirements in password policy.',
        'Weaker passwords.',
        [{ name: 'NIST', id: 'IA-5', label: 'Authenticator Management' }, { name: 'CIS', id: '1.10', label: 'Password complexity' }, { name: 'CCM', id: 'IAM-01', label: 'Identity & Access' }]
      ));
    }
  } catch (e) {
    findings.push(awsFinding('medium', 'Cannot Read IAM Password Policy', 'Account Password Policy', 'IAM Policy', 'global',
      `Error: ${e.message}`, 'Ensure the scanning IAM user has iam:GetAccountPasswordPolicy permission.', 'Unable to verify password policy compliance.', []));
  }

  // Check for admin policies
  try {
    const policies = await client.send(new ListPoliciesCommand({ Scope: 'Local', OnlyAttached: true }));
    for (const policy of (policies.Policies || [])) {
      if (policy.PolicyName.toLowerCase().includes('full') || policy.PolicyName.toLowerCase().includes('admin')) {
        try {
          const version = await client.send(new GetPolicyVersionCommand({
            PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId
          }));
          const doc = JSON.parse(decodeURIComponent(version.PolicyVersion.Document));
          const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
          for (const stmt of statements) {
            if (stmt.Effect === 'Allow' && stmt.Action === '*' && stmt.Resource === '*') {
              try {
                const entities = await client.send(new ListEntitiesForPolicyCommand({ PolicyArn: policy.Arn, EntityFilter: 'User' }));
                const userCount = entities.PolicyUsers?.length || 0;
                findings.push(awsFinding('high', `IAM Policy "${policy.PolicyName}" Grants Full Admin (*:*)`, policy.Arn, 'IAM Policy', 'global',
                  `Policy grants Action:'*' on Resource:'*' and is attached to ${userCount} IAM user(s). Violates least-privilege.`,
                  'Replace with specific permissions per service. Use IAM Access Analyzer.',
                  'Privilege escalation, unauthorized modification.',
                  [{ name: 'NIST', id: 'AC-6', label: 'Least Privilege' }, { name: 'ISO', id: 'A.9.1', label: 'Access Control' }, { name: 'CIS', id: '1.16', label: 'No full admin policies' }, { name: 'CCM', id: 'IAM-02', label: 'Registration' }]
                ));
              } catch { break; }
              break;
            }
          }
        } catch {}
      }
    }
  } catch {}

  return findings;
}

async function scanAwsS3(account) {
  const findings = [];
  const { S3Client, ListBucketsCommand, GetBucketPolicyStatusCommand, GetPublicAccessBlockCommand } = require('@aws-sdk/client-s3');
  const client = new S3Client({
    region: account.region || 'us-east-1',
    credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey },
    forcePathStyle: false
  });

  try {
    const { Buckets } = await client.send(new ListBucketsCommand({}));
    for (const bucket of (Buckets || [])) {
      try {
        const status = await client.send(new GetBucketPolicyStatusCommand({ Bucket: bucket.Name }));
        if (status.PolicyStatus?.IsPublic) {
          findings.push(awsFinding('critical', `S3 Bucket "${bucket.Name}" Is Public`, `s3://${bucket.Name}`, 'S3 Bucket', bucket.Location || account.region,
            'Bucket policy status shows IsPublic=true. Objects may be accessible to anyone.',
            'Enable "Block all public access" on the bucket.',
            'Data exfiltration, compliance violation (GDPR, HIPAA).',
            [{ name: 'NIST', id: 'AC-3', label: 'Access Enforcement' }, { name: 'ISO', id: 'A.9.4', label: 'Access Control' }, { name: 'CIS', id: '2.1.1', label: 'S3 not public' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
          ));
        }
      } catch {}
      try {
        const pab = await client.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }));
        const c = pab.PublicAccessBlockConfiguration;
        if (!c.BlockPublicAcls || !c.BlockPublicPolicy || !c.IgnorePublicAcls || !c.RestrictPublicBuckets) {
          findings.push(awsFinding('high', `S3 Bucket "${bucket.Name}" Missing Full Public Access Block`, `s3://${bucket.Name}`, 'S3 Bucket', bucket.Location || account.region,
            'Public access block is not fully configured. Some public access vectors are open.',
            'Enable all four public access block settings.',
            'Potential public data exposure.',
            [{ name: 'NIST', id: 'AC-3', label: 'Access Enforcement' }, { name: 'CIS', id: '2.1.2', label: 'S3 public access block' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
          ));
        }
      } catch {}
    }
  } catch (e) {
    findings.push(awsFinding('medium', 'Cannot List S3 Buckets', 'S3 Service', 'S3', account.region, `Error: ${e.message}`, 'Check s3:ListAllMyBuckets permission.', 'Unable to assess S3 security.', []));
  }

  return findings;
}

async function scanAwsEc2(account) {
  const findings = [];
  const { EC2Client, DescribeSecurityGroupsCommand, DescribeInstancesCommand, DescribeVpcsCommand, DescribeFlowLogsCommand } = require('@aws-sdk/client-ec2');
  const client = new EC2Client({
    region: account.region || 'us-east-1',
    credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey }
  });

  // Security Groups
  try {
    const { SecurityGroups } = await client.send(new DescribeSecurityGroupsCommand({}));
    for (const sg of (SecurityGroups || [])) {
      for (const rule of (sg.IpPermissions || [])) {
        for (const range of (rule.IpRanges || [])) {
          if (range.CidrIp === '0.0.0.0/0') {
            for (const port of (rule.FromPort ? [rule.FromPort] : [])) {
              if (port === 22) {
                const instances = await countSgInstances(client, sg.GroupId);
                findings.push(awsFinding('critical', `Security Group "${sg.GroupName}" Allows SSH (22) from 0.0.0.0/0`, sg.GroupId, 'Security Group', account.region,
                  `Attached to ${instances} instance(s). Exposes SSH to the internet.`,
                  'Restrict source to VPN/bastion IP. Use SSM Session Manager.',
                  'Brute-force, unauthorized access.',
                  [{ name: 'NIST', id: 'SC-7', label: 'Boundary Protection' }, { name: 'ISO', id: 'A.13.1', label: 'Network Security' }, { name: 'CIS', id: '4.1', label: 'No SSH from 0.0.0.0/0' }, { name: 'CCM', id: 'TVM-01', label: 'Threat Mgmt' }]
                ));
                break;
              }
              if (port === 3389) {
                findings.push(awsFinding('critical', `Security Group "${sg.GroupName}" Allows RDP (3389) from 0.0.0.0/0`, sg.GroupId, 'Security Group', account.region,
                  'RDP port exposed to the internet.',
                  'Restrict source IP. Use bastion host.',
                  'RDP brute-force, ransomware.',
                  [{ name: 'NIST', id: 'SC-7', label: 'Boundary Protection' }, { name: 'CIS', id: '4.1', label: 'No RDP from 0.0.0.0/0' }, { name: 'CCM', id: 'TVM-01', label: 'Threat Mgmt' }]
                ));
                break;
              }
            }
            if (rule.IpProtocol === '-1' && !rule.FromPort) {
              findings.push(awsFinding('high', `Security Group "${sg.GroupName}" Allows ALL Traffic from 0.0.0.0/0`, sg.GroupId, 'Security Group', account.region,
                'Inbound rule allows all protocols, all ports from the internet.',
                'Remove the rule. Add specific port/rules as needed.',
                'Full network exposure.',
                [{ name: 'NIST', id: 'SC-7', label: 'Boundary Protection' }, { name: 'CIS', id: '4.2', label: 'No all traffic from 0.0.0.0/0' }, { name: 'CCM', id: 'TVM-01', label: 'Threat Mgmt' }]
              ));
            }
          }
        }
      }
      // Check unrestricted outbound
      for (const rule of (sg.IpPermissionsEgress || [])) {
        for (const range of (rule.IpRanges || [])) {
          if (range.CidrIp === '0.0.0.0/0' && rule.IpProtocol === '-1') {
            findings.push(awsFinding('medium', `Security Group "${sg.GroupName}" Has Unrestricted Outbound`, sg.GroupId, 'Security Group', account.region,
              'Egress rule allows all traffic to 0.0.0.0/0. Data exfiltration risk if compromised.',
              'Restrict outbound to known destinations.',
              'Data exfiltration, C2 communication.',
              [{ name: 'NIST', id: 'SC-7', label: 'Boundary Protection' }, { name: 'CIS', id: '4.3', label: 'Restrict outbound' }, { name: 'CCM', id: 'TVM-01', label: 'Threat Mgmt' }]
            ));
            break;
          }
        }
      }
    }
  } catch (e) {
    findings.push(awsFinding('medium', 'Cannot Describe Security Groups', 'EC2 Service', 'EC2', account.region, `Error: ${e.message}`, 'Check ec2:DescribeSecurityGroups permission.', 'Unable to assess network security.', []));
  }

  // VPC Flow Logs
  try {
    const { Vpcs } = await client.send(new DescribeVpcsCommand({}));
    for (const vpc of (Vpcs || []).filter(v => !v.IsDefault)) {
      try {
        const { FlowLogs } = await client.send(new DescribeFlowLogsCommand({ Filter: [{ Name: 'resource-id', Values: [vpc.VpcId] }] }));
        if (!FlowLogs || FlowLogs.length === 0) {
          findings.push(awsFinding('high', `VPC "${vpc.VpcId}" Has No Flow Logs`, vpc.VpcId, 'VPC', account.region,
            'No VPC Flow Logs enabled. Network traffic cannot be monitored.',
            'Enable VPC Flow Logs to CloudWatch Logs.',
            'No network visibility, undetected exfiltration.',
            [{ name: 'NIST', id: 'AU-12', label: 'Audit Logging' }, { name: 'CIS', id: '5.1', label: 'VPC Flow Logs' }, { name: 'CCM', id: 'EKM-02', label: 'Event Monitoring' }]
          ));
        }
      } catch {}
    }
  } catch {}

  return findings;
}

async function countSgInstances(client, sgId) {
  try {
    const { Reservations } = await client.send(new DescribeInstancesCommand({ Filters: [{ Name: 'instance.group-id', Values: [sgId] }] }));
    return Reservations?.reduce((acc, r) => acc + (r.Instances?.length || 0), 0) || 0;
  } catch { return '?'; }
}

async function scanAwsRds(account) {
  const findings = [];
  const { RDSClient, DescribeDBInstancesCommand } = require('@aws-sdk/client-rds');
  const client = new RDSClient({
    region: account.region || 'us-east-1',
    credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey }
  });

  try {
    const { DBInstances } = await client.send(new DescribeDBInstancesCommand({}));
    for (const db of (DBInstances || [])) {
      if (db.PubliclyAccessible) {
        findings.push(awsFinding('critical', `RDS Instance "${db.DBInstanceIdentifier}" Is Publicly Accessible`, db.Endpoint?.Address || db.DBInstanceIdentifier, 'RDS Instance', account.region,
          'Database is publicly accessible. Contains potentially sensitive data.',
          'Set PubliclyAccessible=false. Move to private subnet.',
          'Direct database access from internet.',
          [{ name: 'NIST', id: 'SC-8', label: 'Transmission Confidentiality' }, { name: 'ISO', id: 'A.10.1', label: 'Crypto Controls' }, { name: 'CIS', id: '3.4', label: 'RDS not public' }, { name: 'CCM', id: 'DSM-01', label: 'Data Classification' }]
        ));
      }
      if (!db.StorageEncrypted) {
        findings.push(awsFinding('high', `RDS Instance "${db.DBInstanceIdentifier}" Not Encrypted at Rest`, db.DBInstanceIdentifier, 'RDS Instance', account.region,
          'Storage encryption is not enabled.',
          'Enable encryption (requires snapshot restore).',
          'Data exposure at rest.',
          [{ name: 'NIST', id: 'SC-28', label: 'Info at Rest' }, { name: 'CIS', id: '3.5', label: 'RDS encryption' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
        ));
      }
    }
  } catch (e) {
    findings.push(awsFinding('medium', 'Cannot Describe RDS Instances', 'RDS Service', 'RDS', account.region, `Error: ${e.message}`, 'Check rds:DescribeDBInstances permission.', 'Unable to assess RDS security.', []));
  }

  return findings;
}

async function scanAwsCloudTrail(account) {
  const findings = [];
  const { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } = require('@aws-sdk/client-cloudtrail');
  const client = new CloudTrailClient({
    region: account.region || 'us-east-1',
    credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey }
  });

  try {
    const { trailList } = await client.send(new DescribeTrailsCommand({}));
    const multiRegionTrails = (trailList || []).filter(t => t.IsMultiRegionTrail);
    if (multiRegionTrails.length === 0) {
      findings.push(awsFinding('high', 'No Multi-Region CloudTrail Enabled', 'CloudTrail', 'CloudTrail', 'global',
        'No multi-region trail found. API calls in other regions are not logged.',
        'Create a multi-region trail with log file validation.',
        'Blind spots for security monitoring.',
        [{ name: 'NIST', id: 'AU-2', label: 'Audit Events' }, { name: 'ISO', id: 'A.12.4', label: 'Logging' }, { name: 'CIS', id: '3.1', label: 'CloudTrail all regions' }, { name: 'CCM', id: 'EKM-02', label: 'Event Monitoring' }]
      ));
    } else {
      for (const trail of multiRegionTrails) {
        if (!trail.LogFileValidationEnabled) {
          findings.push(awsFinding('medium', `CloudTrail "${trail.Name}" Missing Log File Validation`, trail.TrailARN, 'CloudTrail', account.region,
            'Log file validation is disabled. Log integrity cannot be verified.',
            'Enable log file validation.',
            'Tampered logs go undetected.',
            [{ name: 'NIST', id: 'AU-9', label: 'Protection of Audit Info' }, { name: 'CIS', id: '3.3', label: 'CloudTrail log validation' }, { name: 'CCM', id: 'EKM-02', label: 'Event Monitoring' }]
          ));
        }
      }
    }
  } catch (e) {
    findings.push(awsFinding('medium', 'Cannot Describe CloudTrail', 'CloudTrail Service', 'CloudTrail', account.region, `Error: ${e.message}`, 'Check cloudtrail:DescribeTrails permission.', 'Unable to assess audit logging.', []));
  }

  return findings;
}

async function scanAwsKms(account) {
  const findings = [];
  const { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } = require('@aws-sdk/client-kms');
  const client = new KMSClient({
    region: account.region || 'us-east-1',
    credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey }
  });

  try {
    const { Keys } = await client.send(new ListKeysCommand({}));
    for (const key of (Keys || [])) {
      try {
        const desc = await client.send(new DescribeKeyCommand({ KeyId: key.KeyArn }));
        if (desc.KeyMetadata?.KeyManager === 'CUSTOMER' && desc.KeyMetadata?.Origin === 'AWS_KMS') {
          const status = await client.send(new GetKeyRotationStatusCommand({ KeyId: key.KeyArn }));
          if (!status.RotationEnabled) {
            findings.push(awsFinding('medium', `KMS Key "${key.KeyArn.split('/').pop()}" Rotation Disabled`, key.KeyArn, 'KMS Key', account.region,
              'Automatic key rotation is not enabled.',
              'Enable automatic annual key rotation.',
              'Extended key compromise window.',
              [{ name: 'NIST', id: 'SC-12', label: 'Key Establishment' }, { name: 'ISO', id: 'A.10.3', label: 'Key Management' }, { name: 'CIS', id: '2.8', label: 'KMS rotation' }, { name: 'CCM', id: 'KMN-01', label: 'Key Management' }]
            ));
          }
        }
      } catch {}
    }
  } catch {}

  return findings;
}

async function scanAwsGuardDuty(account) {
  const findings = [];
  const { GuardDutyClient, ListDetectorsCommand, GetDetectorCommand } = require('@aws-sdk/client-guardduty');
  const client = new GuardDutyClient({
    region: account.region || 'us-east-1',
    credentials: { accessKeyId: account.credentials.accessKeyId, secretAccessKey: account.credentials.secretAccessKey }
  });

  try {
    const { DetectorIds } = await client.send(new ListDetectorsCommand({}));
    if (!DetectorIds || DetectorIds.length === 0) {
      findings.push(awsFinding('high', 'GuardDuty Not Enabled', 'GuardDuty', 'GuardDuty', account.region,
        'No GuardDuty detector found. Threat detection is disabled.',
        'Enable GuardDuty in all active regions.',
        'Undetected threats, no intrusion detection.',
        [{ name: 'NIST', id: 'SI-4', label: 'System Monitoring' }, { name: 'CIS', id: '3.11', label: 'GuardDuty enabled' }, { name: 'CCM', id: 'TVM-03', label: 'Threat Mgmt' }]
      ));
    } else {
      for (const id of DetectorIds) {
        const det = await client.send(new GetDetectorCommand({ DetectorId: id }));
        if (!det.Status) {
          findings.push(awsFinding('high', `GuardDuty Detector ${id.substr(0,8)}... Not Enabled`, id, 'GuardDuty', account.region,
            'Detector exists but is not enabled.',
            'Enable the detector.',
            'Threat detection disabled.',
            [{ name: 'NIST', id: 'SI-4', label: 'System Monitoring' }, { name: 'CIS', id: '3.11', label: 'GuardDuty enabled' }, { name: 'CCM', id: 'TVM-03', label: 'Threat Mgmt' }]
          ));
        }
      }
    }
  } catch {}

  return findings;
}

async function scanAwsAccount(account) {
  context.log(`[SCAN] Starting AWS scan for account: ${account.name}`);
  const allFindings = [];

  // Run all scanners in parallel
  const scanners = [
    scanAwsIam(account),
    scanAwsS3(account),
    scanAwsEc2(account),
    scanAwsRds(account),
    scanAwsCloudTrail(account),
    scanAwsKms(account),
    scanAwsGuardDuty(account)
  ];

  const results = await Promise.allSettled(scanners);
  for (const r of results) {
    if (r.status === 'fulfilled') allFindings.push(...r.value);
    else context.log(`[SCAN] Scanner error: ${r.reason?.message}`);
  }

  // Tag all findings with account info
  allFindings.forEach(f => {
    f.accountId = account.id;
    f.accountName = account.name;
  });

  context.log(`[SCAN] AWS scan complete: ${allFindings.length} findings`);
  return allFindings;
}

// ============================================================
// AZURE SECURITY SCANNERS
// ============================================================
function azureFinding(severity, title, resource, resourceType, region, description, remediation, impact, frameworks) {
  return { id: Math.random().toString(36).substr(2, 9), severity, status: 'open', title, resource, resourceType, region, description, remediation, impact, frameworks, accountProvider: 'azure' };
}

async function scanAzureStorage(token, account) {
  const findings = [];
  const sub = account.subscriptionId;
  try {
    const data = await azureRequest(token, 'GET',
      `https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`
    );
    for (const sa of (data.value || [])) {
      const loc = sa.location;
      // Check public access
      if (sa.properties?.allowBlobPublicAccess) {
        findings.push(azureFinding('critical', `Storage Account "${sa.name}" Allows Public Blob Access`, sa.id, 'Storage Account', loc,
          'allowBlobPublicAccess is true. Containers may serve blobs publicly.',
          'Set allowBlobPublicAccess=false. Use SAS tokens.',
          'Data exfiltration.',
          [{ name: 'NIST', id: 'AC-3', label: 'Access Enforcement' }, { name: 'ISO', id: 'A.9.4', label: 'Access Control' }, { name: 'CIS', id: '3.1', label: 'No public blob access' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
        ));
      }
      // Check encryption
      if (!sa.properties?.encryption?.services?.blob?.enabled) {
        findings.push(azureFinding('high', `Storage Account "${sa.name}" Blob Encryption Disabled`, sa.id, 'Storage Account', loc,
          'Blob encryption is not enabled.',
          'Enable encryption with Microsoft-managed or customer-managed keys.',
          'Data at rest unprotected.',
          [{ name: 'NIST', id: 'SC-28', label: 'Info at Rest' }, { name: 'CIS', id: '3.2', label: 'Storage encryption' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
        ));
      }
      // Check network access
      if (sa.properties?.networkAcls?.defaultAction === 'Allow') {
        findings.push(azureFinding('medium', `Storage Account "${sa.name}" Default Network Access is Allow`, sa.id, 'Storage Account', loc,
          'Default action is Allow. Storage accepts traffic from all networks.',
          'Set defaultAction=Deny. Add trusted networks/IPs.',
          'Unauthorized network access.',
          [{ name: 'NIST', id: 'SC-7', label: 'Boundary Protection' }, { name: 'CIS', id: '3.3', label: 'Storage network rules' }, { name: 'CCM', id: 'TVM-01', label: 'Threat Mgmt' }]
        ));
      }
    }
  } catch (e) {
    findings.push(azureFinding('medium', 'Cannot List Storage Accounts', 'Storage Service', 'Storage', account.region || 'unknown', `Error: ${e.message}`, 'Check Reader role on subscription.', 'Unable to assess storage security.', []));
  }
  return findings;
}

async function scanAzureNetwork(token, account) {
  const findings = [];
  const sub = account.subscriptionId;
  try {
    const data = await azureRequest(token, 'GET',
      `https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01`
    );
    for (const nsg of (data.value || [])) {
      for (const rule of (nsg.properties?.securityRules || [])) {
        if (rule.properties?.direction === 'Inbound' && rule.properties?.access === 'Allow') {
          const src = rule.properties.sourceAddressPrefix;
          if (src === '*' || src === '0.0.0.0/0' || src === 'Internet') {
            const port = rule.properties.destinationPortRange;
            if (port === '22' || port === '3389') {
              const proto = port === '22' ? 'SSH' : 'RDP';
              findings.push(azureFinding(port === '22' ? 'critical' : 'critical', `NSG "${nsg.name}" Allows ${proto} (${port}) from Internet`, nsg.id, 'Network Security Group', nsg.location,
                `Inbound rule allows ${proto} from ${src}.`,
                `Restrict source to bastion/VPN IP range.`,
                `${proto} brute-force attacks.`,
                [{ name: 'NIST', id: 'SC-7', label: 'Boundary Protection' }, { name: 'ISO', id: 'A.13.1', label: 'Network Security' }, { name: 'CIS', id: '5.1', label: `No ${proto} from internet` }, { name: 'CCM', id: 'TVM-01', label: 'Threat Mgmt' }]
              ));
            }
            if (port === '*' || port === '0-65535') {
              findings.push(azureFinding('high', `NSG "${nsg.name}" Allows ALL Ports from Internet`, nsg.id, 'Network Security Group', nsg.location,
                'Inbound rule allows all ports from internet.',
                'Remove the rule. Add specific port rules.',
                'Full network exposure.',
                [{ name: 'NIST', id: 'SC-7', label: 'Boundary Protection' }, { name: 'CIS', id: '5.2', label: 'No all ports from internet' }, { name: 'CCM', id: 'TVM-01', label: 'Threat Mgmt' }]
              ));
            }
          }
        }
      }
    }
  } catch (e) {
    findings.push(azureFinding('medium', 'Cannot List NSGs', 'Network Service', 'Network', account.region || 'unknown', `Error: ${e.message}`, 'Check Reader role.', 'Unable to assess network security.', []));
  }
  return findings;
}

async function scanAzureKeyVault(token, account) {
  const findings = [];
  const sub = account.subscriptionId;
  try {
    const data = await azureRequest(token, 'GET',
      `https://management.azure.com/subscriptions/${sub}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01`
    );
    for (const kv of (data.value || [])) {
      const props = kv.properties;
      if (!props?.enableSoftDelete) {
        findings.push(azureFinding('medium', `Key Vault "${kv.name}" Soft Delete Not Enabled`, kv.id, 'Key Vault', kv.location,
          'Soft delete is disabled. Deleted secrets/certs/keys are permanently lost.',
          'Enable softDelete and purgeProtection.',
          'Irreversible secret deletion.',
          [{ name: 'NIST', id: 'CP-9', label: 'Backup' }, { name: 'ISO', id: 'A.12.3', label: 'Backup' }, { name: 'CIS', id: '7.1', label: 'Key Vault soft delete' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
        ));
      }
      if (!props?.enablePurgeProtection) {
        findings.push(azureFinding('low', `Key Vault "${kv.name}" Purge Protection Not Enabled`, kv.id, 'Key Vault', kv.location,
          'Purge protection is disabled. Soft-deleted items can be purged before recovery window.',
          'Enable purge protection.',
          'Permanent data loss risk.',
          [{ name: 'NIST', id: 'CP-9', label: 'Backup' }, { name: 'CIS', id: '7.1', label: 'Key Vault purge protection' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
        ));
      }
    }
  } catch {}
  return findings;
}

async function scanAzureSql(token, account) {
  const findings = [];
  const sub = account.subscriptionId;
  try {
    const data = await azureRequest(token, 'GET',
      `https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Sql/servers?api-version=2023-08-01-preview`
    );
    for (const sql of (data.value || [])) {
      if (sql.properties?.publicNetworkAccess === 'Enabled') {
        findings.push(azureFinding('high', `SQL Server "${sql.name}" Has Public Endpoint`, sql.id, 'SQL Server', sql.location,
          'Public network access is enabled on the SQL server.',
          'Disable public access. Use private endpoint.',
          'Direct SQL access from internet.',
          [{ name: 'NIST', id: 'SC-8', label: 'Transmission Confidentiality' }, { name: 'ISO', id: 'A.13.1', label: 'Network Security' }, { name: 'CIS', id: '4.2', label: 'SQL private endpoint' }, { name: 'CCM', id: 'DSM-01', label: 'Data Classification' }]
        ));
      }
    }
  } catch {}
  return findings;
}

async function scanAzureDisks(token, account) {
  const findings = [];
  const sub = account.subscriptionId;
  try {
    const data = await azureRequest(token, 'GET',
      `https://management.azure.com/subscriptions/${sub}/providers/Microsoft.Compute/disks?api-version=2023-10-02`
    );
    for (const disk of (data.value || [])) {
      if (!disk.properties?.encryption?.type) {
        findings.push(azureFinding('low', `Disk "${disk.name}" Not Encrypted`, disk.id, 'Disk', disk.location,
          'Disk does not have encryption settings.',
          'Enable encryption at rest (EncryptionAtRestWithPlatformKey or customer-managed).',
          'Data exposure at rest.',
          [{ name: 'NIST', id: 'SC-28', label: 'Info at Rest' }, { name: 'CIS', id: '3.4', label: 'Disk encryption' }, { name: 'CCM', id: 'DSM-02', label: 'Data Security' }]
        ));
      }
    }
  } catch {}
  return findings;
}

async function scanAzureAccount(account) {
  context.log(`[SCAN] Starting Azure scan for account: ${account.name}`);
  const allFindings = [];

  try {
    const token = await getAzureToken(account.credentials);
    const scanners = [
      scanAzureStorage(token, account),
      scanAzureNetwork(token, account),
      scanAzureKeyVault(token, account),
      scanAzureSql(token, account),
      scanAzureDisks(token, account)
    ];
    const results = await Promise.allSettled(scanners);
    for (const r of results) {
      if (r.status === 'fulfilled') allFindings.push(...r.value);
      else context.log(`[SCAN] Azure scanner error: ${r.reason?.message}`);
    }
  } catch (e) {
    allFindings.push(azureFinding('high', `Azure Authentication Failed: ${e.message}`, 'Azure AD', 'Identity', 'global', e.message, 'Check Service Principal credentials and permissions.', 'Cannot scan Azure resources.', []));
  }

  allFindings.forEach(f => { f.accountId = account.id; f.accountName = account.name; });
  context.log(`[SCAN] Azure scan complete: ${allFindings.length} findings`);
  return allFindings;
}

// ============================================================
// ROUTING
// ============================================================
module.exports = async function (context, req) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, '') || 'health';
  const method = req.method;

  context.log(`[API] ${method} ${path}`);

  try {
    // HEALTH
    if (method === 'GET' && path === 'health') {
      return { status: 200, body: { status: 'ok', version: '3.2.1', timestamp: new Date().toISOString() } };
    }

    // LIST ACCOUNTS
    if (method === 'GET' && path === 'accounts') {
      return { status: 200, body: store.accounts.map(a => ({ ...a, credentials: undefined })) };
    }

    // ADD ACCOUNT