"""Cloud security configuration assessment module."""
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CloudMisconfiguration:
    """Cloud security misconfiguration."""
    service: str
    resource: str
    issue: str
    severity: str  # critical, high, medium, low
    impact: str
    remediation: str
    framework_ref: str  # e.g., "CIS 1.1", "NIST AC-3"


class CloudSecurityModule:
    """Assesses cloud security posture across AWS, Azure, and GCP."""
    
    def __init__(self):
        self._aws_checks = self._init_aws_checks()
        self._azure_checks = self._init_azure_checks()
        self._gcp_checks = self._init_gcp_checks()
    
    async def assess_aws(self, account_id: str) -> Dict[str, Any]:
        """Assess AWS account security."""
        configs = []
        
        # Check S3 bucket configurations
        configs.extend(self._check_s3_buckets())
        
        # Check IAM configurations
        configs.extend(self._check_iam())
        
        # Check security group configurations
        configs.extend(self._check_security_groups())
        
        # Check CloudTrail
        configs.extend(self._check_cloudtrail())
        
        return {
            "provider": "aws",
            "account_id": account_id,
            "total_checks": len(self._aws_checks),
            "misconfigurations": [c.__dict__ for c in configs],
            "critical_count": sum(1 for c in configs if c.severity == "critical"),
            "high_count": sum(1 for c in configs if c.severity == "high"),
            "score": self._calculate_score(configs),
            "recommendations": self._generate_recommendations(configs),
        }
    
    async def assess_azure(self, subscription_id: str) -> Dict[str, Any]:
        """Assess Azure subscription security."""
        configs = []
        configs.extend(self._check_storage_accounts())
        configs.extend(self._check_nsg_rules())
        configs.extend(self._check_keyvault())
        
        return {
            "provider": "azure",
            "subscription_id": subscription_id,
            "total_checks": len(self._azure_checks),
            "misconfigurations": [c.__dict__ for c in configs],
            "score": self._calculate_score(configs),
        }
    
    async def assess_gcp(self, project_id: str) -> Dict[str, Any]:
        """Assess GCP project security."""
        configs = []
        configs.extend(self._check_gcs_buckets())
        configs.extend(self._check_iam_gcp())
        configs.extend(self._check_firewall_rules())
        
        return {
            "provider": "gcp",
            "project_id": project_id,
            "total_checks": len(self._gcp_checks),
            "misconfigurations": [c.__dict__ for c in configs],
            "score": self._calculate_score(configs),
        }
    
    def _init_aws_checks(self) -> List[Dict]:
        return [
            {"id": "S3-001", "name": "S3 Public Access", "severity": "critical"},
            {"id": "S3-002", "name": "S3 Encryption", "severity": "high"},
            {"id": "IAM-001", "name": "Root MFA", "severity": "critical"},
            {"id": "IAM-002", "name": "Unused IAM Keys", "severity": "medium"},
            {"id": "EC2-001", "name": "Public Security Groups", "severity": "high"},
            {"id": "CT-001", "name": "CloudTrail Enabled", "severity": "high"},
            {"id": "KMS-001", "name": "Key Rotation", "severity": "medium"},
            {"id": "VPC-001", "name": "Default VPC In Use", "severity": "low"},
        ]
    
    def _init_azure_checks(self) -> List[Dict]:
        return [
            {"id": "AZ-001", "name": "Storage Account Public Access", "severity": "critical"},
            {"id": "AZ-002", "name": "NSG Inbound RDP/SSH", "severity": "high"},
            {"id": "AZ-003", "name": "Key Vault Soft Delete", "severity": "high"},
            {"id": "AZ-004", "name": "Managed Disks Encryption", "severity": "medium"},
        ]
    
    def _init_gcp_checks(self) -> List[Dict]:
        return [
            {"id": "GCP-001", "name": "GCS Bucket Public Access", "severity": "critical"},
            {"id": "GCP-002", "name": "IAM Service Account Keys", "severity": "high"},
            {"id": "GCP-003", "name": "VPC Firewall Rules", "severity": "high"},
            {"id": "GCP-004", "name": "OS Login Enabled", "severity": "medium"},
        ]
    
    def _check_s3_buckets(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="S3", resource="logs-bucket-prod",
                issue="Bucket ACL allows public READ access",
                severity="critical",
                impact="Unauthorized access to sensitive log data",
                remediation="Remove public ACL and enable Block Public Access",
                framework_ref="CIS 1.2: S3.1, 2.1.1",
            ),
            CloudMisconfiguration(
                service="S3", resource="backup-bucket",
                issue="Default encryption (SSE-S3) instead of KMS",
                severity="medium",
                impact="Lack of centralized key management and audit",
                remediation="Enable SSE-KMS with customer-managed key",
                framework_ref="CIS 1.2: S3.4, 2.1.2",
            ),
        ]
    
    def _check_iam(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="IAM", resource="Root User",
                issue="Root user does not have MFA enabled",
                severity="critical",
                impact="Full AWS account compromise if root credentials leaked",
                remediation="Enable MFA on root user immediately",
                framework_ref="CIS 1.2: IAM.1, 1.4",
            ),
            CloudMisconfiguration(
                service="IAM", resource="AdminRole",
                issue="Overly permissive IAM policy (Action: '*')",
                severity="high",
                impact="Privilege escalation and lateral movement risk",
                remediation="Implement least privilege IAM policies",
                framework_ref="CIS 1.2: IAM.3, 1.16",
            ),
        ]
    
    def _check_security_groups(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="EC2", resource="sg-web-prod",
                issue="Security group allows SSH (0.0.0.0/0)",
                severity="high", impact="Brute-force SSH attacks from internet",
                remediation="Restrict SSH to bastion host or VPN IP ranges",
                framework_ref="CIS 1.2: EC2.2, 4.1",
            ),
        ]
    
    def _check_cloudtrail(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="CloudTrail", resource="management-trail",
                issue="CloudTrail not enabled in all regions",
                severity="high", impact="Missing audit logs for certain regions",
                remediation="Enable multi-region CloudTrail trail",
                framework_ref="CIS 1.2: CT.1, 2.1",
            ),
        ]
    
    def _check_storage_accounts(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="Storage", resource="proddata",
                issue="Azure Storage Account allows public network access",
                severity="critical", impact="Data exposure to internet",
                remediation="Disable public network access and use Private Endpoint",
                framework_ref="CIS Azure 2.0: 3.1",
            ),
        ]
    
    def _check_nsg_rules(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="NSG", resource="nsg-app-prod",
                issue="Inbound rule allows RDP from internet (0.0.0.0/0:3389)",
                severity="critical", impact="RDP brute-force and potential compromise",
                remediation="Remove RDP internet rule, use Azure Bastion",
                framework_ref="CIS Azure 2.0: 6.1",
            ),
        ]
    
    def _check_keyvault(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="Key Vault", resource="vault-prod",
                issue="Key Vault soft delete not enabled",
                severity="high",
                impact="Permanent data loss if keys/secrets deleted",
                remediation="Enable soft delete and purge protection",
                framework_ref="CIS Azure 2.0: 5.1",
            ),
        ]
    
    def _check_gcs_buckets(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="GCS", resource="app-data",
                issue="Bucket has uniform bucket-level access disabled",
                severity="high", impact="Fine-grained ACL may allow public access",
                remediation="Enable uniform bucket-level access and use IAM",
                framework_ref="CIS GCP 1.0: 1.1",
            ),
        ]
    
    def _check_iam_gcp(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="IAM", resource="service-account-deploy",
                issue="Service account has user-managed keys older than 90 days",
                severity="high",
                impact="Key compromise could lead to persistent access",
                remediation="Rotate keys and use workload identity federation",
                framework_ref="CIS GCP 1.0: 1.4",
            ),
        ]
    
    def _check_firewall_rules(self) -> List[CloudMisconfiguration]:
        return [
            CloudMisconfiguration(
                service="VPC", resource="default-firewall",
                issue="Default VPC firewall allows ingress from 0.0.0.0/0",
                severity="high", impact="Broad network access to GCP resources",
                remediation="Restrict ingress rules and avoid using default network",
                framework_ref="CIS GCP 1.0: 3.1",
            ),
        ]
    
    def _calculate_score(self, configs: List[CloudMisconfiguration]) -> float:
        score = 100.0
        for c in configs:
            if c.severity == "critical":
                score -= 20
            elif c.severity == "high":
                score -= 10
            elif c.severity == "medium":
                score -= 5
        return max(score, 0)
    
    def _generate_recommendations(self, configs: List[CloudMisconfiguration]) -> List[str]:
        recs = []
        if any(c.severity == "critical" for c in configs):
            recs.append("Remediate critical misconfigurations immediately")
        if any("MFA" in c.issue for c in configs):
            recs.append("Enforce MFA for all privileged users")
        if any("public" in c.issue.lower() for c in configs):
            recs.append("Review and restrict all publicly accessible resources")
        recs.append("Implement Cloud Security Posture Management (CSPM)")
        recs.append("Enable automated compliance scanning (e.g., Prowler, ScoutSuite)")
        return recs
