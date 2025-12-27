"""
Advanced Risk Assessment Engine.
Evaluates security risks based on discovered services and vulnerabilities.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Vulnerability information."""
    cve_id: str
    description: str
    severity: RiskLevel
    cvss_score: float
    affected_service: str
    affected_version: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    """Complete risk assessment for a host."""
    host_ip: str
    hostname: Optional[str]
    overall_risk: RiskLevel
    risk_score: float
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risky_services: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class RiskEngine:
    """Advanced risk assessment engine with CVE mapping and scoring."""
    
    # Common vulnerable services and versions
    VULNERABLE_SERVICES = {
        "ftp": {
            "risk": RiskLevel.HIGH,
            "reason": "FTP transmits credentials in plaintext"
        },
        "telnet": {
            "risk": RiskLevel.CRITICAL,
            "reason": "Telnet transmits all data in plaintext"
        },
        "smtp": {
            "risk": RiskLevel.MEDIUM,
            "reason": "Unencrypted email transmission"
        },
        "http": {
            "risk": RiskLevel.MEDIUM,
            "reason": "Unencrypted HTTP traffic"
        },
        "pop3": {
            "risk": RiskLevel.MEDIUM,
            "reason": "Unencrypted email access"
        },
        "imap": {
            "risk": RiskLevel.MEDIUM,
            "reason": "Unencrypted email access"
        },
        "snmp": {
            "risk": RiskLevel.HIGH,
            "reason": "Weak SNMP communities expose system information"
        },
        "vnc": {
            "risk": RiskLevel.HIGH,
            "reason": "Remote desktop with potential authentication issues"
        },
        "rdp": {
            "risk": RiskLevel.HIGH,
            "reason": "Remote desktop with potential vulnerabilities"
        },
        "mysql": {
            "risk": RiskLevel.MEDIUM,
            "reason": "Database service exposed"
        },
        "postgresql": {
            "risk": RiskLevel.MEDIUM,
            "reason": "Database service exposed"
        },
        "mongodb": {
            "risk": RiskLevel.HIGH,
            "reason": "Database service often misconfigured"
        },
        "redis": {
            "risk": RiskLevel.HIGH,
            "reason": "Database service often without authentication"
        },
        "elasticsearch": {
            "risk": RiskLevel.HIGH,
            "reason": "Search service often without authentication"
        }
    }
    
    # High-risk ports
    HIGH_RISK_PORTS = {
        21: "FTP",
        23: "Telnet",
        80: "HTTP (unencrypted)",
        135: "MS-RPC",
        139: "NetBIOS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch"
    }
    
    def __init__(self, cve_database_path: Optional[str] = None):
        """
        Initialize risk engine.
        
        Args:
            cve_database_path: Path to CVE mapping CSV file
        """
        self.cve_database_path = cve_database_path
        self.cve_mapping: Dict[str, List[Dict]] = {}
        self._load_cve_database()
    
    def _load_cve_database(self) -> None:
        """Load CVE mapping from CSV file if available."""
        if not self.cve_database_path:
            return
        
        try:
            cve_path = Path(self.cve_database_path)
            if not cve_path.exists():
                logger.warning(f"CVE database not found at {cve_path}")
                return
            
            import csv
            with open(cve_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    service = row.get('service', '').lower()
                    cve_id = row.get('cve_id', '')
                    description = row.get('description', '')
                    cvss = float(row.get('cvss_score', '0'))
                    
                    if service and cve_id:
                        if service not in self.cve_mapping:
                            self.cve_mapping[service] = []
                        
                        self.cve_mapping[service].append({
                            'cve_id': cve_id,
                            'description': description,
                            'cvss_score': cvss
                        })
            
            logger.info(f"Loaded {sum(len(v) for v in self.cve_mapping.values())} CVE entries")
        except Exception as e:
            logger.error(f"Failed to load CVE database: {e}")
    
    def assess_host(
        self,
        host_ip: str,
        hostname: Optional[str],
        ports: List[Dict],
        os_info: Optional[str] = None
    ) -> RiskAssessment:
        """
        Assess risk for a single host.
        
        Args:
            host_ip: Host IP address
            hostname: Hostname if available
            ports: List of port dictionaries with service information
            os_info: OS information if available
            
        Returns:
            RiskAssessment object
        """
        vulnerabilities = []
        risky_services = []
        recommendations = []
        
        # Analyze each open port/service
        for port_info in ports:
            if port_info.get('state') != 'open':
                continue
            
            port = port_info.get('port')
            service = port_info.get('service', '').lower()
            version = port_info.get('version', '')
            product = port_info.get('product', '')
            
            # Check for known vulnerable services
            service_risk = self._assess_service_risk(
                port, service, version, product
            )
            
            if service_risk:
                risky_services.append({
                    'port': port,
                    'service': service,
                    'version': version,
                    'risk_level': service_risk['level'].value,
                    'reason': service_risk['reason']
                })
                
                # Add recommendations
                if service_risk['recommendation']:
                    recommendations.append(service_risk['recommendation'])
            
            # Check CVE database
            if service in self.cve_mapping:
                for cve_entry in self.cve_mapping[service]:
                    vuln = Vulnerability(
                        cve_id=cve_entry['cve_id'],
                        description=cve_entry['description'],
                        severity=self._cvss_to_risk_level(cve_entry['cvss_score']),
                        cvss_score=cve_entry['cvss_score'],
                        affected_service=service,
                        affected_version=version if version else None
                    )
                    vulnerabilities.append(vuln)
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(vulnerabilities, risky_services)
        overall_risk = self._score_to_risk_level(risk_score)
        
        # Generate additional recommendations
        recommendations.extend(self._generate_recommendations(
            ports, os_info, overall_risk
        ))
        
        # Remove duplicate recommendations
        recommendations = list(dict.fromkeys(recommendations))
        
        return RiskAssessment(
            host_ip=host_ip,
            hostname=hostname,
            overall_risk=overall_risk,
            risk_score=risk_score,
            vulnerabilities=vulnerabilities,
            risky_services=risky_services,
            recommendations=recommendations
        )
    
    def _assess_service_risk(
        self,
        port: int,
        service: str,
        version: str,
        product: str
    ) -> Optional[Dict]:
        """Assess risk for a specific service."""
        # Check high-risk ports
        if port in self.HIGH_RISK_PORTS:
            return {
                'level': RiskLevel.HIGH,
                'reason': f"High-risk port {port} ({self.HIGH_RISK_PORTS[port]})",
                'recommendation': f"Restrict access to port {port} or use encrypted alternatives"
            }
        
        # Check vulnerable services
        if service in self.VULNERABLE_SERVICES:
            svc_info = self.VULNERABLE_SERVICES[service]
            return {
                'level': svc_info['risk'],
                'reason': svc_info['reason'],
                'recommendation': f"Use encrypted alternative for {service.upper()} (e.g., SFTP, HTTPS, IMAPS)"
            }
        
        # Check for outdated versions (basic heuristics)
        if version:
            # Common patterns indicating old versions
            old_patterns = [
                r'(\d+)\.(\d+)',  # Version numbers
            ]
            # This is simplified - real version checking would use a database
            if any(char.isdigit() for char in version):
                return {
                    'level': RiskLevel.MEDIUM,
                    'reason': f"Version information exposed: {version}",
                    'recommendation': f"Ensure {service} is updated to the latest version"
                }
        
        return None
    
    def _cvss_to_risk_level(self, cvss_score: float) -> RiskLevel:
        """Convert CVSS score to risk level."""
        if cvss_score >= 9.0:
            return RiskLevel.CRITICAL
        elif cvss_score >= 7.0:
            return RiskLevel.HIGH
        elif cvss_score >= 4.0:
            return RiskLevel.MEDIUM
        elif cvss_score > 0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _calculate_risk_score(
        self,
        vulnerabilities: List[Vulnerability],
        risky_services: List[Dict]
    ) -> float:
        """Calculate overall risk score (0-100)."""
        score = 0.0
        
        # Add points for vulnerabilities (weighted by CVSS)
        for vuln in vulnerabilities:
            if vuln.severity == RiskLevel.CRITICAL:
                score += 15
            elif vuln.severity == RiskLevel.HIGH:
                score += 10
            elif vuln.severity == RiskLevel.MEDIUM:
                score += 5
            elif vuln.severity == RiskLevel.LOW:
                score += 2
        
        # Add points for risky services
        for svc in risky_services:
            risk_level_str = svc.get('risk_level', 'low')
            if risk_level_str == 'critical':
                score += 12
            elif risk_level_str == 'high':
                score += 8
            elif risk_level_str == 'medium':
                score += 4
            elif risk_level_str == 'low':
                score += 1
        
        # Cap at 100
        return min(score, 100.0)
    
    def _generate_recommendations(
        self,
        ports: List[Dict],
        os_info: Optional[str],
        overall_risk: RiskLevel
    ) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Count open ports
        open_ports = [p for p in ports if p.get('state') == 'open']
        if len(open_ports) > 50:
            recommendations.append(
                "Large number of open ports detected. Consider closing unnecessary services."
            )
        
        # Check for encryption
        has_unencrypted = any(
            p.get('service', '').lower() in ['http', 'ftp', 'telnet', 'smtp']
            for p in open_ports
        )
        if has_unencrypted:
            recommendations.append(
                "Unencrypted services detected. Implement TLS/SSL encryption."
            )
        
        # General recommendations based on risk level
        if overall_risk in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append(
                "Immediate action required. Review and patch identified vulnerabilities."
            )
            recommendations.append(
                "Implement network segmentation to limit exposure."
            )
        
        return recommendations
    
    def assess_multiple_hosts(
        self,
        hosts_data: List[Dict]
    ) -> List[RiskAssessment]:
        """
        Assess risk for multiple hosts.
        
        Args:
            hosts_data: List of host dictionaries with port information
            
        Returns:
            List of RiskAssessment objects
        """
        assessments = []
        
        for host_data in hosts_data:
            try:
                assessment = self.assess_host(
                    host_ip=host_data.get('ip', ''),
                    hostname=host_data.get('hostname'),
                    ports=host_data.get('ports', []),
                    os_info=host_data.get('os')
                )
                assessments.append(assessment)
            except Exception as e:
                logger.error(f"Error assessing host {host_data.get('ip')}: {e}")
                continue
        
        return assessments

