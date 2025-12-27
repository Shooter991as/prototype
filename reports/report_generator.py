"""
Advanced Report Generator with multiple output formats.
Supports JSON, HTML, and CSV report generation.
"""

import json
import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import asdict


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate security assessment reports in multiple formats."""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(
        self,
        scan_data: Dict[str, Any],
        risk_assessments: List[Any],
        filename: Optional[str] = None
    ) -> str:
        """
        Generate JSON report.
        
        Args:
            scan_data: Parsed scan data
            risk_assessments: List of RiskAssessment objects
            filename: Output filename (optional)
            
        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        # Convert risk assessments to dictionaries
        assessments_dict = []
        for assessment in risk_assessments:
            assessment_dict = {
                "host_ip": assessment.host_ip,
                "hostname": assessment.hostname,
                "overall_risk": assessment.overall_risk.value,
                "risk_score": assessment.risk_score,
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "description": v.description,
                        "severity": v.severity.value,
                        "cvss_score": v.cvss_score,
                        "affected_service": v.affected_service,
                        "affected_version": v.affected_version
                    }
                    for v in assessment.vulnerabilities
                ],
                "risky_services": assessment.risky_services,
                "recommendations": assessment.recommendations
            }
            assessments_dict.append(assessment_dict)
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "scan_info": scan_data.get("scan_info", {}),
            "hosts": scan_data.get("hosts", []),
            "risk_assessments": assessments_dict,
            "summary": self._generate_summary(risk_assessments)
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report generated: {output_path}")
        return str(output_path)
    
    def generate_html_report(
        self,
        scan_data: Dict[str, Any],
        risk_assessments: List[Any],
        filename: Optional[str] = None
    ) -> str:
        """
        Generate HTML report with styling.
        
        Args:
            scan_data: Parsed scan data
            risk_assessments: List of RiskAssessment objects
            filename: Output filename (optional)
            
        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.html"
        
        output_path = self.output_dir / filename
        
        summary = self._generate_summary(risk_assessments)
        
        html_content = self._generate_html_content(scan_data, risk_assessments, summary)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return str(output_path)
    
    def generate_csv_report(
        self,
        risk_assessments: List[Any],
        filename: Optional[str] = None
    ) -> str:
        """
        Generate CSV report with vulnerability details.
        
        Args:
            risk_assessments: List of RiskAssessment objects
            filename: Output filename (optional)
            
        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnerabilities_{timestamp}.csv"
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "Host IP",
                "Hostname",
                "Overall Risk",
                "Risk Score",
                "CVE ID",
                "Vulnerability Description",
                "Severity",
                "CVSS Score",
                "Affected Service",
                "Affected Version"
            ])
            
            # Write data
            for assessment in risk_assessments:
                if assessment.vulnerabilities:
                    for vuln in assessment.vulnerabilities:
                        writer.writerow([
                            assessment.host_ip,
                            assessment.hostname or "",
                            assessment.overall_risk.value,
                            assessment.risk_score,
                            vuln.cve_id,
                            vuln.description,
                            vuln.severity.value,
                            vuln.cvss_score,
                            vuln.affected_service,
                            vuln.affected_version or ""
                        ])
                else:
                    # Write row even if no vulnerabilities
                    writer.writerow([
                        assessment.host_ip,
                        assessment.hostname or "",
                        assessment.overall_risk.value,
                        assessment.risk_score,
                        "",
                        "",
                        "",
                        "",
                        "",
                        ""
                    ])
        
        logger.info(f"CSV report generated: {output_path}")
        return str(output_path)
    
    def _generate_summary(self, risk_assessments: List[Any]) -> Dict[str, Any]:
        """Generate summary statistics."""
        total_hosts = len(risk_assessments)
        total_vulnerabilities = sum(len(a.vulnerabilities) for a in risk_assessments)
        
        risk_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for assessment in risk_assessments:
            risk_level = assessment.overall_risk.value
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        avg_risk_score = (
            sum(a.risk_score for a in risk_assessments) / total_hosts
            if total_hosts > 0 else 0
        )
        
        return {
            "total_hosts": total_hosts,
            "total_vulnerabilities": total_vulnerabilities,
            "risk_distribution": risk_counts,
            "average_risk_score": round(avg_risk_score, 2)
        }
    
    def _generate_html_content(
        self,
        scan_data: Dict[str, Any],
        risk_assessments: List[Any],
        summary: Dict[str, Any]
    ) -> str:
        """Generate HTML content with embedded CSS."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f4f4f4;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 5px;
            border-bottom: 2px solid #ecf0f1;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-card h3 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .summary-card p {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .risk-critical {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .risk-high {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .risk-medium {{ background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); color: #333; }}
        .risk-low {{ background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); color: #333; }}
        .host-assessment {{
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        .host-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .risk-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #e74c3c; }}
        .badge-high {{ background: #e67e22; }}
        .badge-medium {{ background: #f39c12; }}
        .badge-low {{ background: #3498db; }}
        .badge-info {{ background: #95a5a6; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #34495e;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .vulnerability-list {{
            margin-top: 15px;
        }}
        .vuln-item {{
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
            border-left: 4px solid #e74c3c;
        }}
        .recommendations {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
        }}
        .recommendations ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-align: right;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Assessment Report</h1>
        <div class="timestamp">Generated: {timestamp}</div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>{summary['total_hosts']}</h3>
                <p>Hosts Scanned</p>
            </div>
            <div class="summary-card risk-critical">
                <h3>{summary['total_vulnerabilities']}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="summary-card">
                <h3>{summary['average_risk_score']:.1f}</h3>
                <p>Average Risk Score</p>
            </div>
            <div class="summary-card risk-{summary['risk_distribution']['critical'] > 0 and 'critical' or 'low'}">
                <h3>{summary['risk_distribution']['critical']}</h3>
                <p>Critical Risk Hosts</p>
            </div>
        </div>
        
        <h2>Risk Distribution</h2>
        <table>
            <tr>
                <th>Risk Level</th>
                <th>Count</th>
            </tr>
            <tr>
                <td><span class="risk-badge badge-critical">Critical</span></td>
                <td>{summary['risk_distribution']['critical']}</td>
            </tr>
            <tr>
                <td><span class="risk-badge badge-high">High</span></td>
                <td>{summary['risk_distribution']['high']}</td>
            </tr>
            <tr>
                <td><span class="risk-badge badge-medium">Medium</span></td>
                <td>{summary['risk_distribution']['medium']}</td>
            </tr>
            <tr>
                <td><span class="risk-badge badge-low">Low</span></td>
                <td>{summary['risk_distribution']['low']}</td>
            </tr>
            <tr>
                <td><span class="risk-badge badge-info">Info</span></td>
                <td>{summary['risk_distribution']['info']}</td>
            </tr>
        </table>
        
        <h2>Host Assessments</h2>
"""
        
        for assessment in risk_assessments:
            risk_class = f"badge-{assessment.overall_risk.value}"
            html += f"""
        <div class="host-assessment">
            <div class="host-header">
                <div>
                    <strong>{assessment.host_ip}</strong>
                    {f'<span style="color: #7f8c8d;">({assessment.hostname})</span>' if assessment.hostname else ''}
                </div>
                <div>
                    <span class="risk-badge {risk_class}">{assessment.overall_risk.value.upper()}</span>
                    <span style="margin-left: 10px;">Score: {assessment.risk_score:.1f}</span>
                </div>
            </div>
            
            {f'''
            <h3>Vulnerabilities ({len(assessment.vulnerabilities)})</h3>
            <div class="vulnerability-list">
                {''.join([
                    f'''
                    <div class="vuln-item">
                        <strong>{v.cve_id}</strong> - {v.description}<br>
                        <small>Severity: {v.severity.value.upper()} | CVSS: {v.cvss_score} | Service: {v.affected_service}</small>
                    </div>
                    '''
                    for v in assessment.vulnerabilities
                ])}
            </div>
            ''' if assessment.vulnerabilities else '<p>No known vulnerabilities detected.</p>'}
            
            {f'''
            <h3>Risky Services</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Risk Level</th>
                    <th>Reason</th>
                </tr>
                {''.join([
                    f'''
                    <tr>
                        <td>{svc['port']}</td>
                        <td>{svc['service']}</td>
                        <td><span class="risk-badge badge-{svc['risk_level']}">{svc['risk_level'].upper()}</span></td>
                        <td>{svc['reason']}</td>
                    </tr>
                    '''
                    for svc in assessment.risky_services
                ])}
            </table>
            ''' if assessment.risky_services else ''}
            
            {f'''
            <div class="recommendations">
                <h3>Recommendations</h3>
                <ul>
                    {''.join([f'<li>{rec}</li>' for rec in assessment.recommendations])}
                </ul>
            </div>
            ''' if assessment.recommendations else ''}
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def generate_all_reports(
        self,
        scan_data: Dict[str, Any],
        risk_assessments: List[Any],
        base_name: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate all report formats.
        
        Returns:
            Dictionary mapping format names to file paths
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = base_name or f"security_report_{timestamp}"
        
        return {
            "json": self.generate_json_report(scan_data, risk_assessments, f"{base}.json"),
            "html": self.generate_html_report(scan_data, risk_assessments, f"{base}.html"),
            "csv": self.generate_csv_report(risk_assessments, f"{base}.csv")
        }

