#!/usr/bin/env python3
"""
Advanced Security Scanner and Risk Assessment Tool
Main entry point for the security scanning application.
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from scanner.nmap_runner import NmapRunner
from scanner.scan_profile import ScanProfile
from analyzer.parser import NmapParser
from analyzer.risk_engine import RiskEngine
from reports.report_generator import ReportGenerator


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main security scanner orchestration class."""
    
    def __init__(
        self,
        cve_db_path: Optional[str] = None,
        output_dir: str = "reports",
        timeout: int = 300,
        sudo: bool = False
    ):
        """
        Initialize security scanner.
        
        Args:
            cve_db_path: Path to CVE mapping CSV file
            output_dir: Directory for output reports
            timeout: Scan timeout in seconds
            sudo: Use sudo for privileged scans
        """
        self.nmap_runner = NmapRunner(timeout=timeout, sudo=sudo)
        self.risk_engine = RiskEngine(cve_db_path=cve_db_path)
        self.report_generator = ReportGenerator(output_dir=output_dir)
    
    def scan_and_assess(
        self,
        target: str,
        profile_name: Optional[str] = None,
        custom_args: Optional[List[str]] = None,
        output_xml: Optional[str] = None
    ) -> dict:
        """
        Perform scan and risk assessment.
        
        Args:
            target: Target host or network range
            profile_name: Name of scan profile to use
            custom_args: Custom nmap arguments (overrides profile)
            output_xml: Optional path to save XML output
            
        Returns:
            Dictionary with scan results and assessments
        """
        logger.info(f"Starting scan of target: {target}")
        
        # Determine scan arguments
        if custom_args:
            scan_args = custom_args
            logger.info(f"Using custom scan arguments: {' '.join(scan_args)}")
        elif profile_name:
            scan_args = ScanProfile.get_profile(profile_name)
            if not scan_args:
                logger.error(f"Unknown profile: {profile_name}")
                logger.info(f"Available profiles: {', '.join(ScanProfile.list_profiles())}")
                return {"error": f"Unknown profile: {profile_name}"}
            logger.info(f"Using profile: {profile_name}")
        else:
            # Default to quick profile
            scan_args = ScanProfile.get_profile("quick")
            logger.info("Using default profile: quick")
        
        # Execute scan
        scan_result = self.nmap_runner.scan_sync(target, scan_args, output_xml)
        
        if not scan_result.success:
            logger.error(f"Scan failed: {scan_result.error_message}")
            return {
                "error": scan_result.error_message,
                "target": target
            }
        
        logger.info("Scan completed successfully, parsing results...")
        
        # Parse XML output
        parser = NmapParser(scan_result.xml_output)
        scan_data = parser.to_dict()
        
        logger.info(f"Found {len(scan_data['hosts'])} hosts")
        
        # Perform risk assessment
        logger.info("Performing risk assessment...")
        risk_assessments = self.risk_engine.assess_multiple_hosts(scan_data["hosts"])
        
        logger.info(f"Completed risk assessment for {len(risk_assessments)} hosts")
        
        return {
            "scan_result": scan_result,
            "scan_data": scan_data,
            "risk_assessments": risk_assessments
        }
    
    def generate_reports(
        self,
        scan_data: dict,
        risk_assessments: List,
        base_name: Optional[str] = None
    ) -> dict:
        """
        Generate all report formats.
        
        Args:
            scan_data: Parsed scan data
            risk_assessments: List of risk assessment objects
            base_name: Base name for report files
            
        Returns:
            Dictionary mapping format names to file paths
        """
        logger.info("Generating reports...")
        return self.report_generator.generate_all_reports(
            scan_data,
            risk_assessments,
            base_name
        )


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced Security Scanner and Risk Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan with default profile
  python main.py 192.168.1.0/24
  
  # Comprehensive scan with specific profile
  python main.py 192.168.1.1 --profile comprehensive
  
  # Custom scan arguments
  python main.py 10.0.0.1 --args "-p 80,443 -sV -A"
  
  # Multiple targets
  python main.py 192.168.1.1 10.0.0.1 --profile vulnerability
  
  # Save XML output
  python main.py 192.168.1.1 --output-xml scan_results.xml
        """
    )
    
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target host(s) or network range(s) to scan"
    )
    
    parser.add_argument(
        "-p", "--profile",
        choices=ScanProfile.list_profiles(),
        help="Scan profile to use"
    )
    
    parser.add_argument(
        "-a", "--args",
        help="Custom nmap arguments (space-separated, e.g., '-p 80,443 -sV')"
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Output directory for reports (default: reports)"
    )
    
    parser.add_argument(
        "-x", "--output-xml",
        help="Save XML output to file"
    )
    
    parser.add_argument(
        "-c", "--cve-db",
        default="data/cve_mapping.csv",
        help="Path to CVE mapping CSV file (default: data/cve_mapping.csv)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=300,
        help="Scan timeout in seconds (default: 300)"
    )
    
    parser.add_argument(
        "--sudo",
        action="store_true",
        help="Use sudo for privileged scans"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available scan profiles and exit"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # List profiles if requested
    if args.list_profiles:
        print("Available scan profiles:")
        for profile in ScanProfile.list_profiles():
            args_list = ScanProfile.get_profile(profile)
            print(f"  {profile:15s}: {' '.join(args_list)}")
        return 0
    
    # Require targets if not listing profiles
    if not args.targets:
        parser.error("the following arguments are required: targets (or use --list-profiles)")
    
    # Parse custom arguments if provided
    custom_args = None
    if args.args:
        custom_args = args.args.split()
        # Remove profile if custom args provided
        if args.profile:
            logger.warning("Custom arguments provided, ignoring profile")
    
    # Initialize scanner
    try:
        scanner = SecurityScanner(
            cve_db_path=args.cve_db if Path(args.cve_db).exists() else None,
            output_dir=args.output_dir,
            timeout=args.timeout,
            sudo=args.sudo
        )
    except Exception as e:
        logger.error(f"Failed to initialize scanner: {e}")
        return 1
    
    # Process each target
    all_results = []
    
    for target in args.targets:
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing target: {target}")
        logger.info(f"{'='*60}\n")
        
        result = scanner.scan_and_assess(
            target=target,
            profile_name=args.profile if not custom_args else None,
            custom_args=custom_args,
            output_xml=args.output_xml
        )
        
        if "error" in result:
            logger.error(f"Failed to scan {target}: {result['error']}")
            continue
        
        all_results.append(result)
        
        # Generate reports for this target
        report_files = scanner.generate_reports(
            scan_data=result["scan_data"],
            risk_assessments=result["risk_assessments"],
            base_name=f"scan_{target.replace('/', '_').replace('.', '_')}"
        )
        
        logger.info(f"\nReports generated:")
        for fmt, path in report_files.items():
            logger.info(f"  {fmt.upper()}: {path}")
    
    # Generate combined report if multiple targets
    if len(all_results) > 1:
        logger.info("\nGenerating combined report for all targets...")
        
        # Combine all scan data and assessments
        combined_scan_data = {
            "scan_info": {
                "target": ", ".join(args.targets),
                "scan_type": "multiple",
                "numhosts": sum(len(r["scan_data"]["hosts"]) for r in all_results),
                "numhosts_up": sum(
                    r["scan_data"]["scan_info"].get("numhosts_up", 0)
                    for r in all_results
                )
            },
            "hosts": []
        }
        
        combined_assessments = []
        for result in all_results:
            combined_scan_data["hosts"].extend(result["scan_data"]["hosts"])
            combined_assessments.extend(result["risk_assessments"])
        
        combined_reports = scanner.generate_reports(
            scan_data=combined_scan_data,
            risk_assessments=combined_assessments,
            base_name="combined_scan_report"
        )
        
        logger.info(f"\nCombined reports generated:")
        for fmt, path in combined_reports.items():
            logger.info(f"  {fmt.upper()}: {path}")
    
    logger.info("\nScan and assessment completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())

