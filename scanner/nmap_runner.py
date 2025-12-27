"""
Advanced Nmap Scanner with async support and comprehensive error handling.
Supports multiple output formats and scan configurations.
"""

import subprocess
import asyncio
import xml.etree.ElementTree as ET
import json
import logging
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Container for scan results."""
    target: str
    xml_output: str
    json_output: Dict
    scan_time: datetime
    success: bool
    error_message: Optional[str] = None


class NmapRunner:
    """Advanced Nmap scanner with async support and comprehensive features."""
    
    def __init__(self, timeout: int = 300, sudo: bool = False):
        """
        Initialize Nmap runner.
        
        Args:
            timeout: Maximum scan time in seconds
            sudo: Whether to use sudo for privileged scans
        """
        self.timeout = timeout
        self.sudo = sudo
        self._check_nmap_installed()
    
    def _check_nmap_installed(self) -> None:
        """Verify nmap is installed and accessible."""
        try:
            cmd = ["sudo", "nmap", "--version"] if self.sudo else ["nmap", "--version"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("nmap is not installed or not accessible")
            logger.info(f"Nmap version check passed: {result.stdout.split()[2]}")
        except FileNotFoundError:
            raise RuntimeError("nmap command not found. Please install nmap.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("nmap version check timed out")
    
    async def scan_async(
        self,
        target: str,
        scan_args: List[str],
        output_file: Optional[str] = None
    ) -> ScanResult:
        """
        Execute nmap scan asynchronously.
        
        Args:
            target: Target host or network range
            scan_args: List of nmap arguments
            output_file: Optional path to save XML output
            
        Returns:
            ScanResult object with scan data
        """
        return await asyncio.to_thread(
            self.scan_sync,
            target,
            scan_args,
            output_file
        )
    
    def scan_sync(
        self,
        target: str,
        scan_args: List[str],
        output_file: Optional[str] = None
    ) -> ScanResult:
        """
        Execute nmap scan synchronously.
        
        Args:
            target: Target host or network range
            scan_args: List of nmap arguments
            output_file: Optional path to save XML output
            
        Returns:
            ScanResult object with scan data
        """
        # Use temporary file if no output file specified
        temp_xml = None
        if output_file is None:
            temp_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.xml',
                delete=False
            )
            output_file = temp_file.name
            temp_file.close()
            temp_xml = output_file
        
        try:
            # Build command
            base_cmd = ["sudo", "nmap"] if self.sudo else ["nmap"]
            cmd = base_cmd + [
                target,
                *scan_args,
                "-oX", output_file,
                "--no-stylesheet"  # Remove XSL stylesheet reference for parsing
            ]
            
            logger.info(f"Executing: {' '.join(cmd)}")
            start_time = datetime.now()
            
            # Execute scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                raise TimeoutError(f"Scan exceeded timeout of {self.timeout} seconds")
            
            scan_time = datetime.now()
            
            # Read XML output
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    xml_output = f.read()
            else:
                xml_output = ""
            
            # Parse XML to JSON for easier access
            json_output = self._xml_to_json(xml_output) if xml_output else {}
            
            success = process.returncode == 0 and len(xml_output) > 0
            
            if not success:
                error_msg = stderr or "Unknown error occurred"
                logger.error(f"Scan failed: {error_msg}")
            else:
                logger.info(f"Scan completed successfully in {(scan_time - start_time).total_seconds():.2f}s")
            
            return ScanResult(
                target=target,
                xml_output=xml_output,
                json_output=json_output,
                scan_time=scan_time,
                success=success,
                error_message=stderr if not success else None
            )
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return ScanResult(
                target=target,
                xml_output="",
                json_output={},
                scan_time=datetime.now(),
                success=False,
                error_message=str(e)
            )
        finally:
            # Clean up temporary file if we created it
            if temp_xml and os.path.exists(temp_xml) and output_file == temp_xml:
                try:
                    os.unlink(temp_xml)
                except Exception as e:
                    logger.warning(f"Failed to delete temp file: {e}")
    
    def _xml_to_json(self, xml_content: str) -> Dict:
        """Convert nmap XML output to JSON structure."""
        if not xml_content:
            return {}
        
        try:
            root = ET.fromstring(xml_content)
            
            result = {
                "scaninfo": {},
                "hosts": []
            }
            
            # Parse scaninfo
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                result["scaninfo"] = scaninfo.attrib
            
            # Parse hosts
            for host in root.findall("host"):
                host_data = {
                    "status": {},
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": {},
                    "uptime": {}
                }
                
                # Status
                status = host.find("status")
                if status is not None:
                    host_data["status"] = status.attrib
                
                # Addresses
                for address in host.findall("address"):
                    host_data["addresses"].append(address.attrib)
                
                # Hostnames
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hostname in hostnames.findall("hostname"):
                        host_data["hostnames"].append(hostname.attrib)
                
                # Ports
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_data = {
                            "protocol": port.get("protocol"),
                            "portid": port.get("portid"),
                            "state": {},
                            "service": {}
                        }
                        
                        state = port.find("state")
                        if state is not None:
                            port_data["state"] = state.attrib
                        
                        service = port.find("service")
                        if service is not None:
                            port_data["service"] = service.attrib
                        
                        # Script output
                        scripts = port.findall("script")
                        if scripts:
                            port_data["scripts"] = []
                            for script in scripts:
                                script_data = {
                                    "id": script.get("id"),
                                    "output": script.get("output", "")
                                }
                                port_data["scripts"].append(script_data)
                        
                        host_data["ports"].append(port_data)
                
                # OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host_data["os"] = osmatch.attrib
                
                # Uptime
                uptime = host.find("uptime")
                if uptime is not None:
                    host_data["uptime"] = uptime.attrib
                
                result["hosts"].append(host_data)
            
            return result
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML: {e}")
            return {}
    
    def scan_multiple(
        self,
        targets: List[str],
        scan_args: List[str],
        max_concurrent: int = 5
    ) -> List[ScanResult]:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of target hosts/networks
            scan_args: Nmap arguments for all scans
            max_concurrent: Maximum concurrent scans
            
        Returns:
            List of ScanResult objects
        """
        async def run_scans():
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def scan_with_limit(target):
                async with semaphore:
                    return await self.scan_async(target, scan_args)
            
            tasks = [scan_with_limit(target) for target in targets]
            return await asyncio.gather(*tasks)
        
        return asyncio.run(run_scans())

