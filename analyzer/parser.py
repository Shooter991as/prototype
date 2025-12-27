"""
Advanced XML parser for nmap scan results.
Extracts comprehensive information from nmap XML output.
"""

import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    """Information about a discovered port."""
    port: int
    protocol: str
    state: str
    service: str
    version: str
    product: Optional[str] = None
    extrainfo: Optional[str] = None
    scripts: List[Dict[str, str]] = field(default_factory=list)
    cpe: Optional[str] = None


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "unknown"
    os: Optional[str] = None
    os_accuracy: Optional[int] = None
    ports: List[PortInfo] = field(default_factory=list)
    uptime: Optional[int] = None
    distance: Optional[int] = None


@dataclass
class ScanInfo:
    """Metadata about the scan."""
    target: str
    scan_type: str
    numhosts: int
    numhosts_up: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    command: Optional[str] = None


class NmapParser:
    """Advanced parser for nmap XML output."""
    
    def __init__(self, xml_content: str):
        """
        Initialize parser with XML content.
        
        Args:
            xml_content: Raw XML string from nmap
        """
        self.xml_content = xml_content
        self.root: Optional[ET.Element] = None
        self._parse()
    
    def _parse(self) -> None:
        """Parse XML content into ElementTree."""
        if not self.xml_content:
            logger.warning("Empty XML content provided")
            return
        
        try:
            self.root = ET.fromstring(self.xml_content)
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML: {e}")
            self.root = None
    
    def parse_scan_info(self) -> Optional[ScanInfo]:
        """Extract scan metadata."""
        if not self.root:
            return None
        
        try:
            # Get target from commandline or args
            args = self.root.get("args", "")
            target = args.split()[1] if len(args.split()) > 1 else "unknown"
            
            # Parse scaninfo
            scaninfo = self.root.find("scaninfo")
            scan_type = scaninfo.get("type", "unknown") if scaninfo is not None else "unknown"
            numhosts = int(scaninfo.get("numhosts", "0")) if scaninfo is not None else 0
            
            # Count hosts
            hosts = self.root.findall("host")
            numhosts_up = sum(
                1 for host in hosts
                if host.find("status") is not None and
                host.find("status").get("state") == "up"
            )
            
            # Parse runstats for timing
            runstats = self.root.find("runstats")
            start_time = None
            end_time = None
            
            if runstats is not None:
                finished = runstats.find("finished")
                if finished is not None:
                    time_str = finished.get("time", "")
                    if time_str:
                        try:
                            end_time = datetime.fromtimestamp(int(time_str))
                        except (ValueError, OSError):
                            pass
            
            # Get command
            command = args if args else None
            
            return ScanInfo(
                target=target,
                scan_type=scan_type,
                numhosts=numhosts,
                numhosts_up=numhosts_up,
                end_time=end_time,
                command=command
            )
        except Exception as e:
            logger.error(f"Error parsing scan info: {e}")
            return None
    
    def parse_hosts(self) -> List[HostInfo]:
        """Parse all hosts from XML."""
        if not self.root:
            return []
        
        hosts = []
        for host_elem in self.root.findall("host"):
            try:
                host_info = self._parse_host(host_elem)
                if host_info:
                    hosts.append(host_info)
            except Exception as e:
                logger.error(f"Error parsing host: {e}")
                continue
        
        return hosts
    
    def _parse_host(self, host_elem: ET.Element) -> Optional[HostInfo]:
        """Parse a single host element."""
        # Get IP address
        ip = None
        mac = None
        for address in host_elem.findall("address"):
            addr_type = address.get("addrtype", "")
            if addr_type == "ipv4" or addr_type == "ipv6":
                ip = address.get("addr")
            elif addr_type == "mac":
                mac = address.get("addr")
        
        if not ip:
            return None
        
        # Get status
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
        
        # Get hostname
        hostname = None
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")
        
        # Get OS information
        os_name = None
        os_accuracy = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "")
                try:
                    os_accuracy = int(osmatch.get("accuracy", "0"))
                except (ValueError, TypeError):
                    pass
        
        # Get uptime
        uptime = None
        uptime_elem = host_elem.find("uptime")
        if uptime_elem is not None:
            try:
                uptime = int(uptime_elem.get("seconds", "0"))
            except (ValueError, TypeError):
                pass
        
        # Get distance
        distance = None
        distance_elem = host_elem.find("distance")
        if distance_elem is not None:
            try:
                distance = int(distance_elem.get("value", "0"))
            except (ValueError, TypeError):
                pass
        
        # Parse ports
        ports = self._parse_ports(host_elem)
        
        return HostInfo(
            ip=ip,
            mac=mac,
            hostname=hostname,
            status=status,
            os=os_name,
            os_accuracy=os_accuracy,
            ports=ports,
            uptime=uptime,
            distance=distance
        )
    
    def _parse_ports(self, host_elem: ET.Element) -> List[PortInfo]:
        """Parse ports from host element."""
        ports = []
        ports_elem = host_elem.find("ports")
        
        if ports_elem is None:
            return ports
        
        for port_elem in ports_elem.findall("port"):
            try:
                port_id = port_elem.get("portid")
                protocol = port_elem.get("protocol")
                
                if not port_id:
                    continue
                
                port_num = int(port_id)
                
                # Get state
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                
                # Get service information
                service_elem = port_elem.find("service")
                service = "unknown"
                version = ""
                product = None
                extrainfo = None
                cpe = None
                
                if service_elem is not None:
                    service = service_elem.get("name", "unknown")
                    version = service_elem.get("version", "")
                    product = service_elem.get("product")
                    extrainfo = service_elem.get("extrainfo")
                    
                    # Get CPE
                    cpe_elem = service_elem.find("cpe")
                    if cpe_elem is not None:
                        cpe = cpe_elem.text
                
                # Parse scripts
                scripts = []
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    scripts.append({
                        "id": script_id,
                        "output": script_output
                    })
                
                ports.append(PortInfo(
                    port=port_num,
                    protocol=protocol or "tcp",
                    state=state,
                    service=service,
                    version=version,
                    product=product,
                    extrainfo=extrainfo,
                    scripts=scripts,
                    cpe=cpe
                ))
            except (ValueError, TypeError) as e:
                logger.warning(f"Error parsing port: {e}")
                continue
        
        return ports
    
    def get_open_ports(self) -> Dict[str, List[PortInfo]]:
        """
        Get all open ports grouped by host IP.
        
        Returns:
            Dictionary mapping IP addresses to lists of open ports
        """
        result = {}
        hosts = self.parse_hosts()
        
        for host in hosts:
            open_ports = [p for p in host.ports if p.state == "open"]
            if open_ports:
                result[host.ip] = open_ports
        
        return result
    
    def get_services(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all discovered services with details.
        
        Returns:
            Dictionary with service information indexed by host:port
        """
        result = {}
        hosts = self.parse_hosts()
        
        for host in hosts:
            for port in host.ports:
                if port.state == "open":
                    key = f"{host.ip}:{port.port}"
                    result[key] = {
                        "host": host.ip,
                        "hostname": host.hostname,
                        "port": port.port,
                        "protocol": port.protocol,
                        "service": port.service,
                        "version": port.version,
                        "product": port.product,
                        "cpe": port.cpe,
                        "scripts": port.scripts
                    }
        
        return result
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert parsed data to dictionary format."""
        scan_info = self.parse_scan_info()
        hosts = self.parse_hosts()
        
        return {
            "scan_info": {
                "target": scan_info.target if scan_info else "unknown",
                "scan_type": scan_info.scan_type if scan_info else "unknown",
                "numhosts": scan_info.numhosts if scan_info else 0,
                "numhosts_up": scan_info.numhosts_up if scan_info else 0,
                "command": scan_info.command if scan_info else None
            } if scan_info else {},
            "hosts": [
                {
                    "ip": h.ip,
                    "mac": h.mac,
                    "hostname": h.hostname,
                    "status": h.status,
                    "os": h.os,
                    "os_accuracy": h.os_accuracy,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                            "product": p.product,
                            "cpe": p.cpe,
                            "scripts": p.scripts
                        }
                        for p in h.ports
                    ]
                }
                for h in hosts
            ]
        }

