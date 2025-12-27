"""
Scan profile configurations for different scanning scenarios.
Provides pre-configured nmap argument sets for various use cases.
"""

from typing import Dict, List, Optional


class ScanProfile:
    """Manages scan profiles with predefined nmap configurations."""
    
    # Basic profiles
    PROFILES: Dict[str, List[str]] = {
        "demo": [
            "-p", "22,80,443,445",
            "--open",
            "-sV",  # Version detection
            "-sC"   # Default scripts
        ],
        "safe": [
            "-p", "1-1024",
            "--open",
            "-sV"
        ],
        "quick": [
            "-F",  # Fast scan (top 100 ports)
            "--open",
            "-sV",
            "-T4"  # Aggressive timing
        ],
        "stealth": [
            "-sS",  # SYN scan
            "-f",   # Fragment packets
            "-D", "RND:10",  # Decoy scan
            "-T2",  # Polite timing
            "--open"
        ],
        "comprehensive": [
            "-p-",  # All ports
            "-sV",
            "-sC",  # Default scripts
            "-A",   # Aggressive scan (OS detection, version, script, traceroute)
            "-O",   # OS detection
            "--script=vuln",  # Vulnerability scripts
            "-T4"
        ],
        "vulnerability": [
            "-sV",
            "--script=vuln,auth,exploit",
            "--open",
            "-T4"
        ],
        "udp": [
            "-sU",  # UDP scan
            "--top-ports", "100",
            "-sV",
            "--open"
        ],
        "os_detection": [
            "-O",   # OS detection
            "-sV",
            "-sC",
            "-T4"
        ],
        "service_scan": [
            "-sV",
            "--version-intensity", "9",  # Maximum version detection
            "--open",
            "-T4"
        ],
        "intense": [
            "-p-",
            "-sS",
            "-sV",
            "-sC",
            "-A",
            "-O",
            "-T4"
        ]
    }
    
    @classmethod
    def get_profile(cls, profile_name: str) -> Optional[List[str]]:
        """
        Get scan arguments for a profile.
        
        Args:
            profile_name: Name of the profile
            
        Returns:
            List of nmap arguments or None if profile doesn't exist
        """
        return cls.PROFILES.get(profile_name.lower())
    
    @classmethod
    def list_profiles(cls) -> List[str]:
        """Return list of available profile names."""
        return list(cls.PROFILES.keys())
    
    @classmethod
    def create_custom_profile(
        cls,
        name: str,
        ports: Optional[str] = None,
        scripts: Optional[List[str]] = None,
        scan_type: str = "-sV",
        timing: str = "-T4",
        additional_args: Optional[List[str]] = None
    ) -> None:
        """
        Create a custom scan profile.
        
        Args:
            name: Profile name
            ports: Port specification (e.g., "80,443" or "1-1024")
            scripts: List of script categories or specific scripts
            scan_type: Scan type (e.g., "-sS", "-sV")
            timing: Timing template (-T0 to -T5)
            additional_args: Additional nmap arguments
        """
        args = []
        
        if ports:
            args.extend(["-p", ports])
        else:
            args.append("--top-ports")
            args.append("1000")
        
        args.append("--open")
        args.append(scan_type)
        
        if scripts:
            script_arg = ",".join(scripts)
            args.extend(["--script", script_arg])
        
        args.append(timing)
        
        if additional_args:
            args.extend(additional_args)
        
        cls.PROFILES[name.lower()] = args
    
    @classmethod
    def get_combined_profile(
        cls,
        base_profile: str,
        additional_args: List[str]
    ) -> Optional[List[str]]:
        """
        Combine a base profile with additional arguments.
        
        Args:
            base_profile: Name of base profile
            additional_args: Additional arguments to append
            
        Returns:
            Combined argument list or None if base profile doesn't exist
        """
        base = cls.get_profile(base_profile)
        if base is None:
            return None
        
        return base + additional_args


# Initialize default profiles
scan_profiles = ScanProfile.PROFILES
