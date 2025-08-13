"""
Error Pattern Detection Module for Log Analysis.

This module provides functionality to detect common error patterns in logs
that could indicate system issues or anomalies.
"""

import re
from typing import Dict, List, Set, Optional, Any, Tuple
import pandas as pd
from core.standard_log import StandardLog

class ErrorPatternDetector:
    """
    Detector for common error patterns in log messages.
    
    This class analyzes log messages to identify patterns that indicate
    various types of system errors or anomalies.
    """
    
    # Common error patterns
    #Implemented patterns using regex that detect various error types
    ERROR_PATTERNS = {
        'connection_errors': [
            r'connection(?:\s+to\s+\S+)?\s+(?:refused|timed?\s*out|closed|reset|aborted)',
            r'(?:could\s+not|cannot|unable\s+to)\s+connect\s+to',
            r'(?:no\s+route\s+to|unreachable)\s+host',
            r'network\s+(?:unreachable|down|error)',
            r'(?:socket|bind|listen)\s+(?:error|failure)',
        ],
        
        'authentication_errors': [
            r'(?:authentication|authorization)\s+(?:failed|error|invalid)',
            r'(?:invalid|wrong|incorrect|bad)\s+(?:password|credentials|token)',
            r'access\s+denied',
            r'permission\s+denied',
            r'unauthorized\s+access',
        ],
        
        'resource_errors': [
            r'(?:out\s+of|insufficient|low)\s+(?:memory|disk|space|storage|cpu|resource)',
            r'memory\s+(?:allocation|leak)',
            r'disk\s+(?:full|space)',
            r'file(?:system)?\s+(?:full|error)',
            r'too\s+many\s+(?:open\s+files|connections|processes|threads)',
        ],
        
        'service_errors': [
            r'service\s+(?:unavailable|not\s+(?:available|running|found))',
            r'(?:process|service|daemon)\s+(?:crashed|terminated|killed|stopped|exited)',
            r'(?:server|host)\s+(?:down|unavailable)',
            r'(?:deadlock|race\s+condition|starvation)',
        ],
        
        'data_errors': [
            r'(?:corrupt|invalid|malformed)\s+(?:data|file|input|payload|message|packet)',
            r'(?:syntax|parse|format)\s+error',
            r'(?:null|nil)\s+pointer|undefined\s+reference',
            r'(?:segmentation|protection)\s+fault',
            r'(?:division\s+by\s+zero|arithmetic\s+error)',
        ],
        
        'system_errors': [
            r'kernel\s+(?:panic|error|oops)',
            r'(?:system|os)\s+(?:error|crash|halt)',
            r'(?:hardware|firmware|bios)\s+(?:error|failure)',
            r'(?:power|thermal|voltage)\s+(?:issue|problem|error|failure)',
            r'watchdog\s+(?:timeout|reset)',
        ]
    }
    
    def __init__(self, custom_patterns: Optional[Dict[str, List[str]]] = None):
        """Initialize the error pattern detector.

        Parameters
        ----------
        custom_patterns : Optional[Dict[str, List[str]]]
            Optional mapping of additional category -> list of regex strings
            to extend the baseline error patterns (Layer 3).
        """
        # Compile regex patterns for better performance
        self.compiled_patterns: Dict[str, List[re.Pattern]] = {}
        # Baseline (generic) categories
        for category, patterns in self.ERROR_PATTERNS.items():
            self.compiled_patterns[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
        self._baseline_categories: Set[str] = set(self.compiled_patterns.keys())

        # Merge custom categories (if any)
        if custom_patterns:
            for cat, plist in custom_patterns.items():
                try:
                    self.compiled_patterns[cat] = [re.compile(p, re.IGNORECASE) for p in (plist or [])]
                except Exception:
                    # Skip malformed entries; keep robust
                    continue
    
    def detect_in_message(self, message: str) -> List[str]:
        """
        Detect error patterns in a single log message.
        
        Parameters
        ----------
        message : str
            The log message to analyze
            
        Returns
        -------
        List[str]
            List of error categories detected in the message
        """
        detected_categories = []
        
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(message):
                    detected_categories.append(category)
                    break  # If any pattern in this category matches, add the category and move on
        
        return detected_categories
    
    def analyze_logs(self, logs: List[StandardLog]) -> Dict[str, Any]:
        """
        Analyze a list of log entries for error patterns.
        
        Parameters
        ----------
        logs : List[StandardLog]
            List of StandardLog objects to analyze
            
        Returns
        -------
        Dict[str, Any]
            Dictionary containing analysis results
        """
        results: Dict[str, Any] = {
            'total_logs': len(logs),
            'error_counts': {category: 0 for category in self.compiled_patterns},
            'error_logs': {category: [] for category in self.compiled_patterns},
            'error_distribution': {},
            'top_errors': [],
        }
        
        # Analyze each log
        for log in logs:
            detected_categories = self.detect_in_message(log.message)
            
            # Update counts and collect error logs
            for category in detected_categories:
                results['error_counts'][category] += 1
                results['error_logs'][category].append(log)
        
        # Calculate error distribution (percentage)
        total_logs = len(logs)
        if total_logs > 0:
            for category, count in results['error_counts'].items():
                results['error_distribution'][category] = (count / total_logs) * 100
        
        # Get top errors (sorted by count)
        results['top_errors'] = sorted(
            results['error_counts'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return results
    
    def analyze_dataframe(self, df: pd.DataFrame, message_column: str = 'message') -> Dict[str, Any]:
        """
        Analyze a DataFrame of log entries for error patterns.
        
        Parameters
        ----------
        df : pd.DataFrame
            DataFrame containing log entries
        message_column : str, default='message'
            Column containing log messages
            
        Returns
        -------
        Dict[str, Any]
            Dictionary containing analysis results
        """
        results: Dict[str, Any] = {
            'total_logs': len(df),
            'error_counts': {category: 0 for category in self.compiled_patterns},
            'error_indices': {category: [] for category in self.compiled_patterns},
            'error_distribution': {},
            'top_errors': [],
        }
        
        # Analyze each log message (Layer 1: baseline + custom regexes)
        for idx, row in df.iterrows():
            if message_column in row:
                message = row[message_column]
                detected_categories = self.detect_in_message(message)
                
                # Update counts and collect error indices
                for category in detected_categories:
                    results['error_counts'][category] += 1
                    results['error_indices'][category].append(idx)

        # Layer 2: Level-based fallback (independent of regex matching)
        # Look for case-insensitive 'Level' or 'Severity' column
        level_col = None
        for col in df.columns:
            c = str(col).strip()
            if c.lower() in ("level", "severity"):
                level_col = col
                break
        if level_col is not None:
            series = df[level_col].astype(str).str.upper().str.strip()
            sev_targets = ["ERROR", "FATAL", "CRITICAL"]
            level_counts = {sev: int((series == sev).sum()) for sev in sev_targets}
            level_counts["TOTAL"] = sum(level_counts.values())
            results['level_based_errors'] = level_counts
        
        # Calculate error distribution (percentage)
        total_logs = len(df)
        if total_logs > 0:
            for category, count in results['error_counts'].items():
                results['error_distribution'][category] = (count / total_logs) * 100
        
        # Get top errors (sorted by count)
        results['top_errors'] = sorted(
            results['error_counts'].items(),
            key=lambda x: x[1],
            reverse=True
        )

        # Optional aggregate of generic (baseline) categories for convenience
        try:
            results['generic_errors'] = int(sum(results['error_counts'].get(cat, 0) for cat in self._baseline_categories))
        except Exception:
            pass
        
        return results
    
    def get_error_dataframe(self, df: pd.DataFrame, message_column: str = 'message') -> pd.DataFrame:
        """
        Create a DataFrame with error categories for each log entry.
        
        Parameters
        ----------
        df : pd.DataFrame
            DataFrame containing log entries
        message_column : str, default='message'
            Column containing log messages
            
        Returns
        -------
        pd.DataFrame
            DataFrame with additional columns for error categories
        """
        # Create a copy of the input DataFrame
        result_df = df.copy()
        
        # Add a column for each error category
        for category in self.ERROR_PATTERNS:
            result_df[f'error_{category}'] = False
        
        # Add a column for any error
        result_df['has_error'] = False
        
        # Analyze each log message
        for idx, row in df.iterrows():
            if message_column in row:
                message = row[message_column]
                detected_categories = self.detect_in_message(message)
                
                # Update category columns
                for category in detected_categories:
                    result_df.at[idx, f'error_{category}'] = True
                
                # Update has_error column
                if detected_categories:
                    result_df.at[idx, 'has_error'] = True
        
        return result_df


# New: WebSecurityAnalyzer for HTTP access log threat signals
class WebSecurityAnalyzer:
    """
    Analyze HTTP access-like logs for security-relevant patterns.
    Expects columns like: ip, method, path, status, bytes, referer, user_agent, timestamp (optional).
    """

    def __init__(self,
                 large_bytes_threshold: int = 5000,
                 bruteforce_threshold: int = 5,
                 req_per_min_threshold: int = 100,
                 brute_failure_statuses: Optional[List[int]] = None,
                 sensitive_paths: Optional[List[str]] = None,
                 malicious_user_agents: Optional[List[str]] = None,
                 login_paths: Optional[List[str]] = None):
        """Configure thresholds and patterns for analysis.

        Parameters
        ----------
        large_bytes_threshold: int
            Response size above which a response is considered large.
        bruteforce_threshold: int
            Number of failed login attempts per IP to consider as brute-force.
        req_per_min_threshold: int
            Requests-per-minute threshold per IP to flag high-frequency offenders.
        brute_failure_statuses: Optional[List[int]]
            HTTP status codes counted as authentication failures (default: [401, 403]).
        sensitive_paths: Optional[List[str]]
            Additional sensitive path fragments to include in pattern detection.
        malicious_user_agents: Optional[List[str]]
            Additional substrings for malicious/scanner user-agents.
        login_paths: Optional[List[str]]
            Additional path fragments indicating login endpoints.
        """
        self.large_bytes_threshold = large_bytes_threshold
        self.bruteforce_threshold = bruteforce_threshold
        self.req_per_min_threshold = req_per_min_threshold
        self.brute_failure_statuses = set(brute_failure_statuses or [401, 403])

        # Compile regexes
        self.uncommon_methods = re.compile(r'^(?:DELETE|CONNECT|OPTIONS|TRACE|PATCH)$', re.IGNORECASE)

        # Login paths
        login_variants = [r'(?:login|signin)'] + [re.escape(p.strip('/')) for p in (login_paths or [])]
        self.login_path = re.compile(r'/(' + "|".join(login_variants) + r')(?:\b|/)', re.IGNORECASE)

        # Sensitive endpoints and suspicious keywords
        base_sensitive = [
            r'admin', r'wp-admin', r'config', r'backup', r'delete_all', r'drop', r'etc/passwd', r'\.git', r'\.env', r'id_rsa', r'var/log'
        ]
        if sensitive_paths:
            base_sensitive.extend([re.escape(p.strip('/')) for p in sensitive_paths])
        self.sensitive_endpoints = re.compile(r'/(' + "|".join(base_sensitive) + r')(?:\b|/)', re.IGNORECASE)
        self.keyword_suspicious = re.compile(r'\b(?:drop|delete|shutdown|reset)\b', re.IGNORECASE)

        # Injection patterns
        self.sqli = re.compile(r'(?:\bunion\b.*\bselect\b|\bdrop\b.*\btable\b|(?:--|#).*$|\bor\b\s+1=1|\bsleep\s*\()', re.IGNORECASE)
        self.xss = re.compile(r'(?:<script|%3cscript%3e|javascript:|onerror=)', re.IGNORECASE)
        self.cmdi = re.compile(r'(?:;|&&|\||`)\|?\b(?:wget|curl|nc|bash|sh)\b', re.IGNORECASE)

        # Path traversal and file access
        # Catch traversal with plain and mixed encodings
        self.traversal = re.compile(r'(?:\.\./|\.\.\\|%2e%2e/|%2e%2e\\|\.\.%2f|%2e%2f|%2e%2e%2f|%2e%2e%5c|%2e%5c)', re.IGNORECASE)
        self.file_access = re.compile(r'(?:\.env|\.git|\.bak|\.sql|\.db|/etc/passwd|id_rsa|/var/log)', re.IGNORECASE)

        # Suspicious params & base64-like
        self.quote_like = re.compile(r"['\";]|%27|%22|--")
        self.base64_like = re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b')

        # Malicious UAs
        ua_variants = [r'sqlmap', r'nikto', r'fuzz', r'wpscan', r'nessus', r'acunetix', r'dirbuster', r'zaproxy']
        if malicious_user_agents:
            ua_variants.extend([re.escape(u) for u in malicious_user_agents])
        self.mal_ua = re.compile(r'(' + "|".join(ua_variants) + r')', re.IGNORECASE)

    def _get(self, row: pd.Series, key: str) -> str:
        v = row.get(key)
        try:
            return '' if pd.isna(v) else str(v)
        except Exception:
            return str(v)

    def _ensure_method_path(self, df: pd.DataFrame) -> pd.DataFrame:
        if 'request' in df.columns and ('method' not in df.columns or 'path' not in df.columns):
            parts = df['request'].astype(str).str.split(' ', n=2, expand=True)
            if parts.shape[1] >= 2:
                df = df.copy()
                df['method'] = parts[0]
                df['path'] = parts[1]
        return df

    def analyze_access_df(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze an HTTP access-like DataFrame and return counters and details."""
        df = self._ensure_method_path(df)
        cols = set(df.columns.astype(str))

        results: Dict[str, Any] = {
            'counters': {},
            'details': {},
        }

        # Early exit if not access-like
        required_any = {'status', 'method', 'path'}
        if not required_any.intersection(cols):
            results['note'] = 'No HTTP-like columns present'
            return results

        # Prepare series
        method = df['method'].astype(str) if 'method' in cols else pd.Series([''] * len(df))
        path = df['path'].astype(str) if 'path' in cols else df.get('request', pd.Series([''] * len(df))).astype(str)
        status = pd.to_numeric(df['status'], errors='coerce').fillna(-1).astype(int) if 'status' in cols else pd.Series([-1] * len(df))
        bytes_s = pd.to_numeric(df['bytes'], errors='coerce').fillna(0) if 'bytes' in cols else pd.Series([0] * len(df))
        ua = df['user_agent'].astype(str) if 'user_agent' in cols else pd.Series([''] * len(df))
        referer = df['referer'].astype(str) if 'referer' in cols else pd.Series([''] * len(df))
        ip = df['ip'].astype(str) if 'ip' in cols else pd.Series([''] * len(df))

        # Uncommon/dangerous methods
        uncommon_mask = method.str.match(self.uncommon_methods.pattern, case=False, na=False)
        results['counters']['uncommon_methods'] = int(uncommon_mask.sum())
        # Method + error status (4xx/5xx)
        danger_mask = uncommon_mask & (status >= 400)
        results['counters']['uncommon_with_error'] = int(danger_mask.sum())

        # Suspicious endpoints
        sens_mask = path.str.contains(self.sensitive_endpoints.pattern, regex=True, na=False) | path.str.contains(self.keyword_suspicious.pattern, regex=True, na=False)
        results['counters']['suspicious_endpoints'] = int(sens_mask.sum())

        # Injection attempts
        sqli_mask = path.str.contains(self.sqli.pattern, regex=True, na=False)
        xss_mask = path.str.contains(self.xss.pattern, regex=True, na=False)
        cmdi_mask = path.str.contains(self.cmdi.pattern, regex=True, na=False)
        results['counters']['sqli'] = int(sqli_mask.sum())
        results['counters']['xss'] = int(xss_mask.sum())
        results['counters']['cmdi'] = int(cmdi_mask.sum())

        # Traversal & file access
        trav_mask = path.str.contains(self.traversal.pattern, regex=True, na=False)
        file_mask = path.str.contains(self.file_access.pattern, regex=True, na=False)
        results['counters']['path_traversal'] = int(trav_mask.sum())
        results['counters']['file_access'] = int(file_mask.sum())

        # User-Agent checks
        empty_ua_mask = (ua.str.strip() == '') | (ua == '-')
        mal_ua_mask = ua.str.contains(self.mal_ua.pattern, regex=True, na=False)
        results['counters']['empty_user_agent'] = int(empty_ua_mask.sum())
        results['counters']['malicious_user_agent'] = int(mal_ua_mask.sum())

        # Large responses
        large_mask = bytes_s > self.large_bytes_threshold
        results['counters']['large_responses'] = int(large_mask.sum())
        # Potential exfil: large + sensitive endpoint
        exfil_mask = large_mask & sens_mask
        results['counters']['possible_exfiltration'] = int(exfil_mask.sum())

        # Brute force indicators
        login_fail_mask = path.str.contains(self.login_path.pattern, regex=True, na=False) & status.isin(list(self.brute_failure_statuses))
        bf_counts = df[login_fail_mask].groupby(ip, dropna=False).size() if not df[login_fail_mask].empty else pd.Series(dtype=int)
        bf_offenders = bf_counts[bf_counts >= self.bruteforce_threshold].sort_values(ascending=False)
        results['details']['bruteforce_ips'] = bf_offenders.to_dict()
        results['counters']['bruteforce_events'] = int(login_fail_mask.sum())
        results['counters']['bruteforce_offenders'] = int((bf_counts >= self.bruteforce_threshold).sum())

        # Anomalous request frequency (per-minute)
        max_per_min_by_ip: Dict[str, int] = {}
        try:
            if 'timestamp' in cols:
                ts = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
                minute = ts.dt.floor('min')
                per_min = df.assign(__ip=ip, __min=minute).dropna(subset=['__min']).groupby(['__ip', '__min']).size()
                if not per_min.empty:
                    max_per_min_by_ip = per_min.groupby(level=0).max().to_dict()
        except Exception:
            max_per_min_by_ip = {}
        offenders = {k: v for k, v in max_per_min_by_ip.items() if v >= self.req_per_min_threshold}
        results['details']['high_freq_ips'] = offenders
        results['counters']['high_freq_offenders'] = len(offenders)

        # Suspicious query parameters
        quote_mask = path.str.contains(self.quote_like.pattern, regex=True, na=False)
        b64_mask = path.str.contains(self.base64_like.pattern, regex=True, na=False)
        results['counters']['suspicious_params_chars'] = int(quote_mask.sum())
        results['counters']['suspicious_params_base64'] = int(b64_mask.sum())

        # Referrer & origin checks for sensitive endpoints
        no_ref_mask = sens_mask & ((referer.str.strip() == '') | (referer == '-'))
        ext_ref_mask = sens_mask & referer.str.startswith(('http://', 'https://'), na=False) & ~referer.str.contains(r'localhost|127\.0\.0\.1', regex=True, na=False)
        results['counters']['sensitive_no_referer'] = int(no_ref_mask.sum())
        results['counters']['sensitive_external_referer'] = int(ext_ref_mask.sum())

        # Collect top examples for key categories
        def top_examples(mask: pd.Series, key: str, n: int = 5) -> List[Tuple[str, int]]:
            try:
                counts = df[mask][key].value_counts().head(n).to_dict()
                return list(counts.items())
            except Exception:
                return []

        results['details']['top_suspicious_paths'] = dict(top_examples(sens_mask, 'path'))
        if 'user_agent' in cols:
            results['details']['top_malicious_user_agents'] = dict(df[mal_ua_mask]['user_agent'].value_counts().head(5).to_dict())
        else:
            results['details']['top_malicious_user_agents'] = {}
        # Build top_large_paths from numeric series to avoid dtype issues
        if 'bytes' in cols and 'path' in cols and int(large_mask.sum()) > 0:
            tmp = pd.DataFrame({'path': path, 'bytes': bytes_s})
            top_large = tmp[large_mask].nlargest(5, 'bytes').set_index('path')['bytes'].astype(int).to_dict()
            results['details']['top_large_paths'] = top_large
        else:
            results['details']['top_large_paths'] = {}

        return results


__all__ = ["ErrorPatternDetector", "WebSecurityAnalyzer"]


# Example usage
if __name__ == "__main__":
    import os
    
    print("\n" + "="*60)
    print("Error Pattern Detection Example")
    print("="*60)
    
    # Create a detector
    detector = ErrorPatternDetector()
    
    # Test with some sample log messages
    sample_messages = [
        "Connection refused to database server at 192.168.1.100",
        "Authentication failed for user 'admin'",
        "Out of memory error occurred during processing",
        "Service unavailable: nginx process crashed",
        "Corrupt data found in log file",
        "Kernel panic: unable to mount root filesystem",
        "Normal log message with no errors",
        "User logged in successfully",
        "Process completed without errors"
    ]
    
    print("Testing with sample log messages:")
    for i, message in enumerate(sample_messages, 1):
        detected = detector.detect_in_message(message)
        if detected:
            print(f"{i}. ERROR - {message}")
            print(f"   Detected categories: {', '.join(detected)}")
        else:
            print(f"{i}. OK - {message}")
    
    # Test with a DataFrame
    print("\nTesting with a DataFrame:")
    df = pd.DataFrame({
        'id': range(1, len(sample_messages) + 1),
        'message': sample_messages,
        'timestamp': pd.date_range(start='2023-07-18', periods=len(sample_messages), freq='H')
    })
    
    # Analyze the DataFrame
    results = detector.analyze_dataframe(df)
    
    print("\nError Analysis Results:")
    print(f"Total logs: {results['total_logs']}")
    
    print("\nError counts:")
    for category, count in results['top_errors']:
        if count > 0:
            print(f"  {category}: {count} logs ({results['error_distribution'][category]:.1f}%)")
    
    # Get a DataFrame with error categories
    error_df = detector.get_error_dataframe(df)
    
    print("\nDataFrame with error categories:")
    print(error_df[['id', 'message', 'has_error'] + [f'error_{c}' for c in detector.ERROR_PATTERNS if error_df[f'error_{c}'].any()]])
