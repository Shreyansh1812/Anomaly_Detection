"""
Raw Log Parser Module for Anomaly Detection System.

This module is responsible for parsing unstructured log files and converting them
to a structured format suitable for further processing and analysis.
"""

import os
import re
from typing import Dict, List, Optional, Iterator, Any, Pattern, Tuple
from datetime import datetime
import pandas as pd
from pathlib import Path

# Common log regex patterns (utility) matching popular formats
LOG_PATTERNS: List[Pattern[str]] = [
    # Apache/Nginx Combined Log Format
    re.compile(
        r'(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) '
        r'\[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<path>[^\"]+) HTTP/(?P<http_version>\d+\.\d+)" '
        r'(?P<status>\d{3}) (?P<size>\S+) '
        r'"(?P<referrer>[^\"]*)" "(?P<user_agent>[^\"]*)"'
    ),
    # Apache Common Log Format (no referrer/UA)
    re.compile(
        r'(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) '
        r'\[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<path>[^\"]+) HTTP/(?P<http_version>\d+\.\d+)" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
    ),
    # W3C Extended Log Format
    re.compile(
        r'(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) '
        r'(?P<ip>\S+) (?P<method>[A-Z]+) (?P<path>\S+) '
        r'(?P<status>\d{3}) (?P<size>\S+)'
    ),
    # Nginx Error Log Format
    re.compile(
        r'(?P<datetime>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
        r'\[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): '
        r'\*(?P<cid>\d+) (?P<message>.+)'
    ),
]


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Try all regex patterns until one matches; return extracted fields and normalized datetime_obj if possible."""
    for pattern in LOG_PATTERNS:
        m = pattern.match(line)
        if not m:
            continue
        data: Dict[str, Any] = m.groupdict()
        # Normalize datetime when present
        if 'datetime' in data and data['datetime']:
            for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y/%m/%d %H:%M:%S"):
                try:
                    data['datetime_obj'] = datetime.strptime(data['datetime'], fmt)
                    break
                except ValueError:
                    continue
        elif 'date' in data and 'time' in data:
            try:
                data['datetime_obj'] = datetime.strptime(f"{data['date']} {data['time']}", "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        return data
    return None


class LogFormat:
    """
    Container for log format patterns and their parsing logic.
    
    This class stores regex patterns and parsing instructions for different log formats.
    Each format has its own regex pattern and field extraction rules.
    """
    
    # Common timestamp patterns found in logs
    TIMESTAMP_PATTERNS = {
        # ISO format: 2023-07-18T15:30:45
        'iso': r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)',
        
        # Common date formats
        'date1': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)',  # 2023-07-18 15:30:45
        'date2': r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})',  # 07/18/2023 15:30:45
        'date3': r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})',  # Jul 18 15:30:45
        
        # Syslog format: Jul 18 15:30:45
        'syslog': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    }
    
    # Common log level patterns
    LEVEL_PATTERNS = {
        'standard': r'\b(INFO|WARNING|ERROR|DEBUG|CRITICAL|FATAL|WARN|ERR|NOTICE|TRACE)\b',
        'brackets': r'\[(INFO|WARNING|ERROR|DEBUG|CRITICAL|FATAL|WARN|ERR|NOTICE|TRACE)\]'
    }
    
    # Built-in log format patterns
    # Each format has a name, regex pattern, and field mapping
    FORMATS = {
        # Apache/Nginx Combined Log Format (with referrer and user agent)
        'apache_combined': {
            'pattern': r'(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) \[(?P<datetime>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^"]+) HTTP/(?P<http_version>\d+\.\d+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"',
            'fields': ['ip','ident','authuser','datetime','method','path','http_version','status','size','referrer','user_agent']
        },

        # Apache Common Log Format (no referrer/UA)
        'apache_common': {
            'pattern': r'(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) \[(?P<datetime>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^"]+) HTTP/(?P<http_version>\d+\.\d+)" (?P<status>\d{3}) (?P<size>\S+)',
            'fields': ['ip','ident','authuser','datetime','method','path','http_version','status','size']
        },

        # W3C Extended Log Format
        'w3c_extended': {
            'pattern': r'(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<ip>\S+) (?P<method>[A-Z]+) (?P<path>\S+) (?P<status>\d{3}) (?P<size>\S+)',
            'fields': ['date','time','ip','method','path','status','size']
        },

        # Nginx Error Log Format
        'nginx_error': {
            'pattern': r'(?P<datetime>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): \*(?P<cid>\d+) (?P<message>.+)',
            'fields': ['datetime','level','pid','tid','cid','message']
        },

        # Apache/NGINX access log format
        'apache_access': {
            'pattern': r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
            'fields': ['ip', 'timestamp', 'request', 'status', 'bytes', 'referer', 'user_agent']
        },
        
        # Apache error log format
        'apache_error': {
            'pattern': r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)',
            'fields': ['timestamp', 'level', 'module', 'message']
        },
        
        # Syslog format
        'syslog': {
            'pattern': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*)',
            'fields': ['timestamp', 'host', 'program', 'pid', 'message']
        },
        
        # Simple format with timestamp, level, and message
        'simple': {
            'pattern': r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\S+)\s+(.*)',
            'fields': ['timestamp', 'level', 'message']
        },
        
        # Java/Spring boot log format
        'java': {
            'pattern': r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\S+)\s+(\S+)\s+\[(\S+)\]\s+(\S+)\s+(.*)',
            'fields': ['timestamp', 'level', 'pid', 'thread', 'class', 'message']
        },
        
        # BGL log format
        'bgl': {
            'pattern': r'(\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)',
            'fields': ['timestamp', 'location', 'component', 'category', 'level', 'message']
        },
        
        # HDFS log format
        'hdfs': {
            'pattern': r'(\d{6}\s+\d{6})\s+(\d+)\s+(\S+)\s+(.*?):\s+(.*)',
            'fields': ['timestamp', 'pid', 'level', 'component', 'message']
        },
        
        # Thunderbird log format
        'thunderbird': {
            'pattern': r'(\d{6}\s+\d{6})\s+(\S+)\s+(\S+)\s+(.*?):\s+(.*)',
            'fields': ['timestamp', 'level', 'component', 'node', 'message']
        }
    }
    
    @classmethod
    def get_pattern(cls, format_name: str) -> Tuple[Pattern, List[str]]:
        """
        Get the compiled regex pattern and field names for a specific log format.
        
        Parameters
        ----------
        format_name : str
            Name of the log format (e.g., 'apache_access', 'syslog')
            
        Returns
        -------
        Tuple[Pattern, List[str]]
            A tuple containing the compiled regex pattern and the list of field names
            
        Raises
        ------
        ValueError
            If the format name is not recognized
        """
        if format_name not in cls.FORMATS:
            raise ValueError(f"Unknown log format: {format_name}")
            
        format_info = cls.FORMATS[format_name]
        pattern = re.compile(format_info['pattern'])
        fields = format_info['fields']
        
        return pattern, fields


class TextLogParser:
    """
    Parser for unstructured text log files.
    
    This class reads raw log files and parses them into a structured format
    using regular expressions and pattern matching.
    """
    
    def __init__(self, file_path: str, format_name: Optional[str] = None):
        """
        Initialize the text log parser.
        
        Parameters
        ----------
        file_path : str
            Path to the log file to parse
            
        format_name : Optional[str], default=None
            Name of the log format to use (e.g., 'apache_access', 'syslog').
            If None, the parser will try to auto-detect the format.
            
        Raises
        ------
        FileNotFoundError
            If the specified file does not exist
        """
        self.file_path = file_path
        self.format_name = format_name
        
        # Check if the file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        # The parsed data will be stored here
        self._data = None
    
    def detect_format(self) -> str:
        """
        Detect the format of the log file by sampling lines and matching patterns.
        
        Returns
        -------
        str
            Detected format name or 'unknown' if no match is found
        """
        # Read a sample of lines from the file
        sample_lines = []
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(10):  # Sample the first 10 lines
                line = f.readline().strip()
                if not line:
                    continue
                sample_lines.append(line)
        
        # Try each format pattern against the sample lines
        format_matches = {}
        
        for format_name, format_info in LogFormat.FORMATS.items():
            pattern = re.compile(format_info['pattern'])
            matches = 0
            
            for line in sample_lines:
                if pattern.match(line):
                    matches += 1
            
            if matches > 0:
                format_matches[format_name] = matches / len(sample_lines)
        
        # If no matches, return 'unknown'
        if not format_matches:
            return 'unknown'
        
        # Return the format with the highest match ratio
        return max(format_matches.items(), key=lambda x: x[1])[0]
    
    def parse(self) -> pd.DataFrame:
        """
        Parse the log file into a structured pandas DataFrame.
        
        Returns
        -------
        pd.DataFrame
            DataFrame containing the parsed log data with appropriate columns
            
        Raises
        ------
        ValueError
            If the log format cannot be determined or is not supported
        """
        # If format_name wasn't specified, try to detect it
        if self.format_name is None:
            self.format_name = self.detect_format()
            
        # If format is still unknown, raise an error
        if self.format_name == 'unknown':
            raise ValueError("Could not determine log format. Please specify a format.")
        
        # Get the pattern and field names for this format
        try:
            pattern, fields = LogFormat.get_pattern(self.format_name)
        except ValueError as e:
            raise ValueError(f"Error parsing logs: {str(e)}")
        
        # Parse the log file line by line
        parsed_logs = []
        
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                match = pattern.match(line)
                if match:
                    # Extract field values from the regex match
                    values = match.groups()
                    log_entry = {field: value for field, value in zip(fields, values)}
                    
                    # Add metadata
                    log_entry['line_num'] = line_num
                    log_entry['raw_content'] = line
                    
                    parsed_logs.append(log_entry)
                else:
                    # Handle lines that don't match the pattern
                    # You could add them as unparsed entries or skip them
                    parsed_logs.append({
                        'line_num': line_num,
                        'raw_content': line,
                        'parsed': False
                    })
        
        # Convert to DataFrame
        if parsed_logs:
            df = pd.DataFrame(parsed_logs)
            
            # Mark successfully parsed entries
            if 'parsed' not in df.columns:
                df['parsed'] = True

            # Normalize datetime/datetime_obj when present (vectorized)
            try:
                if 'datetime' in df.columns:
                    dt1 = pd.to_datetime(df['datetime'], format="%d/%b/%Y:%H:%M:%S %z", errors='coerce')
                    dt2 = pd.to_datetime(df['datetime'], format="%Y/%m/%d %H:%M:%S", errors='coerce')
                    df['datetime_obj'] = dt1.fillna(dt2)
                elif 'date' in df.columns and 'time' in df.columns:
                    df['datetime_obj'] = pd.to_datetime(df['date'].astype(str) + ' ' + df['time'].astype(str), format="%Y-%m-%d %H:%M:%S", errors='coerce')
            except Exception:
                pass
                
            return df
        else:
            # Return an empty DataFrame with the expected columns
            columns = fields + ['line_num', 'raw_content', 'parsed']
            return pd.DataFrame(columns=columns)
    
    def to_csv(self, output_path: Optional[str] = None) -> str:
        """
        Parse the log file and save the results to a CSV file.
        
        Parameters
        ----------
        output_path : Optional[str], default=None
            Path where the CSV file should be saved.
            If None, a path will be generated based on the input file name.
            
        Returns
        -------
        str
            Path to the created CSV file
        """
        # Parse the logs
        df = self.parse()
        
        # Generate output path if not provided
        if output_path is None:
            input_path = Path(self.file_path)
            output_path = str(input_path.with_suffix('.csv'))
        
        # Save to CSV
        df.to_csv(output_path, index=False)
        
        return output_path


class LogDirectoryProcessor:
    """
    Process all log files in a directory.
    
    This class scans a directory for log files, parses them,
    and outputs structured CSV files.
    """
    
    def __init__(self, input_dir: str, output_dir: Optional[str] = None):
        """
        Initialize the log directory processor.
        
        Parameters
        ----------
        input_dir : str
            Directory containing log files to process
            
        output_dir : Optional[str], default=None
            Directory where parsed CSV files should be saved.
            If None, CSV files will be saved in the same directory as the input files.
        """
        self.input_dir = input_dir
        self.output_dir = output_dir or input_dir
        
        # Ensure the output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
    
    def process_all(self, recursive: bool = False) -> List[str]:
        """
        Process all log files in the directory.
        
        Parameters
        ----------
        recursive : bool, default=False
            Whether to recursively process subdirectories
            
        Returns
        -------
        List[str]
            List of paths to the created CSV files
        """
        # Find all log files in the directory
        log_files = []
        
        if recursive:
            # Walk the directory tree to find log files recursively
            for root, _, files in os.walk(self.input_dir):
                for file in files:
                    if self._is_log_file(file):
                        log_files.append(os.path.join(root, file))
        else:
            # Only look in the specified directory
            for file in os.listdir(self.input_dir):
                file_path = os.path.join(self.input_dir, file)
                if os.path.isfile(file_path) and self._is_log_file(file):
                    log_files.append(file_path)
        
        # Process each log file
        csv_files = []
        
        for log_file in log_files:
            try:
                # Determine the output path
                rel_path = os.path.relpath(log_file, self.input_dir)
                output_path = os.path.join(self.output_dir, f"{os.path.splitext(rel_path)[0]}.csv")
                
                # Ensure the output directory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                # Parse the log file
                parser = TextLogParser(log_file)
                csv_path = parser.to_csv(output_path)
                
                csv_files.append(csv_path)
                print(f"Processed {log_file} -> {csv_path}")
                
            except Exception as e:
                print(f"Error processing {log_file}: {e}")
        
        return csv_files
    
    def _is_log_file(self, filename: str) -> bool:
        """
        Check if a file is likely a log file based on its extension.
        
        Parameters
        ----------
        filename : str
            Name of the file to check
            
        Returns
        -------
        bool
            True if the file is likely a log file, False otherwise
        """
        # Common log file extensions
        log_extensions = ['.log', '.txt', '.out', '.err']
        
        # Check if the file has a log extension
        return any(filename.endswith(ext) for ext in log_extensions)


# Example usage
if __name__ == "__main__":
    import os
    
    print("\n" + "="*60)
    print("Example 1: Parsing a raw log text file")
    print("="*60)
    
    # Create a sample log directory for testing
    test_log_dir = "Data/test_logs"
    os.makedirs(test_log_dir, exist_ok=True)
    
    # Sample HDFS format log lines
    hdfs_log_lines = [
        "081109 203518 143 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010",
        "081109 203518 145 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010",
        "081109 203518 147 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010"
    ]
    
    # Sample BGL format log lines
    bgl_log_lines = [
        "2005-06-03-15.42.50.675872 R02-M1-N0-C:J12-U11 RAS KERNEL INFO instruction cache parity error corrected",
        "2005-06-03-15.42.50.715022 R02-M1-N0-C:J12-U11 RAS KERNEL FATAL data TLB parity error interrupt",
        "2005-06-03-15.42.50.744646 R02-M1-N0-C:J12-U11 RAS KERNEL FATAL instruction TLB parity error interrupt"
    ]
    
    # Write sample log files
    with open(os.path.join(test_log_dir, "sample_hdfs.log"), "w") as f:
        f.write("\n".join(hdfs_log_lines))
    
    with open(os.path.join(test_log_dir, "sample_bgl.log"), "w") as f:
        f.write("\n".join(bgl_log_lines))
    
    # Test with the sample files
    test_files = [
        os.path.join(test_log_dir, "sample_hdfs.log"),
        os.path.join(test_log_dir, "sample_bgl.log")
    ]
    
    for file_path in test_files:
        try:
            print(f"\nParsing log file: {file_path}")
            print("-" * 50)
            
            # Create a parser
            parser = TextLogParser(file_path)
            
            # Detect format
            format_type = parser.detect_format()
            print(f"Detected format: {format_type}")
            
            # Parse the log file
            parsed_df = parser.parse()
            
            # Display results
            print(f"Successfully parsed {len(parsed_df)} log entries")
            print(f"Columns in parsed data: {list(parsed_df.columns)}")
            print("\nSample of parsed data:")
            print(parsed_df)
            
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
    
    print("\n" + "="*60)
    print("Example 2: Processing a directory of log files")
    print("="*60)
    
    try:
        # Create a directory processor
        processor = LogDirectoryProcessor(test_log_dir)
        
        # Process all logs in the directory
        csv_files = processor.process_all()
        
        # Display results
        print(f"\nProcessed {len(csv_files)} log files:")
        for csv_file in csv_files:
            print(f"  - {csv_file}")
            
            # Read and display the CSV file contents
            df = pd.read_csv(csv_file)
            print(f"    Rows: {len(df)}, Columns: {list(df.columns)}")
            print(f"    First row: {df.iloc[0].to_dict() if not df.empty else '(empty)'}")
            
    except Exception as e:
        print(f"Error processing directory: {e}")
