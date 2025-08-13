"""
Log Processing Interface for Anomaly Detection System.

This module provides a unified interface and data model for working with logs from
various sources and formats. It serves as the core architectural component that
enables consistent processing of logs regardless of their origin or structure.

Key Components:
--------------
1. StandardLog: A unified data model that represents any log entry regardless
   of its original format, providing a consistent structure for processing.

2. LogReader: An abstract interface that defines the contract for all log readers,
   ensuring that different implementations can be used interchangeably.

3. LogReaderFactory: Factory class that creates appropriate LogReader instances
   based on file type and content analysis, enabling automatic format detection.

4. Adapter Classes: Bridge between specific log readers/parsers and the unified
   LogReader interface, implementing the Adapter design pattern.

Design Patterns:
--------------
- Abstract Factory: LogReaderFactory creates appropriate reader instances
- Adapter: CSVLogReaderAdapter and TextLogReaderAdapter adapt specific implementations
- Iterator: to_standard_logs() returns iterators for memory-efficient processing
- Strategy: Different reader implementations provide format-specific strategies

Usage Examples:
-------------
1. Using the factory for automatic format detection:
   ```python
   reader = LogReaderFactory.create_reader('/path/to/logs/system.log')
   df = reader.read()
   for log in reader.to_standard_logs():
       process_log(log)
   ```

2. Working with a specific reader directly:
   ```python
   reader = CSVLogReaderAdapter('/path/to/logs/data.csv', format_type='BGL')
   for log in reader.to_standard_logs():
       print(f"{log.timestamp}: {log.level} - {log.message}")
   ```

3. Processing logs with the StandardLog model:
   ```python
   log = StandardLog(
       message="Connection failed",
       timestamp=datetime.now(),
       level="ERROR",
       source="database",
       raw_content="2023-07-18 15:31:23 ERROR Connection failed"
   )
   ```
"""

import os
import pandas as pd
from typing import Optional, List, Dict, Any, Iterator, Union
from datetime import datetime
from pathlib import Path
from abc import ABC, abstractmethod
import json

from core.standard_log import StandardLog
from core.interfaces import LogReader


class LogReaderFactory:
    """
    Factory for creating appropriate log readers based on file type.
    
    This factory class implements the Factory Method design pattern to dynamically
    select and create the appropriate LogReader implementation for a given log file.
    It provides a unified entry point for working with logs of different formats
    without requiring client code to know implementation details.
    
    The factory analyzes the provided file (extension, content patterns, etc.) and 
    returns the most suitable reader instance. This allows the system to automatically
    handle different log formats through a consistent interface.
    
    Use Cases:
    1. Processing mixed log formats through a uniform API
    2. Working with logs without knowing their specific format
    3. Adding support for new log formats without changing client code
    4. Simplifying higher-level log processing workflows
    """
    
    @staticmethod
    def create_reader(file_path: str) -> LogReader:
        """
        Create an appropriate log reader for the given file.
        
        This method analyzes the provided file and returns the most suitable
        LogReader implementation. The selection is based on multiple factors:
        1. File extension (.csv, .log, .txt, etc.)
        2. Content analysis for format detection
        3. Fallback to a default reader if needed
        
        Parameters
        ----------
        file_path : str
            Path to the log file. Should be an absolute path to ensure consistent
            behavior across different execution environments.
            
        Returns
        -------
        LogReader
            An appropriate concrete LogReader implementation for the given file.
            
        Raises
        ------
        FileNotFoundError
            If the specified file does not exist
        ValueError
            If no suitable reader is found for the file format
        IOError
            If there's an issue reading or analyzing the file
            
        Examples
        --------
        >>> reader = LogReaderFactory.create_reader('/path/to/logs/system.log')
        >>> df = reader.read()
        >>> for log in reader.to_standard_logs():
        ...     print(log.message)
        """
        # Import the readers here to avoid circular imports
        from log_ingestion import CSVLogReader
        from log_parser import TextLogParser
        
        # Check if the file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Determine the file extension
        _, ext = os.path.splitext(file_path)
        
        # Create an appropriate reader based on file extension
        if ext.lower() == '.csv':
            # Wrap the CSVLogReader to match the LogReader interface
            return CSVLogReaderAdapter(file_path)
        elif ext.lower() in ['.log', '.txt', '.out', '.err']:
            # Wrap the TextLogParser to match the LogReader interface
            return TextLogReaderAdapter(file_path)
        else:
            # Try to guess based on content
            with open(file_path, 'rb') as f:
                header = f.read(4096).decode('utf-8', errors='ignore')
                
                # Check if it looks like a CSV
                if ',' in header and '\n' in header:
                    first_line = header.split('\n')[0]
                    if first_line.count(',') >= 2:
                        return CSVLogReaderAdapter(file_path)
                
                # Default to text log parser
                return TextLogReaderAdapter(file_path)


class CSVLogReaderAdapter(LogReader):
    """
    Adapter for CSVLogReader to match the LogReader interface.
    
    This adapter class implements the Adapter design pattern to bridge between
    the CSVLogReader from log_ingestion.py and the unified LogReader interface.
    It allows CSV-based log readers to be used interchangeably with other LogReader
    implementations through a common interface.
    
    The adapter delegates most operations to the wrapped CSVLogReader instance
    while providing the interface expected by the unified log processing framework.
    This maintains separation of concerns between the CSV-specific logic and the
    unified processing interface.
    
    Key responsibilities:
    1. Adapting CSVLogReader to the LogReader interface
    2. Delegating operations to the wrapped CSVLogReader
    3. Converting between the CSVLogReader's data model and StandardLog
    """
    
    def __init__(self, file_path: str, format_type: Optional[str] = None):
        """
        Initialize the CSVLogReaderAdapter.
        
        Creates a new adapter instance that wraps a CSVLogReader for the specified
        log file. The adapter provides the LogReader interface while delegating
        actual processing to the CSVLogReader implementation.
        
        Parameters
        ----------
        file_path : str
            Path to the CSV log file. Should be an absolute path to ensure
            consistent behavior across different execution environments.
            
        format_type : Optional[str], default=None
            Type of log format (e.g., 'BGL', 'HDFS', 'Thunderbird'). If None,
            the format will be auto-detected based on the file's content and
            column structure.
        """
        from log_ingestion import CSVLogReader
        self.reader = CSVLogReader(file_path, format_type)
    
    def read(self) -> pd.DataFrame:
        """
        Read logs into a pandas DataFrame.
        
        Returns
        -------
        pd.DataFrame
            DataFrame containing the log data
        """
        return self.reader.read()
    
    def to_standard_logs(self) -> Iterator[StandardLog]:
        """
        Convert CSV logs to StandardLog objects.
        
        This method will be implemented in the CSVLogReader class.
        For now, it provides a basic implementation.
        
        Returns
        -------
        Iterator[StandardLog]
            Iterator of StandardLog objects
        """
        df = self.read()
        
        for _, row in df.iterrows():
            # Convert the row to a dictionary
            row_dict = row.to_dict()
            
            # Extract common fields
            message = row_dict.get('Content', row_dict.get('message', ''))
            raw_content = str(row)
            timestamp = None
            level = row_dict.get('Level', row_dict.get('level', None))
            source = row_dict.get('Component', row_dict.get('source', None))
            log_id = str(row_dict.get('LineId', ''))
            
            log = StandardLog(
                message=message,
                raw_content=raw_content,
                timestamp=timestamp,
                level=level,
                source=source,
                log_id=log_id,
                metadata=row_dict
            )
            
            yield log
    
    def can_handle(self, file_path: str) -> bool:
        """
        Check if this reader can handle the given file.
        
        Parameters
        ----------
        file_path : str
            Path to the file to check
            
        Returns
        -------
        bool
            True if this reader can handle the file, False otherwise
        """
        _, ext = os.path.splitext(file_path)
        return ext.lower() == '.csv'


class TextLogReaderAdapter(LogReader):
    """
    Adapter for TextLogParser to match the LogReader interface.
    
    This adapter class bridges between the TextLogParser from log_parser.py
    and the unified LogReader interface. It allows text-based log parsers
    to be used within the unified log processing framework alongside other
    log reader implementations.
    
    The adapter translates between the TextLogParser's specific API and the
    common LogReader interface, ensuring that unstructured text logs can be
    processed using the same high-level code as structured logs.
    
    Key responsibilities:
    1. Adapting TextLogParser to the LogReader interface
    2. Converting unstructured text logs into StandardLog objects
    3. Providing format detection and parsing for text-based logs
    """
    
    def __init__(self, file_path: str, format_name: Optional[str] = None):
        """
        Initialize the TextLogReaderAdapter.
        
        Creates a new adapter instance that wraps a TextLogParser for the specified
        text log file. The adapter conforms to the LogReader interface while
        delegating the actual parsing to the TextLogParser implementation.
        
        Parameters
        ----------
        file_path : str
            Path to the text log file. Should be an absolute path to ensure
            consistent behavior across different execution environments.
            
        format_name : Optional[str], default=None
            Name of the log format (e.g., 'apache_access', 'syslog', 'bgl').
            If None, the format will be auto-detected using pattern matching
            against the log content.
        """
        from log_parser import TextLogParser
        self.parser = TextLogParser(file_path, format_name)
    
    def read(self) -> pd.DataFrame:
        """
        Read logs into a pandas DataFrame.
        
        Returns
        -------
        pd.DataFrame
            DataFrame containing the log data
        """
        return self.parser.parse()
    
    def to_standard_logs(self) -> Iterator[StandardLog]:
        """
        Convert text logs to StandardLog objects.
        
        Returns
        -------
        Iterator[StandardLog]
            Iterator of StandardLog objects
        """
        df = self.read()
        
        for _, row in df.iterrows():
            # Convert the row to a dictionary
            row_dict = row.to_dict()
            
            # Extract common fields
            message = row_dict.get('message', '')
            raw_content = row_dict.get('raw_content', str(row))
            timestamp = row_dict.get('timestamp', None)
            level = row_dict.get('level', None)
            source = row_dict.get('source', None)
            log_id = str(row_dict.get('line_num', ''))
            parsed = row_dict.get('parsed', True)
            
            log = StandardLog(
                message=message,
                raw_content=raw_content,
                timestamp=timestamp,
                level=level,
                source=source,
                log_id=log_id,
                parsed=parsed,
                metadata=row_dict
            )
            
            yield log
    
    def can_handle(self, file_path: str) -> bool:
        """
        Check if this reader can handle the given file.
        
        Parameters
        ----------
        file_path : str
            Path to the file to check
            
        Returns
        -------
        bool
            True if this reader can handle the file, False otherwise
        """
        _, ext = os.path.splitext(file_path)
        return ext.lower() in ['.log', '.txt', '.out', '.err']


# Example usage
if __name__ == "__main__":
    import os
    import sys
    
    print("\n" + "="*60)
    print("Example: Using the unified log processing interface")
    print("="*60)
    
    # Create a sample directory for testing
    test_dir = "Data/test_integrated"
    os.makedirs(test_dir, exist_ok=True)
    
    # Create sample files for testing
    sample_files = {
        "sample_csv.csv": """LineId,Timestamp,Component,Level,Content
1,2023-07-18 15:30:45,Server,INFO,Application started successfully
2,2023-07-18 15:31:50,Database,WARNING,Slow query detected
3,2023-07-18 15:32:30,Network,ERROR,Connection timeout""",
        
        "sample_hdfs.log": """081109 203518 143 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010
081109 203518 145 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010
081109 203518 147 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010""",
        
        "sample_bgl.log": """2005-06-03-15.42.50.675872 R02-M1-N0-C:J12-U11 RAS KERNEL INFO instruction cache parity error corrected
2005-06-03-15.42.50.715022 R02-M1-N0-C:J12-U11 RAS KERNEL FATAL data TLB parity error interrupt
2005-06-03-15.42.50.744646 R02-M1-N0-C:J12-U11 RAS KERNEL FATAL instruction TLB parity error interrupt"""
    }
    
    # Write sample files
    for filename, content in sample_files.items():
        with open(os.path.join(test_dir, filename), "w") as f:
            f.write(content)
    
    # Process each sample file using the unified interface
    for filename in sample_files.keys():
        file_path = os.path.join(test_dir, filename)
        
        print(f"\n{'='*50}")
        print(f"Processing file: {filename}")
        print(f"{'='*50}")
        
        try:
            # Create a reader using the factory
            reader = LogReaderFactory.create_reader(file_path)
            print(f"Selected reader type: {type(reader).__name__}")
            
            # Read the logs
            df = reader.read()
            print(f"\nRead {len(df)} log entries")
            print(f"Columns: {list(df.columns)}")
            
            # Display sample data
            print("\nSample data:")
            print(df.head(2))
            
            # Convert to StandardLog objects
            print("\nConverting to StandardLog format:")
            for i, log in enumerate(reader.to_standard_logs()):
                print(f"\nStandardLog {i+1}:")
                print(f"  Message: {log.message}")
                print(f"  Level: {log.level}")
                print(f"  Source: {log.source}")
                
                # Only show the first 2 logs
                if i >= 1:
                    break
            
        except Exception as e:
            print(f"Error processing {filename}: {e}")
    
    # Example of working with multiple files
    print(f"\n{'='*60}")
    print("Example: Processing multiple files with different formats")
    print(f"{'='*60}")
    
    try:
        # Process all files in the directory
        all_logs = []
        
        for filename in sample_files.keys():
            file_path = os.path.join(test_dir, filename)
            reader = LogReaderFactory.create_reader(file_path)
            
            # Convert all logs to StandardLog format
            file_logs = list(reader.to_standard_logs())
            all_logs.extend(file_logs)
            
            print(f"Added {len(file_logs)} logs from {filename}")
        
        # Show summary of all collected logs
        print(f"\nCollected {len(all_logs)} logs from all files")
        
        # Example of working with the unified logs
        print("\nLog levels found:")
        levels = {}
        for log in all_logs:
            if log.level:
                levels[log.level] = levels.get(log.level, 0) + 1
        
        for level, count in levels.items():
            print(f"  {level}: {count} logs")
            
    except Exception as e:
        print(f"Error in multi-file processing: {e}")
