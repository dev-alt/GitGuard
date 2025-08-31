#!/usr/bin/env python3
"""
GitGuard - Logging System

Provides comprehensive logging functionality for GitGuard application
including error tracking, operation logging, and debug information.
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
import traceback

class GitGuardLogger:
    """GitGuard logging system with file and console output."""
    
    def __init__(self, log_dir=None):
        """Initialize the logging system."""
        if log_dir is None:
            # Create logs directory in the project root
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_dir = os.path.join(project_root, 'logs')
        
        # Create logs directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        self.log_dir = log_dir
        self.setup_logging()
    
    def setup_logging(self):
        """Set up logging configuration."""
        # Create main logger
        self.logger = logging.getLogger('gitguard')
        self.logger.setLevel(logging.DEBUG)
        
        # Avoid duplicate handlers
        if self.logger.handlers:
            return
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        simple_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Main application log file (rotating)
        main_log_file = os.path.join(self.log_dir, 'gitguard.log')
        file_handler = RotatingFileHandler(
            main_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(file_handler)
        
        # Error log file (errors and critical only)
        error_log_file = os.path.join(self.log_dir, 'gitguard_errors.log')
        error_handler = RotatingFileHandler(
            error_log_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(error_handler)
        
        # Console handler (info and above)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(simple_formatter)
        self.logger.addHandler(console_handler)
        
        # Create session log file
        self._create_session_log()
    
    def _create_session_log(self):
        """Create a session-specific log file."""
        session_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        session_log_file = os.path.join(self.log_dir, f'session_{session_time}.log')
        
        session_handler = logging.FileHandler(session_log_file)
        session_handler.setLevel(logging.DEBUG)
        session_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(session_handler)
        
        self.session_log_file = session_log_file
    
    def info(self, message, component=None):
        """Log info message."""
        if component:
            message = f"[{component}] {message}"
        self.logger.info(message)
    
    def warning(self, message, component=None):
        """Log warning message."""
        if component:
            message = f"[{component}] {message}"
        self.logger.warning(message)
    
    def error(self, message, component=None, exception=None):
        """Log error message with optional exception details."""
        if component:
            message = f"[{component}] {message}"
        
        if exception:
            message += f" | Exception: {str(exception)}"
            self.logger.error(message)
            self.logger.debug("Exception traceback:", exc_info=True)
        else:
            self.logger.error(message)
    
    def critical(self, message, component=None, exception=None):
        """Log critical message with optional exception details."""
        if component:
            message = f"[{component}] {message}"
        
        if exception:
            message += f" | Exception: {str(exception)}"
            self.logger.critical(message)
            self.logger.debug("Exception traceback:", exc_info=True)
        else:
            self.logger.critical(message)
    
    def debug(self, message, component=None):
        """Log debug message."""
        if component:
            message = f"[{component}] {message}"
        self.logger.debug(message)
    
    def log_authentication_attempt(self, method, username=None, success=False):
        """Log authentication attempts."""
        user_info = f" for user '{username}'" if username else ""
        status = "SUCCESS" if success else "FAILED"
        self.info(f"Authentication {status} using {method}{user_info}", "AUTH")
    
    def log_repository_operation(self, operation, repo_count=None, success=False):
        """Log repository operations."""
        count_info = f" ({repo_count} repos)" if repo_count else ""
        status = "SUCCESS" if success else "FAILED"
        self.info(f"Repository {operation} {status}{count_info}", "REPO")
    
    def log_scan_operation(self, operation, details=None, success=False):
        """Log scanning operations."""
        status = "SUCCESS" if success else "FAILED"
        detail_info = f" - {details}" if details else ""
        self.info(f"Scan {operation} {status}{detail_info}", "SCAN")
    
    def log_security_finding(self, repo_name, file_path, pattern_type, risk_level):
        """Log security findings."""
        self.info(f"Security finding: {risk_level} risk {pattern_type} in {repo_name}/{file_path}", "SECURITY")
    
    def log_performance_metric(self, operation, duration_seconds, additional_info=None):
        """Log performance metrics."""
        info = f" - {additional_info}" if additional_info else ""
        self.debug(f"Performance: {operation} took {duration_seconds:.2f}s{info}", "PERFORMANCE")
    
    def log_application_start(self):
        """Log application startup."""
        self.info("=" * 60, "APP")
        self.info("GitGuard - GitHub Security Scanner Starting", "APP")
        self.info(f"Session log: {self.session_log_file}", "APP")
        self.info("=" * 60, "APP")
    
    def log_application_stop(self):
        """Log application shutdown."""
        self.info("GitGuard application shutting down", "APP")
        self.info("=" * 60, "APP")
    
    def log_exception(self, exception, component=None, context=None):
        """Log unhandled exceptions with full traceback."""
        context_info = f" in {context}" if context else ""
        self.error(f"Unhandled exception{context_info}", component, exception)
        
        # Also log full traceback
        tb_lines = traceback.format_exception(type(exception), exception, exception.__traceback__)
        tb_str = ''.join(tb_lines)
        self.debug(f"Full traceback:\n{tb_str}", component)
    
    def get_log_files_info(self):
        """Get information about current log files."""
        info = {
            'log_directory': self.log_dir,
            'session_log': self.session_log_file,
            'main_log': os.path.join(self.log_dir, 'gitguard.log'),
            'error_log': os.path.join(self.log_dir, 'gitguard_errors.log'),
            'log_files': []
        }
        
        try:
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log'):
                    filepath = os.path.join(self.log_dir, filename)
                    stat = os.stat(filepath)
                    info['log_files'].append({
                        'name': filename,
                        'path': filepath,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
        except Exception as e:
            self.error(f"Failed to get log files info: {e}", "LOGGER")
        
        return info

# Global logger instance
_logger_instance = None

def get_logger():
    """Get the global logger instance."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = GitGuardLogger()
    return _logger_instance

def init_logging(log_dir=None):
    """Initialize the logging system."""
    global _logger_instance
    _logger_instance = GitGuardLogger(log_dir)
    return _logger_instance

# Convenience functions
def log_info(message, component=None):
    """Log info message using global logger."""
    get_logger().info(message, component)

def log_warning(message, component=None):
    """Log warning message using global logger."""
    get_logger().warning(message, component)

def log_error(message, component=None, exception=None):
    """Log error message using global logger."""
    get_logger().error(message, component, exception)

def log_critical(message, component=None, exception=None):
    """Log critical message using global logger."""
    get_logger().critical(message, component, exception)

def log_debug(message, component=None):
    """Log debug message using global logger."""
    get_logger().debug(message, component)

if __name__ == "__main__":
    # Test the logging system
    logger = GitGuardLogger()
    
    logger.log_application_start()
    logger.info("Testing GitGuard logging system", "TEST")
    logger.warning("This is a test warning", "TEST")
    logger.error("This is a test error", "TEST")
    logger.debug("This is a test debug message", "TEST")
    
    # Test exception logging
    try:
        raise ValueError("Test exception for logging")
    except Exception as e:
        logger.log_exception(e, "TEST", "exception logging test")
    
    logger.log_authentication_attempt("token", "testuser", True)
    logger.log_repository_operation("loading", 5, True)
    logger.log_scan_operation("complete", "5 repos, 23 files", True)
    logger.log_security_finding("test-repo", "config.py", "API_KEY", "HIGH")
    logger.log_performance_metric("repository_scan", 45.2, "5 repositories")
    
    print("\nLog files info:")
    info = logger.get_log_files_info()
    print(f"Log directory: {info['log_directory']}")
    print(f"Session log: {info['session_log']}")
    for log_file in info['log_files']:
        print(f"- {log_file['name']}: {log_file['size']} bytes, modified {log_file['modified']}")
    
    logger.log_application_stop()