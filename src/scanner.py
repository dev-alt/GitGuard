#!/usr/bin/env python3
"""
GitGuard - Repository Scanner

Implements repository scanning functionality that analyzes GitHub repositories
for sensitive information using the detection engine.
"""

import os
import tempfile
import shutil
import threading
import time
from typing import Dict, List, Callable, Optional
from git import Repo
from github import Github
try:
    from .detection import SecurityPatternDetector, Finding, RiskLevel
    from .logger import get_logger
except ImportError:
    from detection import SecurityPatternDetector, Finding, RiskLevel
    from logger import get_logger

class ScanProgress:
    """Container for scan progress information."""
    
    def __init__(self):
        self.repos_total = 0
        self.repos_scanned = 0
        self.files_total = 0
        self.files_processed = 0
        self.findings_total = 0
        self.current_repo = ""
        self.current_file = ""
        self.overall_percentage = 0.0
        self.repo_percentage = 0.0
        self.status_message = ""
        self.start_time = 0.0
        self.is_paused = False
        self.is_cancelled = False

class RepositoryScanner:
    """Main repository scanning engine."""
    
    def __init__(self, github_client: Github, progress_callback: Callable = None):
        self.github_client = github_client
        self.detector = SecurityPatternDetector()
        self.progress_callback = progress_callback
        self.progress = ScanProgress()
        self.findings: List[Finding] = []
        self.temp_dir = None
        
    def update_progress(self, **kwargs):
        """Update progress and notify callback."""
        for key, value in kwargs.items():
            if hasattr(self.progress, key):
                setattr(self.progress, key, value)
        
        if self.progress_callback:
            self.progress_callback(self.progress)
    
    def scan_repositories(self, scan_config: Dict) -> List[Finding]:
        """Scan multiple repositories based on configuration."""
        self.findings = []
        self.progress = ScanProgress()
        self.progress.start_time = time.time()
        
        # Setup scan parameters
        repo_names = scan_config.get('repositories', [])
        scan_depth = scan_config.get('scan_depth', 'current')
        max_commits = scan_config.get('max_commits', 100)
        include_files = scan_config.get('include_files', ['*'])
        exclude_patterns = scan_config.get('exclude_patterns', ['node_modules', '.git', '__pycache__'])
        
        self.progress.repos_total = len(repo_names)
        
        # Create temporary directory for cloning
        self.temp_dir = tempfile.mkdtemp(prefix='gitguard_scan_')
        
        try:
            for i, repo_name in enumerate(repo_names):
                if self.progress.is_cancelled:
                    break
                
                self.progress.repos_scanned = i
                self.progress.current_repo = repo_name
                self.update_progress(
                    current_repo=repo_name,
                    status_message=f"Scanning repository {i+1} of {len(repo_names)}: {repo_name}"
                )
                
                # Wait if paused
                while self.progress.is_paused and not self.progress.is_cancelled:
                    time.sleep(0.1)
                
                if self.progress.is_cancelled:
                    break
                
                # Scan individual repository
                try:
                    repo_findings = self._scan_repository(repo_name, scan_depth, max_commits, include_files, exclude_patterns)
                    self.findings.extend(repo_findings)
                    self.progress.findings_total = len(self.findings)
                    
                except Exception as e:
                    # Log error and continue with next repository
                    error_finding = Finding(
                        pattern_name="scan_error",
                        file_path=f"ERROR: {repo_name}",
                        line_number=0,
                        line_content="",
                        matched_text=str(e),
                        risk_level=RiskLevel.MEDIUM,
                        description=f"Failed to scan repository: {str(e)}"
                    )
                    self.findings.append(error_finding)
                
                # Update overall progress
                self.progress.repos_scanned = i + 1
                self.progress.overall_percentage = (i + 1) / len(repo_names) * 100
                self.update_progress()
            
            # Final progress update
            elapsed_time = int(time.time() - self.progress.start_time)
            self.update_progress(
                status_message="Scan completed" if not self.progress.is_cancelled else "Scan cancelled",
                overall_percentage=100.0 if not self.progress.is_cancelled else self.progress.overall_percentage
            )
            
        finally:
            # Cleanup temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        return self.findings
    
    def _scan_repository(self, repo_name: str, scan_depth: str, max_commits: int, include_files: List[str], exclude_patterns: List[str]) -> List[Finding]:
        """Scan a single repository."""
        findings = []
        
        try:
            # Get repository object
            repo_obj = self.github_client.get_repo(repo_name)
            
            if scan_depth == "current":
                # Scan only current state
                findings.extend(self._scan_current_state(repo_obj, include_files, exclude_patterns))
            
            elif scan_depth == "commits":
                # Scan commit history
                findings.extend(self._scan_commit_history(repo_obj, max_commits, include_files, exclude_patterns))
            
            elif scan_depth == "full":
                # Scan both current state and history
                findings.extend(self._scan_current_state(repo_obj, include_files, exclude_patterns))
                findings.extend(self._scan_commit_history(repo_obj, max_commits, include_files, exclude_patterns))
        
        except Exception as e:
            raise Exception(f"Failed to access repository {repo_name}: {str(e)}")
        
        return findings
    
    def _scan_current_state(self, repo_obj, include_files: List[str], exclude_patterns: List[str]) -> List[Finding]:
        """Scan current repository state with optimized batch processing."""
        findings = []
        
        try:
            # Get repository contents
            contents = repo_obj.get_contents("")
            files_to_scan = []
            
            # Collect all files recursively with better filtering
            self._collect_files_optimized(repo_obj, contents, files_to_scan, exclude_patterns)
            
            # Prioritize high-risk files
            files_to_scan = self._prioritize_files(files_to_scan)
            
            self.progress.files_total += len(files_to_scan)
            
            # Process files in batches for better performance
            batch_size = min(10, len(files_to_scan))  # Process up to 10 files concurrently
            for i in range(0, len(files_to_scan), batch_size):
                if self.progress.is_cancelled:
                    break
                
                batch = files_to_scan[i:i + batch_size]
                batch_findings = self._process_file_batch(batch, repo_obj.name)
                findings.extend(batch_findings)
                
                # Update progress for the entire batch
                self.progress.files_processed += len(batch)
                self.progress.repo_percentage = (i + len(batch)) / len(files_to_scan) * 100
                
                # Wait if paused
                while self.progress.is_paused and not self.progress.is_cancelled:
                    time.sleep(0.1)
                
                if batch:  # Update progress with last file in batch
                    self.update_progress(
                        current_file=batch[-1].path,
                        status_message=f"Processed batch: {len(batch)} files"
                    )
        
        except Exception as e:
            raise Exception(f"Failed to scan current state: {str(e)}")
        
        return findings
    
    def _collect_files_optimized(self, repo_obj, contents, files_to_scan: List, exclude_patterns: List[str]):
        """Optimized file collection with better filtering."""
        queue = list(contents) if isinstance(contents, list) else [contents]
        
        while queue:
            if self.progress.is_cancelled:
                break
                
            content = queue.pop(0)
            
            # Skip if path matches exclude patterns
            if self._should_exclude_path(content.path, exclude_patterns):
                continue
            
            if content.type == "file":
                # Pre-filter by file size and type for better performance
                if self._is_scannable_file(content):
                    files_to_scan.append(content)
            elif content.type == "dir":
                try:
                    # Add directory contents to queue
                    dir_contents = repo_obj.get_contents(content.path)
                    if isinstance(dir_contents, list):
                        queue.extend(dir_contents)
                    else:
                        queue.append(dir_contents)
                except:
                    # Skip directories we can't access
                    continue
    
    def _should_exclude_path(self, path: str, exclude_patterns: List[str]) -> bool:
        """Check if path should be excluded with optimized patterns."""
        # Common exclusions for performance
        performance_excludes = [
            'node_modules/', '.git/', 'dist/', 'build/', 'target/', 'bin/', 'obj/',
            '__pycache__/', '.venv/', 'venv/', '.pytest_cache/', '.mypy_cache/',
            'vendor/', '.gradle/', '.m2/', 'package-lock.json', 'yarn.lock',
            '.min.js', '.min.css', '.bundle.js', '.compiled.'
        ]
        
        # Quick check for common performance exclusions
        path_lower = path.lower()
        for exclude in performance_excludes:
            if exclude in path_lower:
                return True
        
        # Check custom exclude patterns
        for pattern in exclude_patterns:
            if pattern in path:
                return True
        
        return False
    
    def _is_scannable_file(self, content_file) -> bool:
        """Check if file is worth scanning."""
        # Skip very large files (>1MB)
        if content_file.size > 1024 * 1024:
            return False
        
        # Skip binary file extensions
        binary_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.zip', '.tar', '.gz', 
            '.rar', '.7z', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.woff', '.woff2',
            '.ttf', '.eot', '.otf'
        }
        
        file_ext = '.' + content_file.path.split('.')[-1].lower() if '.' in content_file.path else ''
        if file_ext in binary_extensions:
            return False
        
        # Skip empty files
        if content_file.size == 0:
            return False
        
        return True
    
    def _prioritize_files(self, files_to_scan: List) -> List:
        """Prioritize files by security relevance."""
        high_priority = []
        medium_priority = []
        low_priority = []
        
        high_risk_patterns = ['.env', 'config', 'secret', 'key', 'password', 'auth', 'cred']
        medium_risk_extensions = {'.json', '.yaml', '.yml', '.xml', '.ini', '.conf', '.cfg'}
        
        for file_content in files_to_scan:
            file_path = file_content.path.lower()
            
            # High priority: Files likely to contain secrets
            if any(pattern in file_path for pattern in high_risk_patterns):
                high_priority.append(file_content)
            # Medium priority: Configuration-like files
            elif any(file_path.endswith(ext) for ext in medium_risk_extensions):
                medium_priority.append(file_content)
            else:
                low_priority.append(file_content)
        
        # Return prioritized list
        return high_priority + medium_priority + low_priority
    
    def _process_file_batch(self, batch: List, repo_name: str) -> List[Finding]:
        """Process a batch of files efficiently."""
        findings = []
        
        for content_file in batch:
            if self.progress.is_cancelled:
                break
                
            try:
                # Decode file content
                if content_file.encoding == 'base64':
                    import base64
                    file_content = base64.b64decode(content_file.content).decode('utf-8', errors='ignore')
                else:
                    file_content = content_file.decoded_content.decode('utf-8', errors='ignore')
                
                # Skip files that are too large after decoding
                if len(file_content) > 500000:  # 500KB of text
                    continue
                
                # Scan file content
                file_findings = self.detector.scan_file(content_file.path, file_content)
                
                # Log security findings
                for finding in file_findings:
                    get_logger().log_security_finding(
                        repo_name, finding.file_path, finding.pattern_name, finding.risk_level.value
                    )
                
                findings.extend(file_findings)
                
            except Exception as e:
                # Skip files that can't be processed
                get_logger().debug(f"Skipped file {content_file.path}: {e}", "SCAN")
                continue
        
        return findings
    
    def _collect_files(self, repo_obj, contents, files_list: List, exclude_patterns: List[str]):
        """Recursively collect all files in repository."""
        for content_file in contents:
            # Skip excluded patterns
            if any(pattern in content_file.path for pattern in exclude_patterns):
                continue
            
            if content_file.type == "dir":
                # Recursively get directory contents
                try:
                    subdir_contents = repo_obj.get_contents(content_file.path)
                    self._collect_files(repo_obj, subdir_contents, files_list, exclude_patterns)
                except:
                    continue
            else:
                files_list.append(content_file)
    
    def _scan_commit_history(self, repo_obj, max_commits: int, include_files: List[str], exclude_patterns: List[str]) -> List[Finding]:
        """Scan repository commit history."""
        findings = []
        
        try:
            # Clone repository locally for commit history access
            repo_clone_path = os.path.join(self.temp_dir, repo_obj.name)
            
            self.update_progress(status_message=f"Cloning repository: {repo_obj.name}")
            
            # Clone repository
            git_repo = Repo.clone_from(repo_obj.clone_url, repo_clone_path, depth=max_commits)
            
            # Get commits
            commits = list(git_repo.iter_commits(max_count=max_commits))
            
            for i, commit in enumerate(commits):
                if self.progress.is_cancelled:
                    break
                
                # Wait if paused
                while self.progress.is_paused and not self.progress.is_cancelled:
                    time.sleep(0.1)
                
                if self.progress.is_cancelled:
                    break
                
                commit_hash = commit.hexsha
                commit_date = commit.committed_datetime.strftime("%Y-%m-%d %H:%M:%S")
                
                self.update_progress(
                    status_message=f"Scanning commit {i+1}/{len(commits)}: {commit_hash[:8]}"
                )
                
                # Scan changed files in commit
                try:
                    for item in commit.tree.traverse():
                        if item.type != 'blob':  # Skip non-file items
                            continue
                        
                        file_path = item.path
                        
                        # Skip excluded patterns
                        if any(pattern in file_path for pattern in exclude_patterns):
                            continue
                        
                        try:
                            file_content = item.data_stream.read().decode('utf-8', errors='ignore')
                            file_findings = self.detector.scan_file(file_path, file_content, commit_hash, commit_date)
                            # Log security findings
                            for finding in file_findings:
                                get_logger().log_security_finding(
                                    repo_name, finding.file_path, finding.pattern_name, finding.risk_level.value
                                )
                            findings.extend(file_findings)
                        except:
                            continue
                            
                except Exception as e:
                    continue
        
        except Exception as e:
            raise Exception(f"Failed to scan commit history: {str(e)}")
        
        return findings
    
    def pause_scan(self):
        """Pause the current scan."""
        self.progress.is_paused = True
        self.update_progress(status_message="Scan paused")
    
    def resume_scan(self):
        """Resume the paused scan."""
        self.progress.is_paused = False
        self.update_progress(status_message="Scan resumed")
    
    def cancel_scan(self):
        """Cancel the current scan."""
        self.progress.is_cancelled = True
        self.update_progress(status_message="Cancelling scan...")
    
    def get_scan_summary(self) -> Dict:
        """Get summary of scan results."""
        if not self.findings:
            return {}
        
        summary = {
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]),
            "high": len([f for f in self.findings if f.risk_level == RiskLevel.HIGH]),
            "medium": len([f for f in self.findings if f.risk_level == RiskLevel.MEDIUM]),
            "low": len([f for f in self.findings if f.risk_level == RiskLevel.LOW]),
            "repositories_scanned": self.progress.repos_scanned,
            "files_processed": self.progress.files_processed,
            "scan_duration": int(time.time() - self.progress.start_time) if self.progress.start_time else 0
        }
        
        return summary

def run_scan_async(github_client: Github, scan_config: Dict, progress_callback: Callable = None, completion_callback: Callable = None):
    """Run scan in background thread."""
    def scan_thread():
        try:
            scanner = RepositoryScanner(github_client, progress_callback)
            findings = scanner.scan_repositories(scan_config)
            
            if completion_callback:
                completion_callback(findings, scanner.get_scan_summary())
        
        except Exception as e:
            if completion_callback:
                completion_callback([], {"error": str(e)})
    
    thread = threading.Thread(target=scan_thread, daemon=True)
    thread.start()
    return thread

if __name__ == "__main__":
    # Example usage
    from github import Github
    
    # This would normally use real GitHub credentials
    # github_client = Github("your_token_here")
    
    print("GitGuard Repository Scanner")
    print("Module loaded successfully")
    
    detector = SecurityPatternDetector()
    stats = detector.get_pattern_statistics()
    print(f"Detection patterns available: {stats['total_patterns']}")
    print(f"Risk levels: Critical={stats['critical']}, High={stats['high']}, Medium={stats['medium']}, Low={stats['low']}")