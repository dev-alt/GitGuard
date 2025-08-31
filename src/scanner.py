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
        """Scan current repository state."""
        findings = []
        
        try:
            # Get repository contents
            contents = repo_obj.get_contents("")
            files_to_scan = []
            
            # Collect all files recursively
            self._collect_files(repo_obj, contents, files_to_scan, exclude_patterns)
            
            self.progress.files_total += len(files_to_scan)
            
            for i, content_file in enumerate(files_to_scan):
                if self.progress.is_cancelled:
                    break
                
                # Wait if paused
                while self.progress.is_paused and not self.progress.is_cancelled:
                    time.sleep(0.1)
                
                if self.progress.is_cancelled:
                    break
                
                self.progress.current_file = content_file.path
                self.progress.files_processed += 1
                self.progress.repo_percentage = (i + 1) / len(files_to_scan) * 100
                
                self.update_progress(
                    current_file=content_file.path,
                    status_message=f"Scanning file: {content_file.path}"
                )
                
                # Skip binary files and large files
                if content_file.size > 1024 * 1024:  # Skip files larger than 1MB
                    continue
                
                try:
                    # Decode file content
                    if content_file.encoding == 'base64':
                        import base64
                        file_content = base64.b64decode(content_file.content).decode('utf-8', errors='ignore')
                    else:
                        file_content = content_file.decoded_content.decode('utf-8', errors='ignore')
                    
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
                    continue
        
        except Exception as e:
            raise Exception(f"Failed to scan current state: {str(e)}")
        
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