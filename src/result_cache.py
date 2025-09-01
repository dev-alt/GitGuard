#!/usr/bin/env python3
"""
GitGuard - Result Caching System

Provides caching functionality for scan results to avoid re-scanning unchanged repositories.
Includes cache validation, storage management, and incremental scanning capabilities.
"""

import json
import os
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading

try:
    from .logger import get_logger
    from .settings import get_settings
except ImportError:
    from logger import get_logger
    from settings import get_settings


class ResultCache:
    """Manages caching of scan results for repositories."""
    
    def __init__(self, cache_dir=None):
        """Initialize the result cache system."""
        if cache_dir is None:
            # Create cache directory in the project config
            config_dir = get_settings().config_dir
            cache_dir = config_dir / 'scan_cache'
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache configuration
        self.max_cache_age_days = 7  # Cache expires after 7 days
        self.max_cache_entries = 100  # Maximum number of cached repositories
        
        # Thread lock for concurrent access
        self._lock = threading.Lock()
        
        get_logger().debug(f"Result cache initialized at {self.cache_dir}", "CACHE")
    
    def _get_repo_cache_key(self, repo_full_name: str, scan_config: Dict[str, Any]) -> str:
        """Generate a unique cache key for a repository scan."""
        # Include scan configuration in the key to handle different scan types
        config_hash = hashlib.md5(
            json.dumps(scan_config, sort_keys=True).encode('utf-8')
        ).hexdigest()[:8]
        
        # Clean repo name for filesystem
        repo_key = repo_full_name.replace('/', '_').replace('\\', '_')
        return f"{repo_key}_{config_hash}"
    
    def _get_cache_file_path(self, cache_key: str) -> Path:
        """Get the file path for a cache key."""
        return self.cache_dir / f"{cache_key}.json"
    
    def _get_repo_last_commit_hash(self, repo_obj) -> Optional[str]:
        """Get the last commit hash from a repository object."""
        try:
            # Try to get the latest commit hash
            commits = list(repo_obj.get_commits())
            if commits:
                return commits[0].sha
        except Exception as e:
            get_logger().debug(f"Could not get repo commit hash: {e}", "CACHE")
        return None
    
    def _is_cache_valid(self, cache_data: Dict[str, Any], repo_obj) -> bool:
        """Check if cached data is still valid."""
        try:
            # Check cache age
            cache_date = datetime.fromisoformat(cache_data.get('scan_date', ''))
            max_age = datetime.now() - timedelta(days=self.max_cache_age_days)
            
            if cache_date < max_age:
                get_logger().debug("Cache expired due to age", "CACHE")
                return False
            
            # Check if repository has changed (using last commit hash)
            current_commit = self._get_repo_last_commit_hash(repo_obj)
            cached_commit = cache_data.get('last_commit_hash')
            
            if current_commit and cached_commit and current_commit != cached_commit:
                get_logger().debug(f"Cache invalid - repo changed: {cached_commit[:8]} -> {current_commit[:8]}", "CACHE")
                return False
            
            get_logger().debug("Cache is valid", "CACHE")
            return True
            
        except Exception as e:
            get_logger().debug(f"Cache validation failed: {e}", "CACHE")
            return False
    
    def get_cached_results(self, repo_full_name: str, repo_obj, scan_config: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Get cached scan results if available and valid."""
        with self._lock:
            try:
                cache_key = self._get_repo_cache_key(repo_full_name, scan_config)
                cache_file = self._get_cache_file_path(cache_key)
                
                if not cache_file.exists():
                    get_logger().debug(f"No cache found for {repo_full_name}", "CACHE")
                    return None
                
                # Load cache data
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                # Validate cache
                if not self._is_cache_valid(cache_data, repo_obj):
                    # Remove invalid cache
                    cache_file.unlink()
                    return None
                
                results = cache_data.get('results', [])
                get_logger().info(f"Using cached results for {repo_full_name} ({len(results)} findings)", "CACHE")
                return results
                
            except Exception as e:
                get_logger().error(f"Failed to load cache for {repo_full_name}: {e}", "CACHE", e)
                return None
    
    def store_results(self, repo_full_name: str, repo_obj, scan_config: Dict[str, Any], results: List[Dict[str, Any]]):
        """Store scan results in cache."""
        with self._lock:
            try:
                cache_key = self._get_repo_cache_key(repo_full_name, scan_config)
                cache_file = self._get_cache_file_path(cache_key)
                
                # Prepare cache data
                cache_data = {
                    'repo_full_name': repo_full_name,
                    'scan_date': datetime.now().isoformat(),
                    'scan_config': scan_config,
                    'last_commit_hash': self._get_repo_last_commit_hash(repo_obj),
                    'result_count': len(results),
                    'results': results
                }
                
                # Store cache
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2, ensure_ascii=False)
                
                get_logger().info(f"Cached results for {repo_full_name} ({len(results)} findings)", "CACHE")
                
                # Clean up old cache entries if needed
                self._cleanup_old_cache()
                
            except Exception as e:
                get_logger().error(f"Failed to store cache for {repo_full_name}: {e}", "CACHE", e)
    
    def _cleanup_old_cache(self):
        """Clean up old cache entries to maintain cache size limits."""
        try:
            cache_files = list(self.cache_dir.glob("*.json"))
            
            if len(cache_files) <= self.max_cache_entries:
                return
            
            # Sort by modification time (oldest first)
            cache_files.sort(key=lambda f: f.stat().st_mtime)
            
            # Remove oldest entries
            files_to_remove = len(cache_files) - self.max_cache_entries
            for cache_file in cache_files[:files_to_remove]:
                cache_file.unlink()
                get_logger().debug(f"Removed old cache file: {cache_file.name}", "CACHE")
            
            get_logger().info(f"Cache cleanup: removed {files_to_remove} old entries", "CACHE")
            
        except Exception as e:
            get_logger().error(f"Cache cleanup failed: {e}", "CACHE", e)
    
    def clear_cache_for_repo(self, repo_full_name: str):
        """Clear all cached results for a specific repository."""
        with self._lock:
            try:
                cleared_count = 0
                repo_key = repo_full_name.replace('/', '_').replace('\\', '_')
                
                for cache_file in self.cache_dir.glob(f"{repo_key}_*.json"):
                    cache_file.unlink()
                    cleared_count += 1
                
                get_logger().info(f"Cleared {cleared_count} cache entries for {repo_full_name}", "CACHE")
                
            except Exception as e:
                get_logger().error(f"Failed to clear cache for {repo_full_name}: {e}", "CACHE", e)
    
    def clear_all_cache(self):
        """Clear all cached results."""
        with self._lock:
            try:
                cleared_count = 0
                for cache_file in self.cache_dir.glob("*.json"):
                    cache_file.unlink()
                    cleared_count += 1
                
                get_logger().info(f"Cleared all cache ({cleared_count} entries)", "CACHE")
                
            except Exception as e:
                get_logger().error(f"Failed to clear all cache: {e}", "CACHE", e)
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get information about the cache state."""
        try:
            cache_files = list(self.cache_dir.glob("*.json"))
            total_size = sum(f.stat().st_size for f in cache_files)
            
            # Get cache details
            cache_details = []
            for cache_file in cache_files[:10]:  # Show first 10
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                    
                    cache_details.append({
                        'repo_name': cache_data.get('repo_full_name', 'unknown'),
                        'scan_date': cache_data.get('scan_date', 'unknown'),
                        'result_count': cache_data.get('result_count', 0),
                        'file_size': cache_file.stat().st_size
                    })
                except:
                    continue
            
            return {
                'cache_directory': str(self.cache_dir),
                'total_entries': len(cache_files),
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'max_entries': self.max_cache_entries,
                'max_age_days': self.max_cache_age_days,
                'cache_details': cache_details
            }
            
        except Exception as e:
            get_logger().error(f"Failed to get cache info: {e}", "CACHE", e)
            return {
                'error': str(e),
                'cache_directory': str(self.cache_dir),
                'total_entries': 0,
                'total_size_mb': 0
            }


# Global cache instance
_cache_instance = None

def get_cache():
    """Get the global cache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = ResultCache()
    return _cache_instance


if __name__ == "__main__":
    # Test the caching system
    cache = ResultCache()
    
    # Test cache info
    info = cache.get_cache_info()
    print("Cache Info:")
    for key, value in info.items():
        print(f"  {key}: {value}")