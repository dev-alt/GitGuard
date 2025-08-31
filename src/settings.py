#!/usr/bin/env python3
"""
GitGuard - Settings Management

Handles application settings persistence using JSON configuration files.
Provides secure storage for user preferences and application state.
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path
try:
    from .logger import get_logger
except ImportError:
    from logger import get_logger

class GitGuardSettings:
    """GitGuard settings manager with JSON persistence."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize settings manager."""
        if config_dir is None:
            # Create config directory in project root
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_dir = os.path.join(project_root, 'config')
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.settings_file = self.config_dir / 'gitguard_settings.json'
        self.auth_file = self.config_dir / 'auth_cache.json'  # Separate file for auth data
        
        # Default settings
        self.defaults = {
            'gui': {
                'window_geometry': '1200x800',
                'window_maximized': False,
                'remember_auth': False,
                'auto_load_repos': False,
                'confirm_destructive_actions': True
            },
            'scanning': {
                'max_commits': 100,
                'scan_depth': 'current',
                'exclude_build_folders': True,
                'exclude_dependencies': True,
                'parallel_scanning': True,
                'auto_scan_timeout': 300
            },
            'detection': {
                'entropy_threshold': 4.0,
                'min_secret_length': 8,
                'exclude_test_files': True,
                'custom_patterns_enabled': True
            },
            'export': {
                'default_format': 'csv',
                'include_low_risk': False,
                'include_file_content': True,
                'auto_timestamp_files': True
            },
            'logging': {
                'log_level': 'INFO',
                'max_log_size_mb': 10,
                'keep_logs_days': 30,
                'log_to_console': True
            }
        }
        
        self.settings = {}
        self.load_settings()
    
    def load_settings(self):
        """Load settings from JSON file."""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                self.settings = self._merge_settings(self.defaults.copy(), loaded_settings)
                get_logger().debug(f"Settings loaded from {self.settings_file}", "SETTINGS")
            else:
                self.settings = self.defaults.copy()
                get_logger().info("Using default settings - no settings file found", "SETTINGS")
                
        except Exception as e:
            get_logger().error(f"Failed to load settings: {e}", "SETTINGS", e)
            self.settings = self.defaults.copy()
    
    def save_settings(self):
        """Save current settings to JSON file."""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            get_logger().debug(f"Settings saved to {self.settings_file}", "SETTINGS")
            return True
            
        except Exception as e:
            get_logger().error(f"Failed to save settings: {e}", "SETTINGS", e)
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value using dot notation (e.g., 'gui.window_geometry')."""
        keys = key.split('.')
        value = self.settings
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """Set a setting value using dot notation."""
        keys = key.split('.')
        setting = self.settings
        
        # Navigate to the parent key
        for k in keys[:-1]:
            if k not in setting:
                setting[k] = {}
            setting = setting[k]
        
        # Set the final value
        setting[keys[-1]] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get an entire settings section."""
        return self.settings.get(section, {})
    
    def set_section(self, section: str, values: Dict[str, Any]):
        """Set an entire settings section."""
        if section not in self.settings:
            self.settings[section] = {}
        self.settings[section].update(values)
    
    def reset_to_defaults(self):
        """Reset all settings to default values."""
        self.settings = self.defaults.copy()
        get_logger().info("Settings reset to defaults", "SETTINGS")
    
    def reset_section(self, section: str):
        """Reset a specific section to defaults."""
        if section in self.defaults:
            self.settings[section] = self.defaults[section].copy()
            get_logger().info(f"Settings section '{section}' reset to defaults", "SETTINGS")
    
    def _merge_settings(self, defaults: Dict, loaded: Dict) -> Dict:
        """Recursively merge loaded settings with defaults."""
        for key, value in loaded.items():
            if key in defaults:
                if isinstance(defaults[key], dict) and isinstance(value, dict):
                    defaults[key] = self._merge_settings(defaults[key], value)
                else:
                    defaults[key] = value
            else:
                # Add new keys from loaded settings
                defaults[key] = value
        return defaults
    
    # Authentication cache methods (separate from main settings for security)
    def save_auth_cache(self, auth_data: Dict[str, Any]):
        """Save authentication data to secure cache (if enabled)."""
        if not self.get('gui.remember_auth', False):
            return False
            
        try:
            # Only save non-sensitive data
            cache_data = {
                'username': auth_data.get('username', ''),
                'method': auth_data.get('method', 'token'),
                'last_used': auth_data.get('last_used', ''),
                # NOTE: Never save actual tokens/passwords
            }
            
            with open(self.auth_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            get_logger().debug("Authentication cache saved (no sensitive data)", "SETTINGS")
            return True
            
        except Exception as e:
            get_logger().error(f"Failed to save auth cache: {e}", "SETTINGS", e)
            return False
    
    def load_auth_cache(self) -> Optional[Dict[str, Any]]:
        """Load authentication cache."""
        if not self.get('gui.remember_auth', False):
            return None
            
        try:
            if self.auth_file.exists():
                with open(self.auth_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            get_logger().error(f"Failed to load auth cache: {e}", "SETTINGS", e)
        
        return None
    
    def clear_auth_cache(self):
        """Clear authentication cache."""
        try:
            if self.auth_file.exists():
                self.auth_file.unlink()
                get_logger().info("Authentication cache cleared", "SETTINGS")
        except Exception as e:
            get_logger().error(f"Failed to clear auth cache: {e}", "SETTINGS", e)
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get information about configuration files."""
        return {
            'config_directory': str(self.config_dir),
            'settings_file': str(self.settings_file),
            'settings_exists': self.settings_file.exists(),
            'auth_cache_file': str(self.auth_file),
            'auth_cache_exists': self.auth_file.exists(),
            'settings_count': len(self._flatten_dict(self.settings))
        }
    
    def _flatten_dict(self, d: Dict, prefix: str = '') -> Dict:
        """Flatten nested dictionary for counting."""
        items = {}
        for key, value in d.items():
            new_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                items.update(self._flatten_dict(value, new_key))
            else:
                items[new_key] = value
        return items

# Global settings instance
_settings_instance = None

def get_settings() -> GitGuardSettings:
    """Get the global settings instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = GitGuardSettings()
    return _settings_instance

def init_settings(config_dir: Optional[str] = None) -> GitGuardSettings:
    """Initialize the global settings instance."""
    global _settings_instance
    _settings_instance = GitGuardSettings(config_dir)
    return _settings_instance

if __name__ == "__main__":
    # Test the settings system
    settings = GitGuardSettings()
    
    print("Testing GitGuard Settings System")
    print(f"Config directory: {settings.config_dir}")
    print(f"Settings file: {settings.settings_file}")
    
    # Test getting and setting values
    print(f"\nDefault window geometry: {settings.get('gui.window_geometry')}")
    print(f"Default scan depth: {settings.get('scanning.scan_depth')}")
    
    # Test setting values
    settings.set('gui.window_geometry', '1400x900')
    settings.set('scanning.max_commits', 150)
    
    # Test saving and loading
    if settings.save_settings():
        print("\n✅ Settings saved successfully")
    
    # Display config info
    info = settings.get_config_info()
    print(f"\nConfiguration info:")
    for key, value in info.items():
        print(f"  {key}: {value}")