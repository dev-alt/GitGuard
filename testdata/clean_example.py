"""
GitGuard Test Data - Clean Example

This file contains NO sensitive data patterns and should
generate zero security findings when scanned by GitGuard.
"""

import os
import json
from typing import List, Dict, Any


class ExampleApplication:
    """An example application class with no security issues."""
    
    def __init__(self, config_path: str):
        """Initialize with configuration file path."""
        self.config_path = config_path
        self.config = {}
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a configuration setting."""
        return self.config.get(key, default)
    
    def process_data(self, data: List[Dict]) -> List[Dict]:
        """Process a list of data records."""
        processed = []
        
        for record in data:
            # Simple data transformation
            processed_record = {
                'id': record.get('id'),
                'name': record.get('name', '').upper(),
                'active': record.get('active', False)
            }
            processed.append(processed_record)
        
        return processed


def main():
    """Main function with clean, secure code."""
    app = ExampleApplication('config.json')
    
    # Sample data processing
    sample_data = [
        {'id': 1, 'name': 'Alice', 'active': True},
        {'id': 2, 'name': 'Bob', 'active': False}
    ]
    
    processed = app.process_data(sample_data)
    print(f"Processed {len(processed)} records")


if __name__ == "__main__":
    main()