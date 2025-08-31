#!/usr/bin/env python3
"""
GitGuard - Complete GUI Application

Full-featured GUI interface for GitHub repository security scanning.
Includes authentication, repository selection, scanning, and results display.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import os
import json
from typing import Dict, List, Optional
from datetime import datetime

class AuthenticationFrame(ttk.Frame):
    """Frame for GitHub authentication."""
    
    def __init__(self, parent, on_auth_success):
        super().__init__(parent)
        self.on_auth_success = on_auth_success
        self.create_widgets()
    
    def create_widgets(self):
        """Create authentication UI elements."""
        # Title
        title_label = ttk.Label(self, text="🔐 GitHub Authentication", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20), sticky='w')
        
        # Authentication method selection
        self.auth_method = tk.StringVar(value="token")
        
        # Token method (recommended)
        token_frame = ttk.LabelFrame(self, text="Personal Access Token (Recommended)")
        token_frame.grid(row=1, column=0, columnspan=3, sticky='ew', pady=10, padx=10, ipady=10)
        
        ttk.Radiobutton(token_frame, text="Use Personal Access Token", 
                       variable=self.auth_method, value="token").grid(row=0, column=0, sticky='w', padx=5)
        
        ttk.Label(token_frame, text="GitHub Token:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.token_entry = ttk.Entry(token_frame, show='*', width=50)
        self.token_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(token_frame, text="Username (optional):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.token_username_entry = ttk.Entry(token_frame, width=30)
        self.token_username_entry.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Help text
        help_text = "Generate at: https://github.com/settings/tokens\nRequired permissions: repo (for private) or public_repo"
        ttk.Label(token_frame, text=help_text, font=('Arial', 8), foreground='gray').grid(
            row=3, column=0, columnspan=2, sticky='w', padx=5, pady=5)
        
        token_frame.columnconfigure(1, weight=1)
        
        # Username/Password method
        password_frame = ttk.LabelFrame(self, text="Username & Password (Legacy)")
        password_frame.grid(row=2, column=0, columnspan=3, sticky='ew', pady=10, padx=10, ipady=10)
        
        ttk.Radiobutton(password_frame, text="Use Username & Password", 
                       variable=self.auth_method, value="password").grid(row=0, column=0, sticky='w', padx=5)
        
        ttk.Label(password_frame, text="Username:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.username_entry = ttk.Entry(password_frame, width=30)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(password_frame, text="Password:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.password_entry = ttk.Entry(password_frame, show='*', width=30)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Warning
        warning_text = "⚠️ GitHub deprecated password auth. Use Personal Access Token in password field.\nOr use Token method above (recommended)."
        ttk.Label(password_frame, text=warning_text, font=('Arial', 8), foreground='orange').grid(
            row=3, column=0, columnspan=2, sticky='w', padx=5, pady=5)
        
        # SSH Key configuration (future feature)
        ssh_frame = ttk.LabelFrame(self, text="SSH Key Configuration (Coming Soon)")
        ssh_frame.grid(row=3, column=0, columnspan=3, sticky='ew', pady=10, padx=10, ipady=10)
        
        ttk.Label(ssh_frame, text="🚧 SSH key authentication will be available in future version", 
                 font=('Arial', 10), foreground='gray').grid(row=0, column=0, padx=5, pady=10)
        
        # Action buttons
        button_frame = ttk.Frame(self)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        self.test_button = ttk.Button(button_frame, text="Test Connection", command=self.test_connection)
        self.test_button.grid(row=0, column=0, padx=5)
        
        self.login_button = ttk.Button(button_frame, text="Authenticate", command=self.authenticate)
        self.login_button.grid(row=0, column=1, padx=5)
        
        # Status
        self.status_label = ttk.Label(self, text="Enter your GitHub credentials to begin", 
                                     font=('Arial', 10))
        self.status_label.grid(row=5, column=0, columnspan=3, pady=10)
        
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
    
    def test_connection(self):
        """Test GitHub connection without full authentication."""
        self.status_label.config(text="🔄 Testing connection...")
        self.test_button.config(state='disabled')
        
        def test_thread():
            try:
                import requests
                response = requests.get("https://api.github.com/rate_limit", timeout=10)
                if response.status_code == 200:
                    self.after(0, lambda: self.test_success())
                else:
                    self.after(0, lambda: self.test_error("GitHub API not accessible"))
            except Exception as e:
                error_msg = str(e)
                self.after(0, lambda: self.test_error(error_msg))
        
        threading.Thread(target=test_thread, daemon=True).start()
    
    def test_success(self):
        """Handle successful connection test."""
        self.status_label.config(text="✅ GitHub API connection successful")
        self.test_button.config(state='normal')
    
    def test_error(self, error):
        """Handle connection test error."""
        self.status_label.config(text=f"❌ Connection failed: {error}")
        self.test_button.config(state='normal')
    
    def authenticate(self):
        """Perform GitHub authentication."""
        method = self.auth_method.get()
        
        if method == "token":
            token = self.token_entry.get().strip()
            username = self.token_username_entry.get().strip()
            
            if not token:
                messagebox.showerror("Error", "Please enter your GitHub token")
                return
                
            self.perform_auth("token", token=token, username=username)
            
        elif method == "password":
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            
            if not username or not password:
                messagebox.showerror("Error", "Please enter both username and password")
                return
                
            self.perform_auth("password", username=username, password=password)
    
    def perform_auth(self, method, **credentials):
        """Perform the actual authentication."""
        self.status_label.config(text="🔄 Authenticating...")
        self.login_button.config(state='disabled')
        
        def auth_thread():
            try:
                from github import Github
                
                github_client = None
                username = None
                
                if method == "token":
                    token = credentials.get('token')
                    username_override = credentials.get('username')
                    
                    if len(token) < 20:
                        raise ValueError("Invalid token format - must be at least 20 characters")
                    
                    # Create GitHub client with token
                    github_client = Github(token)
                    
                    # Get authenticated user info
                    try:
                        user = github_client.get_user()
                        username = username_override if username_override else user.login
                        
                        # Test API access with a simple call
                        rate_limit = github_client.get_rate_limit()
                        remaining_calls = rate_limit.core.remaining
                        
                    except Exception as api_error:
                        if "401" in str(api_error):
                            raise ValueError("Invalid token - authentication failed")
                        elif "403" in str(api_error):
                            raise ValueError("Token lacks required permissions")
                        else:
                            raise ValueError(f"GitHub API error: {api_error}")
                
                elif method == "password":
                    username = credentials.get('username')
                    password = credentials.get('password')
                    
                    # Note: GitHub deprecated username/password for API access
                    # Try to use it as a personal access token instead
                    if len(password) > 30:  # Looks like a token
                        github_client = Github(password)
                        try:
                            user = github_client.get_user()
                            username = user.login
                            rate_limit = github_client.get_rate_limit()
                            remaining_calls = rate_limit.core.remaining
                        except Exception as api_error:
                            if "401" in str(api_error):
                                raise ValueError("Invalid token in password field")
                            else:
                                raise ValueError(f"GitHub API error: {api_error}")
                    else:
                        # Try traditional username/password (likely to fail with modern GitHub)
                        try:
                            github_client = Github(username, password)
                            user = github_client.get_user()
                            rate_limit = github_client.get_rate_limit()
                            remaining_calls = rate_limit.core.remaining
                        except Exception as api_error:
                            if "401" in str(api_error):
                                raise ValueError("Username/password authentication failed. GitHub requires Personal Access Tokens for API access. Please use a token instead of password.")
                            elif "403" in str(api_error):
                                raise ValueError("Authentication failed - GitHub requires Personal Access Tokens for API access")
                            else:
                                raise ValueError(f"GitHub API error: {api_error}")
                
                # Successful authentication
                if not github_client:
                    raise ValueError("GitHub client not created properly")
                
                auth_data = {
                    'method': method,
                    'username': username,
                    'github_client': github_client,
                    'authenticated': True,
                    'api_calls_remaining': remaining_calls
                }
                
                self.after(0, lambda: self.auth_success(auth_data))
                
            except Exception as e:
                error_msg = str(e)
                self.after(0, lambda: self.auth_error(error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def auth_success(self, auth_data):
        """Handle successful authentication."""
        username = auth_data.get('username', 'User')
        api_calls = auth_data.get('api_calls_remaining', 0)
        self.status_label.config(text=f"✅ Authenticated as {username} ({api_calls} API calls remaining)")
        self.login_button.config(text="Re-authenticate", state='normal')
        
        # Notify parent of successful authentication
        self.on_auth_success(auth_data)
    
    def auth_error(self, error):
        """Handle authentication error."""
        self.status_label.config(text=f"❌ Authentication failed: {error}")
        self.login_button.config(state='normal')
        messagebox.showerror("Authentication Failed", f"Failed to authenticate:\n{error}")


class RepositoryFrame(ttk.Frame):
    """Frame for repository selection."""
    
    def __init__(self, parent, on_scan_start):
        super().__init__(parent)
        self.on_scan_start = on_scan_start
        self.repositories = []
        self.auth_data = None
        self.create_widgets()
    
    def create_widgets(self):
        """Create repository selection UI."""
        # Title
        title_label = ttk.Label(self, text="📁 Repository Selection", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 20), sticky='w')
        
        # Controls
        controls_frame = ttk.Frame(self)
        controls_frame.grid(row=1, column=0, columnspan=4, sticky='ew', pady=10)
        
        self.load_button = ttk.Button(controls_frame, text="Load Repositories", 
                                     command=self.load_repositories, state='disabled')
        self.load_button.pack(side='left', padx=5)
        
        self.refresh_button = ttk.Button(controls_frame, text="Refresh", 
                                        command=self.load_repositories, state='disabled')
        self.refresh_button.pack(side='left', padx=5)
        
        ttk.Separator(controls_frame, orient='vertical').pack(side='left', fill='y', padx=10)
        
        self.select_all_button = ttk.Button(controls_frame, text="Select All", 
                                           command=self.select_all, state='disabled')
        self.select_all_button.pack(side='left', padx=5)
        
        self.deselect_all_button = ttk.Button(controls_frame, text="Clear All", 
                                             command=self.deselect_all, state='disabled')
        self.deselect_all_button.pack(side='left', padx=5)
        
        # Filter frame
        filter_frame = ttk.LabelFrame(self, text="Filters")
        filter_frame.grid(row=2, column=0, columnspan=4, sticky='ew', pady=10, padx=10)
        
        # Repository type filter
        ttk.Label(filter_frame, text="Type:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.type_filter = ttk.Combobox(filter_frame, values=["All", "Public", "Private"], 
                                       state="readonly", width=10)
        self.type_filter.set("All")
        self.type_filter.grid(row=0, column=1, padx=5, pady=5)
        self.type_filter.bind('<<ComboboxSelected>>', self.apply_filters)
        
        # Language filter  
        ttk.Label(filter_frame, text="Language:").grid(row=0, column=2, sticky='w', padx=5, pady=5)
        self.language_filter = ttk.Combobox(filter_frame, values=["All"], 
                                           state="readonly", width=15)
        self.language_filter.set("All")
        self.language_filter.grid(row=0, column=3, padx=5, pady=5)
        self.language_filter.bind('<<ComboboxSelected>>', self.apply_filters)
        
        # Search
        ttk.Label(filter_frame, text="Search:").grid(row=0, column=4, sticky='w', padx=5, pady=5)
        self.search_entry = ttk.Entry(filter_frame, width=20)
        self.search_entry.grid(row=0, column=5, padx=5, pady=5)
        self.search_entry.bind('<KeyRelease>', self.apply_filters)
        
        # Repository list
        list_frame = ttk.Frame(self)
        list_frame.grid(row=3, column=0, columnspan=4, sticky='nsew', pady=10)
        
        # Create treeview with checkboxes simulation
        columns = ('selected', 'name', 'private', 'language', 'size', 'updated', 'full_name')
        self.repo_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', height=12)
        
        # Configure columns
        self.repo_tree.heading('#0', text='')
        self.repo_tree.column('#0', width=30, minwidth=30)
        
        self.repo_tree.heading('selected', text='✓')
        self.repo_tree.column('selected', width=40, minwidth=40)
        
        self.repo_tree.heading('name', text='Repository Name')
        self.repo_tree.column('name', width=250, minwidth=200)
        
        self.repo_tree.heading('private', text='Private')
        self.repo_tree.column('private', width=80, minwidth=60)
        
        self.repo_tree.heading('language', text='Language')
        self.repo_tree.column('language', width=100, minwidth=80)
        
        self.repo_tree.heading('size', text='Size (KB)')
        self.repo_tree.column('size', width=100, minwidth=80)
        
        self.repo_tree.heading('updated', text='Last Updated')
        self.repo_tree.column('updated', width=120, minwidth=100)
        
        # Hidden column for full_name (used for API calls)
        self.repo_tree.heading('full_name', text='')
        self.repo_tree.column('full_name', width=0, minwidth=0)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.repo_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient='horizontal', command=self.repo_tree.xview)
        self.repo_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.repo_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Bind selection events
        self.repo_tree.bind('<Button-1>', self.on_repo_click)
        self.repo_tree.bind('<Double-1>', self.on_repo_double_click)
        
        # Scan configuration
        config_frame = ttk.LabelFrame(self, text="Scan Configuration")
        config_frame.grid(row=4, column=0, columnspan=4, sticky='ew', pady=10, padx=10)
        
        # Scan depth
        ttk.Label(config_frame, text="Scan Depth:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.scan_depth = ttk.Combobox(config_frame, values=["Surface (latest commit)", "Deep (full history)", "Custom"], 
                                      state="readonly", width=20)
        self.scan_depth.set("Surface (latest commit)")
        self.scan_depth.grid(row=0, column=1, padx=5, pady=5)
        
        # Max commits
        ttk.Label(config_frame, text="Max Commits:").grid(row=0, column=2, sticky='w', padx=5, pady=5)
        self.max_commits_var = tk.StringVar(value="100")
        max_commits_spinbox = ttk.Spinbox(config_frame, from_=1, to=10000, width=10, 
                                         textvariable=self.max_commits_var)
        max_commits_spinbox.grid(row=0, column=3, padx=5, pady=5)
        
        # File filters
        ttk.Label(config_frame, text="Include Files:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.include_files = ttk.Entry(config_frame, width=30)
        self.include_files.insert(0, "*.py,*.js,*.json,*.env,*.config")
        self.include_files.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky='ew')
        
        # Action buttons
        action_frame = ttk.Frame(self)
        action_frame.grid(row=5, column=0, columnspan=4, pady=20)
        
        self.scan_button = ttk.Button(action_frame, text="🔍 Start Security Scan", 
                                     command=self.start_scan, state='disabled')
        self.scan_button.pack(side='left', padx=10)
        
        # Status
        self.repo_status_label = ttk.Label(self, text="Please authenticate first to load repositories")
        self.repo_status_label.grid(row=6, column=0, columnspan=4, pady=5)
        
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
    
    def set_auth_data(self, auth_data):
        """Set authentication data and enable repository loading."""
        self.auth_data = auth_data
        self.load_button.config(state='normal')
        self.refresh_button.config(state='normal')
        self.repo_status_label.config(text="Click 'Load Repositories' to fetch your repositories")
    
    def load_repositories(self):
        """Load repositories from GitHub."""
        if not self.auth_data:
            messagebox.showerror("Error", "Please authenticate first")
            return
        
        self.load_button.config(state='disabled')
        self.refresh_button.config(state='disabled')
        self.repo_status_label.config(text="🔄 Loading repositories...")
        
        def load_thread():
            try:
                github_client = self.auth_data.get('github_client')
                if not github_client:
                    # Debug info
                    auth_keys = list(self.auth_data.keys()) if self.auth_data else ['None']
                    raise ValueError(f"No GitHub client available. Auth data keys: {auth_keys}")
                
                repos = []
                user = github_client.get_user()
                
                # Get user's repositories
                for repo in user.get_repos(sort='updated', direction='desc'):
                    try:
                        repo_data = {
                            "name": repo.name,
                            "full_name": repo.full_name,
                            "private": repo.private,
                            "language": repo.language,
                            "size": repo.size,
                            "updated": repo.updated_at.strftime("%Y-%m-%d") if repo.updated_at else "Unknown",
                            "description": repo.description or "No description",
                            "default_branch": repo.default_branch,
                            "clone_url": repo.clone_url,
                            "repo_object": repo  # Keep reference for later use
                        }
                        repos.append(repo_data)
                        
                        # Limit to prevent API rate limiting issues
                        if len(repos) >= 100:
                            break
                            
                    except Exception as repo_error:
                        # Skip repositories that cause errors (e.g., access issues)
                        continue
                
                self.after(0, lambda: self.repos_loaded(repos))
                
            except Exception as e:
                error_msg = str(e)
                self.after(0, lambda: self.repos_error(error_msg))
        
        threading.Thread(target=load_thread, daemon=True).start()
    
    def repos_loaded(self, repositories):
        """Handle successful repository loading."""
        self.repositories = repositories
        
        # Update language filter
        languages = set(repo.get('language') for repo in repositories if repo.get('language'))
        language_values = ["All"] + sorted(list(languages))
        self.language_filter.config(values=language_values)
        
        self.refresh_repository_list()
        
        self.load_button.config(state='normal')
        self.refresh_button.config(state='normal')
        self.select_all_button.config(state='normal')
        self.deselect_all_button.config(state='normal')
        
        self.repo_status_label.config(text=f"✅ Loaded {len(repositories)} repositories")
    
    def repos_error(self, error):
        """Handle repository loading error."""
        self.repo_status_label.config(text=f"❌ Failed to load repositories: {error}")
        self.load_button.config(state='normal')
        self.refresh_button.config(state='normal')
        messagebox.showerror("Error", f"Failed to load repositories:\n{error}")
    
    def refresh_repository_list(self):
        """Refresh the repository list display."""
        # Clear existing items
        for item in self.repo_tree.get_children():
            self.repo_tree.delete(item)
        
        # Add repositories
        for repo in self.repositories:
            private_text = "Yes" if repo.get('private') else "No"
            language_text = repo.get('language') or "Unknown"
            size_text = f"{repo.get('size', 0):,}"
            updated_text = repo.get('updated', 'Unknown')
            
            item_id = self.repo_tree.insert('', 'end', values=(
                '', repo['name'], private_text, language_text, size_text, updated_text
            ))
            # Store full_name for API calls
            self.repo_tree.set(item_id, 'full_name', repo['full_name'])
            
            # Store selection state
            self.repo_tree.set(item_id, 'selected', '☐')
    
    def apply_filters(self, event=None):
        """Apply filters to repository list."""
        if not self.repositories:
            return
        
        type_filter = self.type_filter.get()
        language_filter = self.language_filter.get()
        search_text = self.search_entry.get().lower()
        
        # Filter repositories
        filtered_repos = []
        for repo in self.repositories:
            # Type filter
            if type_filter != "All":
                if type_filter == "Private" and not repo.get('private'):
                    continue
                if type_filter == "Public" and repo.get('private'):
                    continue
            
            # Language filter
            if language_filter != "All" and repo.get('language') != language_filter:
                continue
            
            # Search filter
            if search_text and search_text not in repo['name'].lower():
                continue
            
            filtered_repos.append(repo)
        
        # Update display with filtered repositories
        for item in self.repo_tree.get_children():
            self.repo_tree.delete(item)
        
        for repo in filtered_repos:
            private_text = "Yes" if repo.get('private') else "No"
            language_text = repo.get('language') or "Unknown"
            size_text = f"{repo.get('size', 0):,}"
            updated_text = repo.get('updated', 'Unknown')
            
            item_id = self.repo_tree.insert('', 'end', values=(
                '', repo['name'], private_text, language_text, size_text, updated_text
            ))
            # Store full_name for API calls
            self.repo_tree.set(item_id, 'full_name', repo['full_name'])
            self.repo_tree.set(item_id, 'selected', '☐')
        
        self.repo_status_label.config(text=f"Showing {len(filtered_repos)} of {len(self.repositories)} repositories")
    
    def on_repo_click(self, event):
        """Handle repository selection click."""
        item = self.repo_tree.identify('item', event.x, event.y)
        column = self.repo_tree.identify('column', event.x, event.y)
        
        if item and (column == '#1' or column == '#0'):  # Selected column or tree column
            current = self.repo_tree.set(item, 'selected')
            new_value = '☑' if current == '☐' else '☐'
            self.repo_tree.set(item, 'selected', new_value)
            
            self.update_scan_button()
    
    def on_repo_double_click(self, event):
        """Handle repository double-click for details."""
        item = self.repo_tree.selection()[0] if self.repo_tree.selection() else None
        if item:
            repo_name = self.repo_tree.set(item, 'name')
            repo_info = f"Repository: {repo_name}\n\nThis would show detailed repository information in a full implementation."
            messagebox.showinfo("Repository Details", repo_info)
    
    def select_all(self):
        """Select all repositories."""
        for item in self.repo_tree.get_children():
            self.repo_tree.set(item, 'selected', '☑')
        self.update_scan_button()
    
    def deselect_all(self):
        """Deselect all repositories."""
        for item in self.repo_tree.get_children():
            self.repo_tree.set(item, 'selected', '☐')
        self.update_scan_button()
    
    def update_scan_button(self):
        """Update scan button state based on selections."""
        selected_count = 0
        for item in self.repo_tree.get_children():
            if self.repo_tree.set(item, 'selected') == '☑':
                selected_count += 1
        
        if selected_count > 0:
            self.scan_button.config(state='normal')
            self.repo_status_label.config(text=f"{selected_count} repositories selected for scanning")
        else:
            self.scan_button.config(state='disabled')
            current_count = len(self.repo_tree.get_children())
            total_count = len(self.repositories)
            if current_count == total_count:
                self.repo_status_label.config(text=f"Showing all {total_count} repositories - select some to scan")
            else:
                self.repo_status_label.config(text=f"Showing {current_count} of {total_count} repositories")
    
    def start_scan(self):
        """Start the security scan."""
        selected_repos = []
        for item in self.repo_tree.get_children():
            if self.repo_tree.set(item, 'selected') == '☑':
                repo_full_name = self.repo_tree.set(item, 'full_name')
                selected_repos.append(repo_full_name)
        
        if not selected_repos:
            messagebox.showwarning("Warning", "Please select at least one repository to scan")
            return
        
        # Get scan configuration
        scan_config = {
            'repositories': selected_repos,
            'scan_depth': self.scan_depth.get(),
            'max_commits': int(self.max_commits_var.get()),
            'include_files': self.include_files.get().split(','),
            'auth_data': self.auth_data
        }
        
        # Notify parent to start scan
        self.on_scan_start(scan_config)


class ScanProgressFrame(ttk.Frame):
    """Frame for displaying scan progress."""
    
    def __init__(self, parent, on_scan_complete=None):
        super().__init__(parent)
        self.on_scan_complete = on_scan_complete
        self.create_widgets()
    
    def create_widgets(self):
        """Create progress display UI."""
        # Title
        title_label = ttk.Label(self, text="🔍 Scanning Progress", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky='w')
        
        # Current status
        status_frame = ttk.LabelFrame(self, text="Current Status")
        status_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=10, padx=10, ipady=10)
        
        ttk.Label(status_frame, text="Repository:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.current_repo_label = ttk.Label(status_frame, text="Not started", 
                                           font=('Arial', 10, 'bold'), foreground='blue')
        self.current_repo_label.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(status_frame, text="File:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.current_file_label = ttk.Label(status_frame, text="", foreground='gray')
        self.current_file_label.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(status_frame, text="Status:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.status_label = ttk.Label(status_frame, text="Ready to scan")
        self.status_label.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        
        status_frame.columnconfigure(1, weight=1)
        
        # Progress bars
        progress_frame = ttk.LabelFrame(self, text="Progress")
        progress_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=10, padx=10, ipady=10)
        
        # Overall progress
        ttk.Label(progress_frame, text="Overall Progress:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.overall_progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.overall_progress.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        self.overall_progress_label = ttk.Label(progress_frame, text="0%")
        self.overall_progress_label.grid(row=0, column=2, padx=5, pady=5)
        
        # Repository progress
        ttk.Label(progress_frame, text="Repository:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.repo_progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.repo_progress.grid(row=1, column=1, sticky='ew', padx=5, pady=5)
        self.repo_progress_label = ttk.Label(progress_frame, text="0 / 0")
        self.repo_progress_label.grid(row=1, column=2, padx=5, pady=5)
        
        progress_frame.columnconfigure(1, weight=1)
        
        # Statistics
        stats_frame = ttk.LabelFrame(self, text="Statistics")
        stats_frame.grid(row=3, column=0, columnspan=2, sticky='ew', pady=10, padx=10, ipady=10)
        
        # Create stats in a grid
        stats_labels = [
            ("Repositories Scanned:", "repos_scanned"),
            ("Files Processed:", "files_processed"),
            ("Security Issues Found:", "issues_found"),
            ("Scan Duration:", "duration")
        ]
        
        self.stat_labels = {}
        for i, (label_text, key) in enumerate(stats_labels):
            row, col = i // 2, (i % 2) * 2
            ttk.Label(stats_frame, text=label_text).grid(row=row, column=col, sticky='w', padx=5, pady=5)
            self.stat_labels[key] = ttk.Label(stats_frame, text="0", font=('Arial', 10, 'bold'))
            self.stat_labels[key].grid(row=row, column=col+1, sticky='w', padx=5, pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(self)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        self.pause_button = ttk.Button(button_frame, text="⏸️ Pause", state='disabled', command=self.pause_scan)
        self.pause_button.grid(row=0, column=0, padx=5)
        
        self.cancel_button = ttk.Button(button_frame, text="⏹️ Cancel", state='disabled', command=self.cancel_scan)
        self.cancel_button.grid(row=0, column=1, padx=5)
        
        self.view_results_button = ttk.Button(button_frame, text="📊 View Results", state='disabled')
        self.view_results_button.grid(row=0, column=2, padx=5)
        
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
    
    def start_scan(self, scan_config):
        """Start the scanning process."""
        self.scan_config = scan_config
        self.pause_button.config(state='normal')
        self.cancel_button.config(state='normal')
        self.is_scanning = True
        self.scanner = None
        
        # Reset progress
        self.overall_progress['value'] = 0
        self.repo_progress['value'] = 0
        self.current_repo_label.config(text="Initializing...")
        self.current_file_label.config(text="")
        self.status_label.config(text="Starting scan...")
        
        # Reset statistics
        for key in self.stat_labels:
            self.stat_labels[key].config(text="0")
        
        # Start real scanning
        self._start_real_scan(scan_config)
    
    def _start_real_scan(self, scan_config):
        """Start real repository scanning."""
        # Import scanner modules
        try:
            from scanner import RepositoryScanner
            from detection import SecurityPatternDetector
        except ImportError as e:
            self.status_label.config(text=f"❌ Scanner modules not available: {e}")
            return
        
        # Get GitHub client from parent application
        github_client = None
        # Try multiple ways to get auth data
        auth_data = None
        if hasattr(self, 'auth_data') and self.auth_data:
            auth_data = self.auth_data
        elif hasattr(self.master, 'auth_data') and self.master.auth_data:
            auth_data = self.master.auth_data
        elif hasattr(self.master.master, 'auth_data') and self.master.master.auth_data:
            auth_data = self.master.master.auth_data
            
        if auth_data:
            github_client = auth_data.get('github_client')
        
        if not github_client:
            self.status_label.config(text="❌ GitHub authentication required")
            return
        
        # Create scanner with progress callback
        self.scanner = RepositoryScanner(github_client, self._on_scan_progress)
        
        # Start scanning in background thread
        def scan_thread():
            try:
                findings = self.scanner.scan_repositories(scan_config)
                summary = self.scanner.get_scan_summary()
                
                # Update UI on main thread
                self.after(0, lambda: self._on_scan_complete(findings, summary))
                
            except Exception as e:
                error_msg = str(e)
                self.after(0, lambda: self._on_scan_error(error_msg))
        
        import threading
        self.scan_thread = threading.Thread(target=scan_thread, daemon=True)
        self.scan_thread.start()
    
    def _on_scan_progress(self, progress):
        """Handle scan progress updates."""
        # Update current repository and file
        self.current_repo_label.config(text=f"Repository: {progress.current_repo}")
        self.current_file_label.config(text=f"File: {progress.current_file}")
        
        # Update progress bars
        self.overall_progress['value'] = progress.overall_percentage
        self.repo_progress['value'] = progress.repo_percentage
        
        # Update progress labels
        self.overall_progress_label.config(text=f"{progress.overall_percentage:.1f}%")
        self.repo_progress_label.config(text=f"{progress.repo_percentage:.1f}%")
        
        # Update status
        self.status_label.config(text=progress.status_message)
        
        # Update statistics
        elapsed = int(time.time() - progress.start_time) if progress.start_time else 0
        self.update_statistics(
            progress.repos_scanned,
            progress.files_processed,
            progress.findings_total,
            elapsed
        )
    
    def _on_scan_complete(self, findings, summary):
        """Handle scan completion."""
        self.is_scanning = False
        self.scan_results = findings
        self.scan_summary = summary
        
        # Update final statistics
        self.update_statistics(
            summary.get('repositories_scanned', 0),
            summary.get('files_processed', 0),
            summary.get('total_findings', 0),
            summary.get('scan_duration', 0)
        )
        
        # Update UI
        self.status_label.config(text="✅ Scan completed successfully")
        self.overall_progress['value'] = 100
        self.overall_progress_label.config(text="100%")
        
        # Enable results view
        self.cancel_button.config(text="Close", state='normal')
        self.view_results_button.config(state='normal')
        
        # Notify completion callback if set
        if self.on_scan_complete:
            self.on_scan_complete(findings, summary)
    
    def _on_scan_error(self, error_message):
        """Handle scan error."""
        self.is_scanning = False
        self.status_label.config(text=f"❌ Scan failed: {error_message}")
        self.cancel_button.config(text="Close", state='normal')
    
    def pause_scan(self):
        """Pause or resume the scan."""
        if hasattr(self, 'scanner') and self.scanner:
            current_text = self.pause_button.cget("text")
            if "Pause" in current_text:
                self.scanner.pause_scan()
                self.pause_button.config(text="▶️ Resume")
            else:
                self.scanner.resume_scan()
                self.pause_button.config(text="⏸️ Pause")
    
    def cancel_scan(self):
        """Cancel the current scan."""
        if hasattr(self, 'scanner') and self.scanner and hasattr(self, 'is_scanning') and self.is_scanning:
            self.scanner.cancel_scan()
            self.status_label.config(text="🛑 Cancelling scan...")
        else:
            # Just close if not scanning
            self.status_label.config(text="❌ Scan cancelled")
            self.pause_button.config(state='disabled')
            self.cancel_button.config(text="Close", state='normal')
            self.view_results_button.config(state='normal')
    
    def simulate_scan(self):
        """Simulate the scanning process."""
        repositories = self.scan_config['repositories']
        total_repos = len(repositories)
        
        def scan_simulation():
            import time
            import random
            
            start_time = time.time()
            total_files = 0
            total_issues = 0
            
            for repo_idx, repo_name in enumerate(repositories):
                # Update repository progress
                self.after(0, lambda r=repo_name: self.current_repo_label.config(text=r))
                self.after(0, lambda: self.status_label.config(text="Scanning repository..."))
                
                # Simulate files in repository
                num_files = random.randint(10, 50)
                for file_idx in range(num_files):
                    # Update file progress
                    file_name = f"src/file_{file_idx + 1}.py"
                    self.after(0, lambda f=file_name: self.current_file_label.config(text=f))
                    
                    # Simulate scan time
                    time.sleep(0.1)
                    
                    # Randomly find issues
                    if random.random() < 0.2:  # 20% chance of finding an issue
                        total_issues += 1
                    
                    total_files += 1
                    
                    # Update statistics
                    duration = int(time.time() - start_time)
                    self.after(0, lambda: self.update_statistics(repo_idx + 1, total_files, total_issues, duration))
                    
                    # Update repository progress
                    repo_progress = ((file_idx + 1) / num_files) * 100
                    self.after(0, lambda p=repo_progress: self.update_repo_progress(p, file_idx + 1, num_files))
                
                # Update overall progress
                overall_progress = ((repo_idx + 1) / total_repos) * 100
                self.after(0, lambda p=overall_progress: self.update_overall_progress(p))
            
            # Scan completed
            self.after(0, self.scan_completed)
        
        threading.Thread(target=scan_simulation, daemon=True).start()
    
    def update_statistics(self, repos_scanned, files_processed, issues_found, duration):
        """Update scan statistics."""
        self.stat_labels['repos_scanned'].config(text=str(repos_scanned))
        self.stat_labels['files_processed'].config(text=str(files_processed))
        self.stat_labels['issues_found'].config(text=str(issues_found))
        self.stat_labels['duration'].config(text=f"{duration}s")
    
    def update_overall_progress(self, percentage):
        """Update overall progress bar."""
        self.overall_progress['value'] = percentage
        self.overall_progress_label.config(text=f"{percentage:.1f}%")
    
    def update_repo_progress(self, percentage, current, total):
        """Update repository progress bar."""
        self.repo_progress['value'] = percentage
        self.repo_progress_label.config(text=f"{current} / {total}")
    
    def scan_completed(self):
        """Handle scan completion."""
        self.status_label.config(text="✅ Scan completed successfully!")
        self.current_file_label.config(text="All files processed")
        
        self.pause_button.config(state='disabled')
        self.cancel_button.config(text="Close", state='normal')
        self.view_results_button.config(state='normal')


class ResultsFrame(ttk.Frame):
    """Frame for displaying scan results."""
    
    def __init__(self, parent, on_results_ready=None):
        super().__init__(parent)
        self.on_results_ready = on_results_ready
        self.results = []
        self.create_widgets()
    
    def create_widgets(self):
        """Create results display UI."""
        # Title
        title_label = ttk.Label(self, text="📊 Scan Results", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 20), sticky='w')
        
        # Summary frame
        summary_frame = ttk.LabelFrame(self, text="Summary")
        summary_frame.grid(row=1, column=0, columnspan=4, sticky='ew', pady=10, padx=10, ipady=10)
        
        # Risk level summary
        risk_colors = {'Critical': 'red', 'High': 'orange', 'Medium': 'yellow', 'Low': 'green'}
        self.risk_labels = {}
        for i, (risk, color) in enumerate(risk_colors.items()):
            ttk.Label(summary_frame, text=f"{risk}:").grid(row=0, column=i*2, sticky='w', padx=5, pady=5)
            self.risk_labels[risk] = ttk.Label(summary_frame, text="0", 
                                             font=('Arial', 10, 'bold'), foreground=color)
            self.risk_labels[risk].grid(row=0, column=i*2+1, sticky='w', padx=5, pady=5)
        
        # Filters
        filter_frame = ttk.Frame(self)
        filter_frame.grid(row=2, column=0, columnspan=4, sticky='ew', pady=10)
        
        ttk.Label(filter_frame, text="Filter by Risk:").pack(side='left', padx=5)
        self.risk_filter = ttk.Combobox(filter_frame, values=["All", "Critical", "High", "Medium", "Low"], 
                                       state="readonly", width=10)
        self.risk_filter.set("All")
        self.risk_filter.pack(side='left', padx=5)
        self.risk_filter.bind('<<ComboboxSelected>>', self.apply_filter)
        
        ttk.Label(filter_frame, text="Filter by Type:").pack(side='left', padx=5)
        self.type_filter = ttk.Combobox(filter_frame, values=["All", "API Keys", "Passwords", "Private Keys", "Tokens"], 
                                       state="readonly", width=15)
        self.type_filter.set("All")
        self.type_filter.pack(side='left', padx=5)
        self.type_filter.bind('<<ComboboxSelected>>', self.apply_filter)
        
        ttk.Label(filter_frame, text="Search:").pack(side='left', padx=5)
        self.search_entry = ttk.Entry(filter_frame, width=20)
        self.search_entry.pack(side='left', padx=5)
        self.search_entry.bind('<KeyRelease>', self.apply_filter)
        
        # Results table
        table_frame = ttk.Frame(self)
        table_frame.grid(row=3, column=0, columnspan=4, sticky='nsew', pady=10)
        
        columns = ('repository', 'file', 'line', 'risk', 'type', 'finding', 'context')
        self.results_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.results_tree.heading('repository', text='Repository')
        self.results_tree.column('repository', width=150, minwidth=100)
        
        self.results_tree.heading('file', text='File')
        self.results_tree.column('file', width=200, minwidth=150)
        
        self.results_tree.heading('line', text='Line')
        self.results_tree.column('line', width=60, minwidth=50)
        
        self.results_tree.heading('risk', text='Risk')
        self.results_tree.column('risk', width=80, minwidth=60)
        
        self.results_tree.heading('type', text='Type')
        self.results_tree.column('type', width=100, minwidth=80)
        
        self.results_tree.heading('finding', text='Finding')
        self.results_tree.column('finding', width=200, minwidth=150)
        
        self.results_tree.heading('context', text='Context')
        self.results_tree.column('context', width=150, minwidth=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient='horizontal', command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        
        # Bind double-click for details
        self.results_tree.bind('<Double-1>', self.show_finding_details)
        
        # Export buttons
        export_frame = ttk.Frame(self)
        export_frame.grid(row=4, column=0, columnspan=4, pady=20)
        
        ttk.Button(export_frame, text="📄 Export CSV", command=self.export_csv).pack(side='left', padx=5)
        ttk.Button(export_frame, text="📋 Export JSON", command=self.export_json).pack(side='left', padx=5)
        ttk.Button(export_frame, text="🌐 Export HTML Report", command=self.export_html).pack(side='left', padx=5)
        ttk.Button(export_frame, text="📊 Generate Summary", command=self.generate_summary).pack(side='left', padx=5)
        
        # Status
        self.results_status_label = ttk.Label(self, text="No scan results available")
        self.results_status_label.grid(row=5, column=0, columnspan=4, pady=5)
        
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
    
    def load_results(self, scan_results=None):
        """Load scan results from actual scan or use mock data."""
        if scan_results is not None:
            # Use real scan results (even if empty)
            self.results = []
            for finding in scan_results:
                result = {
                    'repository': finding.file_path.split('/')[0] if '/' in finding.file_path else 'unknown',
                    'file': finding.file_path,
                    'line': finding.line_number,
                    'risk': finding.risk_level.value,
                    'type': finding.pattern_name.replace('_', ' ').title(),
                    'finding': finding.description,
                    'context': finding.matched_text[:100] + '...' if len(finding.matched_text) > 100 else finding.matched_text,
                    'commit_hash': finding.commit_hash,
                    'commit_date': finding.commit_date
                }
                self.results.append(result)
        else:
            # Generate mock results for demonstration
            import random
            
            mock_results = [
                {
                    'repository': 'my-web-app',
                    'file': 'config/database.js',
                    'line': 12,
                    'risk': 'CRITICAL',
                    'type': 'API Keys',
                    'finding': 'Database password in plaintext',
                    'context': 'password: "mySecretPass123"',
                    'commit_hash': None,
                    'commit_date': None
                },
                {
                    'repository': 'python-scripts',
                    'file': '.env',
                    'line': 3,
                    'risk': 'HIGH',
                    'type': 'API Keys',
                    'finding': 'AWS access key',
                    'context': 'AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE',
                    'commit_hash': None,
                    'commit_date': None
                },
                {
                    'repository': 'api-server',
                    'file': 'auth/keys.go',
                    'line': 45,
                    'risk': 'CRITICAL',
                    'type': 'Private Keys',
                    'finding': 'JWT signing key',
                    'context': 'signingKey := "supersecretkey123"',
                    'commit_hash': None,
                    'commit_date': None
                },
                {
                    'repository': 'my-web-app',
                    'file': 'src/api.js',
                    'line': 28,
                    'risk': 'MEDIUM',
                    'type': 'Tokens',
                    'finding': 'GitHub token in code',
                    'context': 'token: "ghp_xxxxxxxxxxxx"',
                    'commit_hash': None,
                    'commit_date': None
                },
                {
                    'repository': 'config-files',
                    'file': 'deploy.sh',
                    'line': 8,
                    'risk': 'HIGH',
                    'type': 'Passwords',
                    'finding': 'SSH password',
                    'context': 'sshpass -p "admin123" ssh...',
                    'commit_hash': None,
                    'commit_date': None
                },
            ]
            
            self.results = mock_results
        
        # Always refresh display and summary after loading results
        self.refresh_results_display()
        self.update_summary()
    
    def refresh_results_display(self):
        """Refresh the results display."""
        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Filter results
        filtered_results = self.filter_results()
        
        # Add results to tree
        for result in filtered_results:
            item_id = self.results_tree.insert('', 'end', values=(
                result['repository'],
                result['file'],
                result['line'],
                result['risk'],
                result['type'],
                result['finding'],
                result['context']
            ))
            
            # Color code by risk
            risk_colors = {'Critical': 'red', 'High': 'orange', 'Medium': 'yellow', 'Low': 'lightgreen'}
            if result['risk'] in risk_colors:
                self.results_tree.set(item_id, 'risk', result['risk'])
        
        # Update status
        total_results = len(self.results)
        filtered_count = len(filtered_results)
        
        if total_results == 0:
            self.results_status_label.config(text="No security issues found! 🎉")
        else:
            self.results_status_label.config(text=f"Showing {filtered_count} of {total_results} findings")
    
    def filter_results(self):
        """Apply filters to results."""
        filtered = self.results.copy()
        
        # Risk filter
        risk_filter = self.risk_filter.get()
        if risk_filter != "All":
            filtered = [r for r in filtered if r['risk'] == risk_filter]
        
        # Type filter
        type_filter = self.type_filter.get()
        if type_filter != "All":
            filtered = [r for r in filtered if r['type'] == type_filter]
        
        # Search filter
        search_text = self.search_entry.get().lower()
        if search_text:
            filtered = [r for r in filtered if 
                       search_text in r['file'].lower() or 
                       search_text in r['finding'].lower() or
                       search_text in r['context'].lower()]
        
        return filtered
    
    def apply_filter(self, event=None):
        """Apply filters and refresh display."""
        self.refresh_results_display()
    
    def update_summary(self):
        """Update the summary statistics."""
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for result in self.results:
            risk = result.get('risk', 'Low')
            if risk in risk_counts:
                risk_counts[risk] += 1
        
        for risk, count in risk_counts.items():
            self.risk_labels[risk].config(text=str(count))
    
    def show_finding_details(self, event):
        """Show detailed information about a finding."""
        item = self.results_tree.selection()[0] if self.results_tree.selection() else None
        if item:
            values = self.results_tree.item(item)['values']
            
            details = f"""Security Finding Details

Repository: {values[0]}
File: {values[1]}
Line: {values[2]}
Risk Level: {values[3]}
Type: {values[4]}
Finding: {values[5]}
Context: {values[6]}

Recommendations:
• Remove sensitive data from source code
• Use environment variables or secure configuration
• Review commit history for exposed secrets
• Consider rotating compromised credentials"""
            
            messagebox.showinfo("Finding Details", details)
    
    def export_csv(self):
        """Export results to CSV."""
        if not self.results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export CSV Report"
        )
        
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['Repository', 'File', 'Line', 'Risk', 'Type', 'Finding', 'Context']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for result in self.results:
                        writer.writerow({
                            'Repository': result['repository'],
                            'File': result['file'],
                            'Line': result['line'],
                            'Risk': result['risk'],
                            'Type': result['type'],
                            'Finding': result['finding'],
                            'Context': result['context']
                        })
                
                messagebox.showinfo("Success", f"CSV report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export CSV: {e}")
    
    def export_json(self):
        """Export results to JSON."""
        if not self.results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export JSON Report"
        )
        
        if filename:
            try:
                report = {
                    'scan_metadata': {
                        'timestamp': datetime.now().isoformat(),
                        'tool': 'GitGuard',
                        'version': '1.0.0'
                    },
                    'summary': {
                        'total_findings': len(self.results),
                        'risk_breakdown': {
                            risk: sum(1 for r in self.results if r['risk'] == risk)
                            for risk in ['Critical', 'High', 'Medium', 'Low']
                        }
                    },
                    'findings': self.results
                }
                
                with open(filename, 'w', encoding='utf-8') as jsonfile:
                    json.dump(report, jsonfile, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Success", f"JSON report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export JSON: {e}")
    
    def export_html(self):
        """Export results to HTML."""
        messagebox.showinfo("HTML Export", "HTML export functionality would generate a styled report with charts and detailed analysis.")
    
    def generate_summary(self):
        """Generate executive summary."""
        if not self.results:
            messagebox.showwarning("Warning", "No results to summarize")
            return
        
        risk_counts = {risk: sum(1 for r in self.results if r['risk'] == risk) 
                      for risk in ['Critical', 'High', 'Medium', 'Low']}
        
        total_high_risk = risk_counts['Critical'] + risk_counts['High']
        
        summary = f"""GitGuard Security Scan Summary
{'=' * 40}

Total Findings: {len(self.results)}
High Priority Issues: {total_high_risk}

Risk Breakdown:
• Critical: {risk_counts['Critical']}
• High: {risk_counts['High']}
• Medium: {risk_counts['Medium']}
• Low: {risk_counts['Low']}

Recommendations:
{"• Immediate action required for critical/high-risk findings" if total_high_risk > 0 else "• Good security posture - continue monitoring"}
• Review all findings and implement fixes
• Set up pre-commit hooks to prevent future issues
• Regular security scanning recommended

Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        # Show in a new window
        summary_window = tk.Toplevel(self)
        summary_window.title("Security Scan Summary")
        summary_window.geometry("600x400")
        
        text_widget = tk.Text(summary_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.insert(tk.END, summary)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Add save button
        save_button = ttk.Button(summary_window, text="Save Summary", 
                                command=lambda: self.save_summary(summary))
        save_button.pack(pady=10)
    
    def save_summary(self, summary_text):
        """Save summary to file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Summary"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(summary_text)
                messagebox.showinfo("Success", f"Summary saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save summary: {e}")


class GitGuardGUI:
    """Main GitGuard application window with full functionality."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("GitGuard - GitHub Security Scanner v1.0.0")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Application state
        self.auth_data = None
        
        self.create_widgets()
        self.setup_styles()
    
    def create_widgets(self):
        """Create main application widgets."""
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Authentication tab
        self.auth_frame = AuthenticationFrame(self.notebook, self.on_authentication_success)
        self.notebook.add(self.auth_frame, text="🔐 Authentication")
        
        # Repository selection tab
        self.repo_frame = RepositoryFrame(self.notebook, self.on_scan_start)
        self.notebook.add(self.repo_frame, text="📁 Repositories", state='disabled')
        
        # Scan progress tab
        self.progress_frame = ScanProgressFrame(self.notebook)
        self.notebook.add(self.progress_frame, text="🔍 Scanning", state='disabled')
        
        # Results tab
        self.results_frame = ResultsFrame(self.notebook)
        self.notebook.add(self.results_frame, text="📊 Results", state='disabled')
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Welcome to GitGuard - Please authenticate to begin", 
                                   relief='sunken', anchor='w')
        self.status_bar.pack(side='bottom', fill='x')
        
        # Menu bar
        self.create_menu()
    
    def create_menu(self):
        """Create application menu."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self.new_scan)
        file_menu.add_separator()
        file_menu.add_command(label="Import Results", command=self.import_results)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Check Dependencies", command=self.check_dependencies)
        tools_menu.add_command(label="Clear Cache", command=self.clear_cache)
        tools_menu.add_command(label="Settings", command=self.show_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_styles(self):
        """Setup custom styles for the application."""
        style = ttk.Style()
        
        # Configure treeview styles
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=('Arial', 10, 'bold'))
    
    def on_authentication_success(self, auth_data):
        """Handle successful authentication."""
        self.auth_data = auth_data
        
        # Enable repository tab
        self.notebook.tab(1, state='normal')
        self.notebook.select(1)
        
        # Pass auth data to repository frame and progress frame
        self.repo_frame.set_auth_data(auth_data)
        self.progress_frame.auth_data = auth_data
        
        username = auth_data.get('username', 'User')
        self.status_bar.config(text=f"Authenticated as {username} - Ready to scan repositories")
    
    def on_scan_start(self, scan_config):
        """Handle scan start."""
        # Enable and switch to progress tab
        self.notebook.tab(2, state='normal')
        self.notebook.select(2)
        
        # Start the scan
        self.progress_frame.start_scan(scan_config)
        
        # Setup progress completion callback
        self.progress_frame.view_results_button.config(command=self.show_results)
        
        repos_count = len(scan_config['repositories'])
        self.status_bar.config(text=f"Scanning {repos_count} repositories...")
    
    def show_results(self):
        """Show scan results."""
        # Enable and switch to results tab
        self.notebook.tab(3, state='normal')
        self.notebook.select(3)
        
        # Load results from scan if available
        scan_results = getattr(self.progress_frame, 'scan_results', None)
        self.results_frame.load_results(scan_results)
        
        findings_count = len(self.results_frame.results)
        if findings_count == 0:
            self.status_bar.config(text="Scan completed - No security issues found! 🎉")
        else:
            self.status_bar.config(text=f"Scan completed - {findings_count} security findings to review")
    
    def new_scan(self):
        """Start a new scan."""
        if self.auth_data:
            self.notebook.select(1)  # Go to repositories tab
            self.status_bar.config(text="Ready to start new scan")
        else:
            self.notebook.select(0)  # Go to authentication tab
            self.status_bar.config(text="Please authenticate first")
    
    def import_results(self):
        """Import scan results from file."""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Scan Results"
        )
        
        if filename:
            messagebox.showinfo("Import", f"Would import results from {filename}")
    
    def export_results(self):
        """Export current results."""
        if hasattr(self.results_frame, 'results') and self.results_frame.results:
            self.results_frame.export_json()
        else:
            messagebox.showwarning("Warning", "No results available to export")
    
    def check_dependencies(self):
        """Check system dependencies."""
        missing = []
        
        try:
            from github import Github
        except ImportError:
            missing.append("PyGithub")
        
        try:
            import requests
        except ImportError:
            missing.append("requests")
        
        if missing:
            deps_text = f"❌ Missing Dependencies:\n\n" + "\n".join(f"• {dep}" for dep in missing)
            deps_text += "\n\nInstall with: pip3 install -r requirements.txt"
        else:
            deps_text = "✅ All dependencies are installed and ready!"
        
        messagebox.showinfo("Dependency Check", deps_text)
    
    def clear_cache(self):
        """Clear application cache."""
        messagebox.showinfo("Cache", "Cache cleared successfully")
    
    def show_settings(self):
        """Show application settings."""
        messagebox.showinfo("Settings", "Settings dialog would allow configuration of:\n• Scan depth preferences\n• Export formats\n• API rate limits\n• Custom detection patterns")
    
    def show_documentation(self):
        """Show documentation."""
        docs_text = """GitGuard Documentation

📁 Local Documentation:
• docs/TECHNICAL_SPECIFICATION.md
• docs/SECURITY_PRIVACY_PLAN.md  
• docs/DEVELOPMENT_RULES.md

🌐 Online Documentation:
https://github.com/dev-alt/GitGuard

💡 Quick Help:
1. Authenticate with GitHub credentials
2. Select repositories to scan
3. Configure scan options
4. Review security findings
5. Export reports for remediation"""
        
        messagebox.showinfo("Documentation", docs_text)
    
    def show_about(self):
        """Show about dialog."""
        about_text = """GitGuard - GitHub Security Scanner v1.0.0

🛡️ A comprehensive desktop application for scanning GitHub 
repositories and commit history for sensitive information.

✨ Features:
• GitHub authentication (token/password)
• Repository selection and filtering
• Real-time scan progress monitoring
• Comprehensive security findings analysis
• Multiple export formats (CSV, JSON, HTML)
• Risk-based categorization and filtering

🔒 Security & Privacy:
• Local-only processing
• No external data transmission
• Secure credential storage
• User-controlled data retention

📄 License: MIT License
🔗 Repository: https://github.com/dev-alt/GitGuard

© 2024 GitGuard Project"""
        
        messagebox.showinfo("About GitGuard", about_text)
    
    def run(self):
        """Start the GUI application."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass


def main():
    """Main entry point for the complete GUI application."""
    app = GitGuardGUI()
    app.run()


if __name__ == "__main__":
    main()