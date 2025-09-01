#!/usr/bin/env python3
"""
GitGuard - Complete GUI Application

Full-featured GUI interface for GitHub repository security scanning.
Includes authentication, repository selection, scanning, and results display.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import time
import os
import json
import sys
import traceback
import webbrowser
from typing import Dict, List, Optional
from datetime import datetime
try:
    from .logger import get_logger, init_logging
    from .settings import get_settings, init_settings
    from .result_cache import get_cache
except ImportError:
    from logger import get_logger, init_logging
    from settings import get_settings, init_settings
    from result_cache import get_cache

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
        self._bind_select_all(self.token_entry)
        
        ttk.Label(token_frame, text="Username (optional):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.token_username_entry = ttk.Entry(token_frame, width=30)
        self.token_username_entry.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        self._bind_select_all(self.token_username_entry)
        
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
        self._bind_select_all(self.username_entry)
        
        ttk.Label(password_frame, text="Password:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.password_entry = ttk.Entry(password_frame, show='*', width=30)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        self._bind_select_all(self.password_entry)
        
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
    
    def _bind_select_all(self, entry_widget):
        """Bind Ctrl+A to select all text in Entry widget."""
        def select_all(event):
            entry_widget.select_range(0, 'end')
            return 'break'  # Prevent default behavior
        
        # Bind both Control-a and Control-A to handle different cases
        entry_widget.bind('<Control-a>', select_all)
        entry_widget.bind('<Control-A>', select_all)
    
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
                get_logger().info(f"Starting authentication using {method}", "AUTH")
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
                        get_logger().debug(f"GitHub API rate limit remaining: {remaining_calls}", "AUTH")
                        
                    except Exception as api_error:
                        get_logger().error(f"GitHub API test failed: {api_error}", "AUTH")
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
                        get_logger().info(f"Attempting token authentication via password field for user {username}", "AUTH")
                        github_client = Github(password)
                        try:
                            user = github_client.get_user()
                            username = user.login
                            rate_limit = github_client.get_rate_limit()
                            remaining_calls = rate_limit.core.remaining
                            get_logger().debug(f"Token authentication successful, API calls remaining: {remaining_calls}", "AUTH")
                        except Exception as api_error:
                            get_logger().error(f"Token authentication via password field failed: {api_error}", "AUTH")
                            if "401" in str(api_error):
                                raise ValueError("Invalid token in password field")
                            else:
                                raise ValueError(f"GitHub API error: {api_error}")
                    else:
                        # Try traditional username/password (likely to fail with modern GitHub)
                        get_logger().warning(f"Attempting deprecated username/password authentication for user {username}", "AUTH")
                        try:
                            github_client = Github(username, password)
                            user = github_client.get_user()
                            rate_limit = github_client.get_rate_limit()
                            remaining_calls = rate_limit.core.remaining
                        except Exception as api_error:
                            get_logger().error(f"Username/password authentication failed: {api_error}", "AUTH")
                            if "401" in str(api_error):
                                raise ValueError("Username/password authentication failed. GitHub requires Personal Access Tokens for API access. Please use a token instead of password.")
                            elif "403" in str(api_error):
                                raise ValueError("Authentication failed - GitHub requires Personal Access Tokens for API access")
                            else:
                                raise ValueError(f"GitHub API error: {api_error}")
                
                # Successful authentication
                if not github_client:
                    raise ValueError("GitHub client not created properly")
                
                get_logger().log_authentication_attempt(method, username, True)
                auth_data = {
                    'method': method,
                    'username': username,
                    'github_client': github_client,
                    'authenticated': True,
                    'api_calls_remaining': remaining_calls
                }
                
                self.after(0, lambda: self.auth_success(auth_data))
                
            except Exception as e:
                get_logger().log_authentication_attempt(method, credentials.get('username', 'unknown'), False)
                get_logger().error(f"Authentication failed: {e}", "AUTH", e)
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
        ErrorHandler.show_error(self.root, error, "authentication")


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
        
        ttk.Separator(controls_frame, orient='vertical').pack(side='left', fill='y', padx=10)
        
        self.auto_scan_button = ttk.Button(controls_frame, text="🚀 Auto Scan All", 
                                          command=self.auto_scan_all, state='disabled')
        self.auto_scan_button.pack(side='left', padx=5)
        
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
        
        # Scan selected repository button
        self.scan_selected_button = ttk.Button(action_frame, text="⚡ Scan Selected Repo", 
                                              command=self.scan_selected_repo, state='disabled')
        self.scan_selected_button.pack(side='left', padx=5)
        
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
        self.auto_scan_button.config(state='normal')
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
                get_logger().info("Starting repository loading", "REPO")
                github_client = self.auth_data.get('github_client')
                if not github_client:
                    # Debug info
                    auth_keys = list(self.auth_data.keys()) if self.auth_data else ['None']
                    raise ValueError(f"No GitHub client available. Auth data keys: {auth_keys}")
                
                repos = []
                user = github_client.get_user()
                get_logger().debug(f"Loading repositories for user: {user.login}", "REPO")
                
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
                
                get_logger().log_repository_operation("loading", len(repos), True)
                self.after(0, lambda: self.repos_loaded(repos))
                
            except Exception as e:
                get_logger().log_repository_operation("loading", None, False)
                get_logger().error(f"Repository loading failed: {e}", "REPO", e)
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
        self.auto_scan_button.config(state='normal')
        self.scan_selected_button.config(state='normal')
        
        self.repo_status_label.config(text=f"✅ Loaded {len(repositories)} repositories")
    
    def repos_error(self, error):
        """Handle repository loading error."""
        self.repo_status_label.config(text=f"❌ Failed to load repositories: {error}")
        self.load_button.config(state='normal')
        self.refresh_button.config(state='normal')
        ErrorHandler.show_error(self.winfo_toplevel(), error, "repository_loading")
    
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
    
    def scan_selected_repo(self):
        """Scan the currently selected repository directly."""
        # Get the currently selected item in the tree
        selection = self.repo_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a repository to scan")
            return
        
        selected_item = selection[0]
        repo_full_name = self.repo_tree.set(selected_item, 'full_name')
        
        # Get scan configuration
        scan_config = {
            'repositories': [repo_full_name],
            'scan_depth': self.scan_depth.get(),
            'max_commits': int(self.max_commits_var.get()),
            'include_files': self.include_files.get().split(','),
            'auth_data': self.auth_data,
            'single_repo_mode': True,  # Flag to indicate this is single repo scanning
            'use_cache': True  # Enable caching for single repo scans
        }
        
        # Notify parent to start scan
        self.on_scan_start(scan_config)
    
    def auto_scan_all(self):
        """Automatically scan all repositories with optimized settings."""
        if not self.repositories:
            messagebox.showwarning("Warning", "Please load repositories first")
            return
        
        # Count repositories
        total_repos = len(self.repositories)
        
        # Show confirmation dialog
        result = messagebox.askyesno(
            "Auto Scan All Repositories",
            f"This will scan ALL {total_repos} repositories in your account.\n\n"
            f"⚡ Quick scan mode will be used for efficiency:\n"
            f"• Current state only (no commit history)\n"
            f"• Max 50 commits per repository\n"
            f"• Focus on high-risk files and patterns\n\n"
            f"This may take several minutes. Continue?",
            icon='question'
        )
        
        if not result:
            return
        
        # Select all repositories
        for item in self.repo_tree.get_children():
            self.repo_tree.set(item, 'selected', '☑')
        
        # Create optimized scan configuration for auto mode
        all_repos = []
        for item in self.repo_tree.get_children():
            repo_full_name = self.repo_tree.set(item, 'full_name')
            all_repos.append(repo_full_name)
        
        scan_config = {
            'repositories': all_repos,
            'scan_depth': 'current',  # Optimized for speed
            'max_commits': 50,  # Reduced for performance
            'include_files': ['*'],
            'exclude_patterns': ['node_modules', '.git', '__pycache__', '*.min.js', '*.min.css', 'dist/', 'build/'],
            'auto_mode': True  # Flag for auto scanning mode
        }
        
        # Update status
        self.repo_status_label.config(text=f"🚀 Auto scanning {total_repos} repositories...")
        
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
        repo_count = len(scan_config.get('repositories', []))
        is_auto_mode = scan_config.get('auto_mode', False)
        scan_type = "auto scan" if is_auto_mode else "manual scan"
        get_logger().log_scan_operation(f"{scan_type} start", f"{repo_count} repositories", True)
        
        self.scan_config = scan_config
        self.pause_button.config(state='normal')
        self.cancel_button.config(state='normal')
        self.is_scanning = True
        self.scanner = None
        
        # Check if auto mode
        auto_status = " (Auto Mode - Optimized)" if is_auto_mode else ""
        
        # Reset progress
        self.overall_progress['value'] = 0
        self.repo_progress['value'] = 0
        self.current_repo_label.config(text="Initializing...")
        self.current_file_label.config(text="")
        self.status_label.config(text=f"Starting scan{auto_status}...")
        
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
                # Check if we should use caching
                use_cache = scan_config.get('use_cache', False)
                findings = []
                cached_repos = []
                
                if use_cache:
                    # Try to get cached results first
                    cache = get_cache()
                    repositories = scan_config.get('repositories', [])
                    
                    for repo_name in repositories:
                        try:
                            # Get repository object for cache validation
                            repo_obj = github_client.get_repo(repo_name)
                            cached_results = cache.get_cached_results(repo_name, repo_obj, scan_config)
                            
                            if cached_results:
                                findings.extend(cached_results)
                                cached_repos.append(repo_name)
                                get_logger().info(f"Using cached results for {repo_name}", "SCAN")
                            
                        except Exception as e:
                            get_logger().debug(f"Cache check failed for {repo_name}: {e}", "SCAN")
                    
                    # Remove cached repos from scan config
                    remaining_repos = [repo for repo in repositories if repo not in cached_repos]
                    scan_config = scan_config.copy()
                    scan_config['repositories'] = remaining_repos
                    
                    # Update progress for cached results
                    if cached_repos:
                        progress_msg = f"Loaded {len(cached_repos)} repositories from cache"
                        self.after(0, lambda: self._update_status(progress_msg))
                
                # Scan remaining repositories
                if scan_config.get('repositories'):
                    new_findings = self.scanner.scan_repositories(scan_config)
                    findings.extend(new_findings)
                    
                    # Cache the new results if caching is enabled
                    if use_cache:
                        cache = get_cache()
                        for repo_name in scan_config['repositories']:
                            try:
                                repo_obj = github_client.get_repo(repo_name)
                                repo_findings = [f for f in new_findings if f.get('repository') == repo_name]
                                cache.store_results(repo_name, repo_obj, scan_config, repo_findings)
                            except Exception as e:
                                get_logger().debug(f"Failed to cache results for {repo_name}: {e}", "SCAN")
                
                summary = self.scanner.get_scan_summary() if hasattr(self.scanner, 'get_scan_summary') else {}
                
                # Update scan summary with cache info
                if use_cache and cached_repos:
                    summary['cached_repositories'] = len(cached_repos)
                    summary['scanned_repositories'] = len(scan_config.get('repositories', []))
                    summary['total_repositories'] = len(cached_repos) + len(scan_config.get('repositories', []))
                
                # Update UI on main thread
                self.after(0, lambda: self._on_scan_complete(findings, summary))
                
            except Exception as e:
                error_msg = str(e)
                self.after(0, lambda: self._on_scan_error(error_msg))
        
        import threading
        self.scan_thread = threading.Thread(target=scan_thread, daemon=True)
        self.scan_thread.start()
    
    def _update_status(self, message):
        """Update the status label."""
        self.status_label.config(text=message)
    
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
        # Create an exception object from the error message for better error handling
        error = Exception(error_message)
        ErrorHandler.show_error(self.winfo_toplevel(), error, "scanning")
    
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
        findings_count = len(self.scanner.results) if hasattr(self.scanner, 'results') else 0
        get_logger().log_scan_operation("completion", f"{findings_count} findings", True)
        
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
                ErrorHandler.show_error(self.winfo_toplevel(), e, "csv_export")
    
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
                ErrorHandler.show_error(self.winfo_toplevel(), e, "json_export")
    
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
    
    def export_csv(self):
        """Export results to CSV format."""
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export to CSV"
        )
        
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['repository', 'file', 'line', 'risk', 'type', 'finding', 'context', 'commit_hash', 'commit_date']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for result in self.results:
                        writer.writerow(result)
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
                get_logger().info(f"Results exported to CSV: {filename}", "EXPORT")
            except Exception as e:
                ErrorHandler.show_error(self.winfo_toplevel(), e, "csv_export")
                get_logger().error(f"CSV export failed: {e}", "EXPORT", e)
    
    def export_json(self):
        """Export results to JSON format."""
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export to JSON"
        )
        
        if filename:
            try:
                import json
                export_data = {
                    "scan_metadata": {
                        "timestamp": datetime.now().isoformat(),
                        "tool": "GitGuard",
                        "version": "1.0.0",
                        "total_findings": len(self.results)
                    },
                    "findings": self.results
                }
                
                with open(filename, 'w', encoding='utf-8') as jsonfile:
                    json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
                get_logger().info(f"Results exported to JSON: {filename}", "EXPORT")
            except Exception as e:
                ErrorHandler.show_error(self.winfo_toplevel(), e, "json_export")
                get_logger().error(f"JSON export failed: {e}", "EXPORT", e)
    
    def export_html(self):
        """Export results to HTML report format."""
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            title="Export HTML Report"
        )
        
        if filename:
            try:
                # Generate comprehensive HTML report
                html_content = self._generate_html_report()
                
                with open(filename, 'w', encoding='utf-8') as htmlfile:
                    htmlfile.write(html_content)
                
                messagebox.showinfo("Success", f"HTML report exported to {filename}")
                get_logger().info(f"HTML report exported: {filename}", "EXPORT")
                
                # Ask if user wants to open the report
                if messagebox.askyesno("Open Report", "Would you like to open the HTML report in your browser?"):
                    import webbrowser
                    webbrowser.open(f"file://{os.path.abspath(filename)}")
                    
            except Exception as e:
                ErrorHandler.show_error(self.winfo_toplevel(), e, "html_export")
                get_logger().error(f"HTML export failed: {e}", "EXPORT", e)
    
    def _generate_html_report(self):
        """Generate comprehensive HTML report."""
        # Calculate statistics
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        repo_counts = {}
        file_types = {}
        
        for result in self.results:
            risk = result.get('risk', 'Unknown')
            if risk in risk_counts:
                risk_counts[risk] += 1
            
            repo = result.get('repository', 'Unknown')
            repo_counts[repo] = repo_counts.get(repo, 0) + 1
            
            file_path = result.get('file', '')
            file_ext = file_path.split('.')[-1] if '.' in file_path else 'no extension'
            file_types[file_ext] = file_types.get(file_ext, 0) + 1
        
        total_findings = len(self.results)
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitGuard Security Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header .subtitle {{
            margin-top: 10px;
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .summary {{
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }}
        .summary h2 {{
            color: #495057;
            margin-top: 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .findings {{
            padding: 0;
        }}
        .findings h2 {{
            padding: 30px 30px 0;
            color: #495057;
        }}
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        .findings-table th {{
            background: #e9ecef;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
        }}
        .findings-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
            vertical-align: top;
        }}
        .findings-table tr:hover {{
            background-color: #f8f9fa;
        }}
        .risk-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }}
        .risk-critical {{
            background-color: #dc3545;
        }}
        .risk-high {{
            background-color: #fd7e14;
        }}
        .risk-medium {{
            background-color: #ffc107;
            color: #212529;
        }}
        .risk-low {{
            background-color: #28a745;
        }}
        .code-snippet {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            max-width: 300px;
            overflow-x: auto;
        }}
        .footer {{
            background: #495057;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
        .no-findings {{
            text-align: center;
            padding: 60px 30px;
            color: #6c757d;
        }}
        .no-findings h3 {{
            color: #28a745;
            font-size: 1.5em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ GitGuard Security Report</h1>
            <div class="subtitle">Comprehensive Repository Security Analysis</div>
            <div class="subtitle">Generated on {scan_time}</div>
        </div>
        
        <div class="summary">
            <h2>📊 Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_findings}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number critical">{risk_counts['Critical']}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number high">{risk_counts['High']}</div>
                    <div class="stat-label">High Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number medium">{risk_counts['Medium']}</div>
                    <div class="stat-label">Medium Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number low">{risk_counts['Low']}</div>
                    <div class="stat-label">Low Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(repo_counts)}</div>
                    <div class="stat-label">Repositories</div>
                </div>
            </div>
        </div>
        
        <div class="findings">"""
        
        if total_findings > 0:
            html_template += f"""
            <h2>🔍 Security Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Repository</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Risk</th>
                        <th>Type</th>
                        <th>Finding</th>
                        <th>Context</th>
                    </tr>
                </thead>
                <tbody>"""
            
            for result in self.results:
                risk_class = result.get('risk', 'unknown').lower()
                html_template += f"""
                    <tr>
                        <td>{result.get('repository', 'N/A')}</td>
                        <td><code>{result.get('file', 'N/A')}</code></td>
                        <td>{result.get('line', 'N/A')}</td>
                        <td><span class="risk-badge risk-{risk_class}">{result.get('risk', 'Unknown')}</span></td>
                        <td>{result.get('type', 'N/A')}</td>
                        <td>{result.get('finding', 'N/A')}</td>
                        <td><div class="code-snippet">{result.get('context', 'N/A')[:100]}{'...' if len(result.get('context', '')) > 100 else ''}</div></td>
                    </tr>"""
            
            html_template += """
                </tbody>
            </table>"""
        else:
            html_template += """
            <div class="no-findings">
                <h3>✅ No Security Issues Found</h3>
                <p>Congratulations! No security vulnerabilities were detected in the scanned repositories.</p>
                <p>Continue following security best practices and perform regular scans.</p>
            </div>"""
        
        html_template += f"""
        </div>
        
        <div class="footer">
            <p>Generated by GitGuard v1.0.0 | <a href="https://github.com/dev-alt/GitGuard" style="color: #fff;">GitHub Repository</a></p>
            <p>For questions or support, please visit the project repository</p>
        </div>
    </div>
</body>
</html>"""
        
        return html_template


class CustomPatternEditor:
    """Dialog for creating and editing custom detection patterns."""
    
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("🎨 Custom Pattern Editor")
        self.dialog.geometry("700x500")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        parent.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 350
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 250
        self.dialog.geometry(f"+{x}+{y}")
        
        self.patterns = self._load_custom_patterns()
        self.create_widgets()
    
    def create_widgets(self):
        """Create pattern editor interface."""
        # Header
        header_frame = ttk.Frame(self.dialog)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(header_frame, text="🎨 Custom Detection Patterns", 
                 font=('Arial', 14, 'bold')).pack()
        ttk.Label(header_frame, text="Create your own patterns to detect specific secrets or sensitive data", 
                 font=('Arial', 9), foreground='gray').pack(pady=5)
        
        # Pattern list and editor
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Left side: Pattern list
        list_frame = ttk.LabelFrame(main_frame, text="Existing Custom Patterns")
        list_frame.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        # Pattern listbox
        list_container = ttk.Frame(list_frame)
        list_container.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.pattern_listbox = tk.Listbox(list_container, height=15)
        self.pattern_listbox.pack(side='left', fill='both', expand=True)
        
        list_scroll = ttk.Scrollbar(list_container, orient='vertical', command=self.pattern_listbox.yview)
        list_scroll.pack(side='right', fill='y')
        self.pattern_listbox.config(yscrollcommand=list_scroll.set)
        
        # Bind selection
        self.pattern_listbox.bind('<<ListboxSelect>>', self.on_pattern_select)
        
        # List buttons
        list_btn_frame = ttk.Frame(list_frame)
        list_btn_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(list_btn_frame, text="➕ New", command=self.new_pattern).pack(side='left', padx=2)
        ttk.Button(list_btn_frame, text="🗑️ Delete", command=self.delete_pattern).pack(side='left', padx=2)
        
        # Right side: Pattern editor
        editor_frame = ttk.LabelFrame(main_frame, text="Pattern Details")
        editor_frame.pack(side='right', fill='both', expand=True, padx=(5, 0))
        
        # Pattern form
        form_frame = ttk.Frame(editor_frame)
        form_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Name
        ttk.Label(form_frame, text="Pattern Name:").grid(row=0, column=0, sticky='w', pady=5)
        self.name_entry = ttk.Entry(form_frame, width=30)
        self.name_entry.grid(row=0, column=1, sticky='ew', pady=5, padx=(5, 0))
        
        # Description
        ttk.Label(form_frame, text="Description:").grid(row=1, column=0, sticky='w', pady=5)
        self.desc_entry = ttk.Entry(form_frame, width=30)
        self.desc_entry.grid(row=1, column=1, sticky='ew', pady=5, padx=(5, 0))
        
        # Risk Level
        ttk.Label(form_frame, text="Risk Level:").grid(row=2, column=0, sticky='w', pady=5)
        self.risk_var = tk.StringVar(value="MEDIUM")
        risk_combo = ttk.Combobox(form_frame, textvariable=self.risk_var, 
                                 values=["CRITICAL", "HIGH", "MEDIUM", "LOW"], 
                                 state="readonly", width=27)
        risk_combo.grid(row=2, column=1, sticky='w', pady=5, padx=(5, 0))
        
        # Pattern (regex)
        ttk.Label(form_frame, text="Regex Pattern:").grid(row=3, column=0, sticky='nw', pady=5)
        pattern_frame = ttk.Frame(form_frame)
        pattern_frame.grid(row=3, column=1, sticky='ew', pady=5, padx=(5, 0))
        
        self.pattern_text = tk.Text(pattern_frame, height=3, width=40, wrap='word')
        self.pattern_text.pack(fill='both', expand=True)
        
        # Test section
        test_frame = ttk.LabelFrame(form_frame, text="Test Pattern")
        test_frame.grid(row=4, column=0, columnspan=2, sticky='ew', pady=10, padx=0)
        
        ttk.Label(test_frame, text="Test Text:").pack(anchor='w', padx=5, pady=2)
        self.test_text = tk.Text(test_frame, height=3, wrap='word')
        self.test_text.pack(fill='x', padx=5, pady=2)
        
        test_btn_frame = ttk.Frame(test_frame)
        test_btn_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(test_btn_frame, text="🧪 Test Pattern", command=self.test_pattern).pack(side='left')
        self.test_result_label = ttk.Label(test_btn_frame, text="", foreground='blue')
        self.test_result_label.pack(side='left', padx=10)
        
        # Configure grid weights
        form_frame.columnconfigure(1, weight=1)
        test_frame.columnconfigure(0, weight=1)
        
        # Bottom buttons
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(button_frame, text="💾 Save Pattern", 
                  command=self.save_current_pattern).pack(side='left', padx=5)
        
        ttk.Frame(button_frame).pack(side='left', expand=True)  # Spacer
        
        ttk.Button(button_frame, text="Cancel", 
                  command=self.dialog.destroy).pack(side='right', padx=5)
        ttk.Button(button_frame, text="✅ Save All & Close", 
                  command=self.save_and_close).pack(side='right')
        
        # Load patterns into list
        self.refresh_pattern_list()
    
    def _load_custom_patterns(self):
        """Load custom patterns from settings."""
        try:
            settings_file = get_settings().config_dir / 'custom_patterns.json'
            if settings_file.exists():
                with open(settings_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            get_logger().error(f"Failed to load custom patterns: {e}", "PATTERNS")
        
        # Return default examples
        return [
            {
                "name": "Internal API Key",
                "description": "Company-specific API key pattern",
                "pattern": "INTERNAL_API_[A-Za-z0-9]{32}",
                "risk": "HIGH"
            },
            {
                "name": "Database Connection String",
                "description": "Custom database connection format",
                "pattern": "db://[^:]+:[^@]+@[^/]+/\\w+",
                "risk": "CRITICAL"
            }
        ]
    
    def _save_custom_patterns(self):
        """Save custom patterns to file."""
        try:
            settings_file = get_settings().config_dir / 'custom_patterns.json'
            with open(settings_file, 'w') as f:
                json.dump(self.patterns, f, indent=2)
            get_logger().info(f"Saved {len(self.patterns)} custom patterns", "PATTERNS")
        except Exception as e:
            get_logger().error(f"Failed to save custom patterns: {e}", "PATTERNS")
            ErrorHandler.show_error(self.dialog, e, "custom_patterns")
    
    def refresh_pattern_list(self):
        """Refresh the pattern list display."""
        self.pattern_listbox.delete(0, tk.END)
        for i, pattern in enumerate(self.patterns):
            risk_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(pattern['risk'], "⚪")
            self.pattern_listbox.insert(tk.END, f"{risk_icon} {pattern['name']}")
    
    def on_pattern_select(self, event=None):
        """Handle pattern selection."""
        selection = self.pattern_listbox.curselection()
        if not selection:
            return
        
        pattern = self.patterns[selection[0]]
        
        # Populate form
        self.name_entry.delete(0, tk.END)
        self.name_entry.insert(0, pattern['name'])
        
        self.desc_entry.delete(0, tk.END)
        self.desc_entry.insert(0, pattern['description'])
        
        self.risk_var.set(pattern['risk'])
        
        self.pattern_text.delete(1.0, tk.END)
        self.pattern_text.insert(1.0, pattern['pattern'])
    
    def new_pattern(self):
        """Create a new pattern."""
        new_pattern = {
            "name": "New Pattern",
            "description": "Description of what this pattern detects",
            "pattern": "your_regex_pattern_here",
            "risk": "MEDIUM"
        }
        self.patterns.append(new_pattern)
        self.refresh_pattern_list()
        
        # Select the new pattern
        self.pattern_listbox.selection_set(len(self.patterns) - 1)
        self.on_pattern_select()
    
    def delete_pattern(self):
        """Delete selected pattern."""
        selection = self.pattern_listbox.curselection()
        if not selection:
            return
        
        if messagebox.askyesno("Delete Pattern", "Are you sure you want to delete this pattern?"):
            del self.patterns[selection[0]]
            self.refresh_pattern_list()
            
            # Clear form
            self.name_entry.delete(0, tk.END)
            self.desc_entry.delete(0, tk.END)
            self.pattern_text.delete(1.0, tk.END)
    
    def test_pattern(self):
        """Test the current pattern against test text."""
        pattern = self.pattern_text.get(1.0, tk.END).strip()
        test_text = self.test_text.get(1.0, tk.END).strip()
        
        if not pattern or not test_text:
            self.test_result_label.config(text="❗ Need pattern and test text", foreground='red')
            return
        
        try:
            import re
            matches = re.findall(pattern, test_text, re.IGNORECASE)
            if matches:
                self.test_result_label.config(
                    text=f"✅ Found {len(matches)} match(es): {matches[:3]}", 
                    foreground='green'
                )
            else:
                self.test_result_label.config(text="❌ No matches found", foreground='orange')
        except re.error as e:
            self.test_result_label.config(text=f"❗ Invalid regex: {e}", foreground='red')
    
    def save_current_pattern(self):
        """Save the currently edited pattern."""
        selection = self.pattern_listbox.curselection()
        if not selection:
            return
        
        # Update pattern data
        pattern = self.patterns[selection[0]]
        pattern['name'] = self.name_entry.get().strip()
        pattern['description'] = self.desc_entry.get().strip()
        pattern['risk'] = self.risk_var.get()
        pattern['pattern'] = self.pattern_text.get(1.0, tk.END).strip()
        
        self.refresh_pattern_list()
        self.pattern_listbox.selection_set(selection[0])  # Maintain selection
        
        messagebox.showinfo("Saved", "Pattern updated successfully!")
    
    def save_and_close(self):
        """Save all patterns and close dialog."""
        self._save_custom_patterns()
        messagebox.showinfo("Success", f"Saved {len(self.patterns)} custom patterns!")
        self.dialog.destroy()


class ErrorDialog:
    """Enhanced error dialog with better user guidance."""
    
    def __init__(self, parent, title="Error", error_message="", error_type="error", 
                 suggestions=None, show_details=False, technical_details=""):
        self.parent = parent
        self.title = title
        self.error_message = error_message
        self.error_type = error_type
        self.suggestions = suggestions or []
        self.show_details = show_details
        self.technical_details = technical_details
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("600x400")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create the error dialog widgets."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with icon and title
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Error icon
        icon = "❌" if self.error_type == "error" else "⚠️" if self.error_type == "warning" else "ℹ️"
        icon_label = ttk.Label(header_frame, text=icon, font=("Arial", 24))
        icon_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Title
        title_label = ttk.Label(header_frame, text=self.title, font=("Arial", 16, "bold"))
        title_label.pack(side=tk.LEFT)
        
        # Error message
        if self.error_message:
            message_frame = ttk.LabelFrame(main_frame, text="Description", padding="10")
            message_frame.pack(fill=tk.X, pady=(0, 15))
            
            message_text = tk.Text(message_frame, height=3, wrap=tk.WORD, font=("Arial", 10))
            message_text.pack(fill=tk.X)
            message_text.insert(tk.END, self.error_message)
            message_text.config(state=tk.DISABLED)
        
        # Suggestions
        if self.suggestions:
            suggestions_frame = ttk.LabelFrame(main_frame, text="💡 Suggested Solutions", padding="10")
            suggestions_frame.pack(fill=tk.X, pady=(0, 15))
            
            for i, suggestion in enumerate(self.suggestions, 1):
                suggestion_label = ttk.Label(suggestions_frame, text=f"{i}. {suggestion}", 
                                           wraplength=500, font=("Arial", 10))
                suggestion_label.pack(anchor=tk.W, pady=2)
        
        # Technical details (collapsible)
        if self.technical_details:
            details_frame = ttk.LabelFrame(main_frame, text="🔧 Technical Details", padding="10")
            
            if self.show_details:
                details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
                
                details_text = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD, 
                                                       font=("Courier", 9))
                details_text.pack(fill=tk.BOTH, expand=True)
                details_text.insert(tk.END, self.technical_details)
                details_text.config(state=tk.DISABLED)
            
            # Toggle button for details
            self.details_visible = self.show_details
            self.details_frame = details_frame
            
            toggle_button = ttk.Button(main_frame, text="🔽 Show Technical Details" if not self.show_details else "🔼 Hide Technical Details",
                                     command=self.toggle_details)
            toggle_button.pack(pady=(0, 15))
            self.toggle_button = toggle_button
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        # Help button (if applicable)
        if self.error_type in ["auth_error", "api_error", "connection_error"]:
            help_button = ttk.Button(button_frame, text="📖 Get Help", command=self.show_help)
            help_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Copy details button
        if self.technical_details:
            copy_button = ttk.Button(button_frame, text="📋 Copy Details", command=self.copy_details)
            copy_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # OK button
        ok_button = ttk.Button(button_frame, text="OK", command=self.dialog.destroy)
        ok_button.pack(side=tk.RIGHT)
        ok_button.focus_set()
        
        # Bind Enter key to OK button
        self.dialog.bind('<Return>', lambda e: self.dialog.destroy())
        self.dialog.bind('<Escape>', lambda e: self.dialog.destroy())
    
    def toggle_details(self):
        """Toggle technical details visibility."""
        if self.details_visible:
            self.details_frame.pack_forget()
            self.toggle_button.config(text="🔽 Show Technical Details")
            self.details_visible = False
        else:
            self.details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
            self.toggle_button.config(text="🔼 Hide Technical Details")
            self.details_visible = True
    
    def copy_details(self):
        """Copy technical details to clipboard."""
        self.dialog.clipboard_clear()
        details = f"Error: {self.error_message}\n\nTechnical Details:\n{self.technical_details}"
        self.dialog.clipboard_append(details)
        
        # Show brief confirmation
        messagebox.showinfo("Copied", "Error details copied to clipboard", parent=self.dialog)
    
    def show_help(self):
        """Show context-sensitive help."""
        help_urls = {
            "auth_error": "https://github.com/dev-alt/GitGuard#authentication-options",
            "api_error": "https://github.com/dev-alt/GitGuard#troubleshooting",
            "connection_error": "https://github.com/dev-alt/GitGuard#troubleshooting"
        }
        
        url = help_urls.get(self.error_type)
        if url:
            webbrowser.open(url)


class ErrorHandler:
    """Centralized error handling with smart categorization and suggestions."""
    
    @staticmethod
    def show_error(parent, error, context="", show_technical_details=False):
        """Show an appropriately formatted error dialog."""
        error_message = str(error)
        suggestions = []
        error_type = "error"
        technical_details = ""
        
        # Generate technical details
        if hasattr(error, '__traceback__') and error.__traceback__:
            technical_details = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
        else:
            technical_details = f"Error Type: {type(error).__name__}\nError Message: {error_message}\nContext: {context}"
        
        # Smart error categorization and suggestions
        if "401" in error_message or "authentication" in error_message.lower():
            error_type = "auth_error"
            suggestions = [
                "Check that your GitHub Personal Access Token is valid",
                "Ensure your token has the required 'repo' or 'public_repo' permissions",
                "Verify that your token hasn't expired",
                "Try generating a new Personal Access Token at https://github.com/settings/tokens"
            ]
            
        elif "404" in error_message or "not found" in error_message.lower():
            error_type = "api_error"
            suggestions = [
                "Verify that the repository exists and you have access to it",
                "Check that your authentication token has the correct permissions",
                "Ensure the repository name format is correct (owner/repo)"
            ]
            
        elif "403" in error_message or "rate limit" in error_message.lower():
            error_type = "api_error"
            suggestions = [
                "GitHub API rate limit exceeded - please wait and try again",
                "Use a Personal Access Token instead of username/password for higher rate limits",
                "Consider reducing the number of repositories scanned simultaneously"
            ]
            
        elif "connection" in error_message.lower() or "network" in error_message.lower():
            error_type = "connection_error"
            suggestions = [
                "Check your internet connection",
                "Verify that GitHub.com is accessible",
                "Try again in a few moments - this might be a temporary issue",
                "Check if you're behind a firewall or proxy that might block GitHub API access"
            ]
            
        elif "file" in error_message.lower() or "permission" in error_message.lower():
            error_type = "file_error"
            suggestions = [
                "Check that you have write permissions to the export directory",
                "Ensure the file isn't open in another application",
                "Try selecting a different location for saving files"
            ]
            
        elif "json" in error_message.lower() or "parsing" in error_message.lower():
            error_type = "data_error"
            suggestions = [
                "The configuration file may be corrupted - try resetting settings",
                "Check that custom pattern files are properly formatted JSON",
                "Consider clearing the application cache and trying again"
            ]
        
        else:
            # Generic error handling
            suggestions = [
                "Try the operation again - this might be a temporary issue",
                "Check the application logs for more detailed information",
                "Consider restarting the application if the problem persists"
            ]
        
        # Create and show the error dialog
        title = {
            "auth_error": "Authentication Error",
            "api_error": "GitHub API Error", 
            "connection_error": "Connection Error",
            "file_error": "File Operation Error",
            "data_error": "Data Format Error"
        }.get(error_type, "Application Error")
        
        dialog = ErrorDialog(
            parent=parent,
            title=title,
            error_message=error_message,
            error_type=error_type,
            suggestions=suggestions,
            show_details=show_technical_details,
            technical_details=technical_details
        )
        
        # Log the error
        try:
            get_logger().error(f"Error shown to user: {error_message}", context.upper() if context else "GUI", error)
        except:
            pass  # Don't let logging errors crash the error handler


class GitGuardGUI:
    """Main GitGuard application window with full functionality."""
    
    def __init__(self):
        # Initialize logging and settings systems
        self.logger = init_logging()
        self.settings = init_settings()
        self.logger.log_application_start()
        
        self.root = tk.Tk()
        self.root.title("GitGuard - GitHub Security Scanner v1.0.0")
        
        # Load window settings
        geometry = self.settings.get('gui.window_geometry', '1200x800')
        self.root.geometry(geometry)
        self.root.minsize(1000, 600)
        
        if self.settings.get('gui.window_maximized', False):
            self.root.state('zoomed')  # Windows/Linux
        
        # Application state
        self.auth_data = None
        
        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.create_widgets()
        self.setup_styles()
        self.load_cached_auth()
    
    def create_widgets(self):
        """Create main application widgets."""
        # Create menu bar
        self.create_menu()
        
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
        
        # Save auth cache if enabled
        cache_auth_data = {
            'username': auth_data.get('username', ''),
            'method': auth_data.get('method', 'token'),
            'last_used': datetime.now().isoformat()
        }
        self.settings.save_auth_cache(cache_auth_data)
        
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
        auto_mode = scan_config.get('auto_mode', False)
        auto_text = " (Auto Mode)" if auto_mode else ""
        self.status_bar.config(text=f"Scanning {repos_count} repositories{auto_text}...")
    
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
    
    def show_cache_manager(self):
        """Show cache management dialog."""
        cache = get_cache()
        cache_info = cache.get_cache_info()
        
        dialog = tk.Toplevel(self.root)
        dialog.title("💾 Cache Management")
        dialog.geometry("600x500")
        dialog.resizable(True, True)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_label = ttk.Label(main_frame, text="💾 Scan Result Cache Management", 
                               font=("Arial", 14, "bold"))
        header_label.pack(pady=(0, 15))
        
        # Cache stats
        stats_frame = ttk.LabelFrame(main_frame, text="Cache Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 15))
        
        stats_text = f"""Directory: {cache_info.get('cache_directory', 'N/A')}
Total Entries: {cache_info.get('total_entries', 0)}
Total Size: {cache_info.get('total_size_mb', 0)} MB
Max Entries: {cache_info.get('max_entries', 0)}
Max Age: {cache_info.get('max_age_days', 0)} days"""
        
        stats_label = ttk.Label(stats_frame, text=stats_text, font=("Courier", 10))
        stats_label.pack(anchor='w')
        
        # Cache entries
        if cache_info.get('cache_details'):
            entries_frame = ttk.LabelFrame(main_frame, text="Recent Cache Entries", padding="10")
            entries_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
            
            # Create treeview for cache entries
            tree_frame = ttk.Frame(entries_frame)
            tree_frame.pack(fill=tk.BOTH, expand=True)
            
            cache_tree = ttk.Treeview(tree_frame, columns=("repo", "date", "findings", "size"), show="headings", height=8)
            cache_tree.pack(side='left', fill='both', expand=True)
            
            # Configure columns
            cache_tree.heading("repo", text="Repository")
            cache_tree.heading("date", text="Scan Date")
            cache_tree.heading("findings", text="Findings")
            cache_tree.heading("size", text="Size (KB)")
            
            cache_tree.column("repo", width=200)
            cache_tree.column("date", width=120)
            cache_tree.column("findings", width=80)
            cache_tree.column("size", width=80)
            
            # Add scrollbar
            tree_scroll = ttk.Scrollbar(tree_frame, orient='vertical', command=cache_tree.yview)
            tree_scroll.pack(side='right', fill='y')
            cache_tree.config(yscrollcommand=tree_scroll.set)
            
            # Populate tree
            for entry in cache_info.get('cache_details', []):
                cache_tree.insert('', 'end', values=(
                    entry.get('repo_name', 'Unknown'),
                    entry.get('scan_date', '').split('T')[0] if 'T' in entry.get('scan_date', '') else entry.get('scan_date', ''),
                    entry.get('result_count', 0),
                    round(entry.get('file_size', 0) / 1024, 1)
                ))
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="🗑️ Clear All Cache", 
                  command=lambda: self._clear_all_cache(dialog)).pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="🔄 Refresh", 
                  command=lambda: self._refresh_cache_dialog(dialog)).pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Close", 
                  command=dialog.destroy).pack(side='right')
    
    def _clear_all_cache(self, parent_dialog):
        """Clear all cache with confirmation."""
        if messagebox.askyesno("Clear Cache", "Are you sure you want to clear all scan result cache?", parent=parent_dialog):
            cache = get_cache()
            cache.clear_all_cache()
            messagebox.showinfo("Cache Cleared", "All scan result cache has been cleared.", parent=parent_dialog)
            self._refresh_cache_dialog(parent_dialog)
    
    def _refresh_cache_dialog(self, dialog):
        """Refresh the cache management dialog."""
        dialog.destroy()
        self.show_cache_manager()
    
    def clear_scan_cache(self):
        """Clear scan cache from menu."""
        if messagebox.askyesno("Clear Cache", "Are you sure you want to clear all scan result cache?"):
            cache = get_cache()
            cache.clear_all_cache()
            messagebox.showinfo("Cache Cleared", "All scan result cache has been cleared.")
    
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
    
    def create_menu(self):
        """Create application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Settings...", command=self.show_settings_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Clear Auth Cache", command=self.clear_auth_cache)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="🎨 Custom Patterns...", command=self.show_pattern_editor)
        tools_menu.add_separator()
        tools_menu.add_command(label="💾 Cache Management...", command=self.show_cache_manager)
        tools_menu.add_command(label="🗑️ Clear Scan Cache", command=self.clear_scan_cache)
        tools_menu.add_separator()
        tools_menu.add_command(label="View Logs...", command=self.show_logs_dialog)
        tools_menu.add_command(label="Export Settings...", command=self.export_settings)
        tools_menu.add_command(label="Import Settings...", command=self.import_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def show_settings_dialog(self):
        """Show settings configuration dialog."""
        SettingsDialog(self.root, self.settings)
    
    def show_pattern_editor(self):
        """Show custom pattern editor dialog."""
        CustomPatternEditor(self.root)
    
    def clear_auth_cache(self):
        """Clear stored authentication cache."""
        if messagebox.askyesno("Clear Auth Cache", "Clear stored authentication data?"):
            self.settings.clear_auth_cache()
            messagebox.showinfo("Success", "Authentication cache cleared.")
    
    def show_logs_dialog(self):
        """Show logs directory information."""
        log_info = self.logger.get_log_files_info()
        info_text = f"""Log Directory: {log_info['log_directory']}

Current Session: {log_info['session_log']}
Main Log: {log_info['main_log']}
Error Log: {log_info['error_log']}

Recent Log Files:"""
        
        for log_file in log_info['log_files'][-5:]:  # Show last 5 files
            info_text += f"\n• {log_file['name']} ({log_file['size']} bytes)"
        
        if messagebox.askyesno("Log Files", f"{info_text}\n\nOpen log directory?"):
            import subprocess
            import platform
            log_dir = log_info['log_directory']
            
            if platform.system() == "Windows":
                subprocess.run(f'explorer "{log_dir}"', shell=True)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(f'open "{log_dir}"', shell=True)
            else:  # Linux
                subprocess.run(f'xdg-open "{log_dir}"', shell=True)
    
    def export_settings(self):
        """Export settings to file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Settings"
        )
        
        if filename:
            try:
                import shutil
                shutil.copy2(self.settings.settings_file, filename)
                messagebox.showinfo("Success", f"Settings exported to:\n{filename}")
            except Exception as e:
                ErrorHandler.show_error(self, e, "settings_export")
    
    def import_settings(self):
        """Import settings from file."""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Settings"
        )
        
        if filename:
            if messagebox.askyesno("Import Settings", "Import settings will replace current settings. Continue?"):
                try:
                    import shutil
                    shutil.copy2(filename, self.settings.settings_file)
                    self.settings.load_settings()
                    messagebox.showinfo("Success", "Settings imported successfully.\nRestart the application for all changes to take effect.")
                except Exception as e:
                    ErrorHandler.show_error(self, e, "settings_import")
    
    def load_cached_auth(self):
        """Load cached authentication data if available."""
        if self.settings.get('gui.remember_auth', False):
            auth_cache = self.settings.load_auth_cache()
            if auth_cache:
                # Pre-fill authentication form with cached data
                if hasattr(self, 'auth_frame'):
                    username = auth_cache.get('username', '')
                    method = auth_cache.get('method', 'token')
                    
                    if method == 'token' and hasattr(self.auth_frame, 'token_username_entry'):
                        self.auth_frame.token_username_entry.delete(0, tk.END)
                        self.auth_frame.token_username_entry.insert(0, username)
                    elif method == 'password' and hasattr(self.auth_frame, 'username_entry'):
                        self.auth_frame.username_entry.delete(0, tk.END)
                        self.auth_frame.username_entry.insert(0, username)
    
    def save_window_settings(self):
        """Save current window geometry and state."""
        try:
            # Save window geometry
            geometry = self.root.geometry()
            self.settings.set('gui.window_geometry', geometry)
            
            # Save maximized state
            state = self.root.state()
            self.settings.set('gui.window_maximized', state == 'zoomed')
            
            # Save settings to file
            self.settings.save_settings()
            
        except Exception as e:
            get_logger().error(f"Failed to save window settings: {e}", "GUI", e)
    
    def on_closing(self):
        """Handle application closing."""
        self.save_window_settings()
        self.logger.log_application_stop()
        self.root.destroy()
    
    def run(self):
        """Start the GUI application."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.logger.log_application_stop()


class SettingsDialog:
    """Settings configuration dialog."""
    
    def __init__(self, parent, settings):
        self.settings = settings
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("GitGuard Settings")
        self.dialog.geometry("600x500")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        parent.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 300
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 250
        self.dialog.geometry(f"+{x}+{y}")
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create settings dialog widgets."""
        # Create notebook for different setting categories
        notebook = ttk.Notebook(self.dialog)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # GUI Settings tab
        gui_frame = ttk.Frame(notebook)
        notebook.add(gui_frame, text="Interface")
        self.create_gui_settings(gui_frame)
        
        # Scanning Settings tab
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text="Scanning")
        self.create_scan_settings(scan_frame)
        
        # Detection Settings tab
        detection_frame = ttk.Frame(notebook)
        notebook.add(detection_frame, text="Detection")
        self.create_detection_settings(detection_frame)
        
        # Export Settings tab
        export_frame = ttk.Frame(notebook)
        notebook.add(export_frame, text="Export")
        self.create_export_settings(export_frame)
        
        # Logging Settings tab
        logging_frame = ttk.Frame(notebook)
        notebook.add(logging_frame, text="Logging")
        self.create_logging_settings(logging_frame)
        
        # Button frame
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="Reset to Defaults", 
                  command=self.reset_to_defaults).pack(side='left')
        
        ttk.Frame(button_frame).pack(side='left', expand=True)  # Spacer
        
        ttk.Button(button_frame, text="Cancel", 
                  command=self.dialog.destroy).pack(side='right', padx=5)
        ttk.Button(button_frame, text="OK", 
                  command=self.save_and_close).pack(side='right')
    
    def create_gui_settings(self, parent):
        """Create GUI settings controls."""
        # Remember authentication
        self.remember_auth = tk.BooleanVar(value=self.settings.get('gui.remember_auth', False))
        ttk.Checkbutton(parent, text="Remember authentication details", 
                       variable=self.remember_auth).pack(anchor='w', pady=5)
        
        # Auto load repositories
        self.auto_load_repos = tk.BooleanVar(value=self.settings.get('gui.auto_load_repos', False))
        ttk.Checkbutton(parent, text="Automatically load repositories after authentication", 
                       variable=self.auto_load_repos).pack(anchor='w', pady=5)
        
        # Confirm destructive actions
        self.confirm_actions = tk.BooleanVar(value=self.settings.get('gui.confirm_destructive_actions', True))
        ttk.Checkbutton(parent, text="Confirm destructive actions", 
                       variable=self.confirm_actions).pack(anchor='w', pady=5)
    
    def create_scan_settings(self, parent):
        """Create scanning settings controls."""
        # Max commits
        ttk.Label(parent, text="Maximum commits to scan per repository:").pack(anchor='w', pady=5)
        self.max_commits = tk.IntVar(value=self.settings.get('scanning.max_commits', 100))
        commits_frame = ttk.Frame(parent)
        commits_frame.pack(fill='x', pady=5)
        ttk.Scale(commits_frame, from_=10, to=500, variable=self.max_commits, 
                 orient='horizontal').pack(side='left', expand=True, fill='x')
        ttk.Label(commits_frame, textvariable=self.max_commits, width=4).pack(side='right')
        
        # Scan depth
        ttk.Label(parent, text="Default scan depth:").pack(anchor='w', pady=5)
        self.scan_depth = tk.StringVar(value=self.settings.get('scanning.scan_depth', 'current'))
        depth_frame = ttk.Frame(parent)
        depth_frame.pack(anchor='w', pady=5)
        ttk.Radiobutton(depth_frame, text="Current state only", 
                       variable=self.scan_depth, value='current').pack(anchor='w')
        ttk.Radiobutton(depth_frame, text="Full commit history", 
                       variable=self.scan_depth, value='history').pack(anchor='w')
        
        # Exclusions
        self.exclude_build = tk.BooleanVar(value=self.settings.get('scanning.exclude_build_folders', True))
        ttk.Checkbutton(parent, text="Exclude build folders (node_modules, dist, build)", 
                       variable=self.exclude_build).pack(anchor='w', pady=5)
        
        self.exclude_deps = tk.BooleanVar(value=self.settings.get('scanning.exclude_dependencies', True))
        ttk.Checkbutton(parent, text="Exclude dependency files", 
                       variable=self.exclude_deps).pack(anchor='w', pady=5)
        
        self.parallel_scan = tk.BooleanVar(value=self.settings.get('scanning.parallel_scanning', True))
        ttk.Checkbutton(parent, text="Enable parallel scanning", 
                       variable=self.parallel_scan).pack(anchor='w', pady=5)
    
    def create_detection_settings(self, parent):
        """Create detection settings controls."""
        # Entropy threshold
        ttk.Label(parent, text="Entropy threshold for secret detection:").pack(anchor='w', pady=5)
        self.entropy_threshold = tk.DoubleVar(value=self.settings.get('detection.entropy_threshold', 4.0))
        entropy_frame = ttk.Frame(parent)
        entropy_frame.pack(fill='x', pady=5)
        ttk.Scale(entropy_frame, from_=2.0, to=6.0, variable=self.entropy_threshold, 
                 orient='horizontal').pack(side='left', expand=True, fill='x')
        entropy_label = ttk.Label(entropy_frame, width=4)
        entropy_label.pack(side='right')
        
        def update_entropy_label(*args):
            entropy_label.config(text=f"{self.entropy_threshold.get():.1f}")
        self.entropy_threshold.trace('w', update_entropy_label)
        update_entropy_label()
        
        # Minimum secret length
        ttk.Label(parent, text="Minimum secret length:").pack(anchor='w', pady=5)
        self.min_secret_length = tk.IntVar(value=self.settings.get('detection.min_secret_length', 8))
        length_frame = ttk.Frame(parent)
        length_frame.pack(fill='x', pady=5)
        ttk.Scale(length_frame, from_=4, to=32, variable=self.min_secret_length, 
                 orient='horizontal').pack(side='left', expand=True, fill='x')
        ttk.Label(length_frame, textvariable=self.min_secret_length, width=4).pack(side='right')
        
        # Exclude test files
        self.exclude_tests = tk.BooleanVar(value=self.settings.get('detection.exclude_test_files', True))
        ttk.Checkbutton(parent, text="Exclude test files from scanning", 
                       variable=self.exclude_tests).pack(anchor='w', pady=5)
        
        # Custom patterns
        self.custom_patterns = tk.BooleanVar(value=self.settings.get('detection.custom_patterns_enabled', True))
        ttk.Checkbutton(parent, text="Enable custom pattern detection", 
                       variable=self.custom_patterns).pack(anchor='w', pady=5)
    
    def create_export_settings(self, parent):
        """Create export settings controls."""
        # Default format
        ttk.Label(parent, text="Default export format:").pack(anchor='w', pady=5)
        self.export_format = tk.StringVar(value=self.settings.get('export.default_format', 'csv'))
        format_frame = ttk.Frame(parent)
        format_frame.pack(anchor='w', pady=5)
        for fmt in ['csv', 'json', 'html']:
            ttk.Radiobutton(format_frame, text=fmt.upper(), 
                           variable=self.export_format, value=fmt).pack(side='left', padx=10)
        
        # Include options
        self.include_low_risk = tk.BooleanVar(value=self.settings.get('export.include_low_risk', False))
        ttk.Checkbutton(parent, text="Include low-risk findings in exports", 
                       variable=self.include_low_risk).pack(anchor='w', pady=5)
        
        self.include_content = tk.BooleanVar(value=self.settings.get('export.include_file_content', True))
        ttk.Checkbutton(parent, text="Include file content in exports", 
                       variable=self.include_content).pack(anchor='w', pady=5)
        
        self.auto_timestamp = tk.BooleanVar(value=self.settings.get('export.auto_timestamp_files', True))
        ttk.Checkbutton(parent, text="Automatically timestamp export files", 
                       variable=self.auto_timestamp).pack(anchor='w', pady=5)
    
    def create_logging_settings(self, parent):
        """Create logging settings controls."""
        # Log level
        ttk.Label(parent, text="Log level:").pack(anchor='w', pady=5)
        self.log_level = tk.StringVar(value=self.settings.get('logging.log_level', 'INFO'))
        level_frame = ttk.Frame(parent)
        level_frame.pack(anchor='w', pady=5)
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        ttk.Combobox(level_frame, textvariable=self.log_level, values=levels, 
                    state='readonly', width=15).pack(side='left')
        
        # Max log size
        ttk.Label(parent, text="Maximum log file size (MB):").pack(anchor='w', pady=(10, 5))
        self.max_log_size = tk.IntVar(value=self.settings.get('logging.max_log_size_mb', 10))
        size_frame = ttk.Frame(parent)
        size_frame.pack(fill='x', pady=5)
        ttk.Scale(size_frame, from_=1, to=100, variable=self.max_log_size, 
                 orient='horizontal').pack(side='left', expand=True, fill='x')
        ttk.Label(size_frame, textvariable=self.max_log_size, width=4).pack(side='right')
        
        # Keep logs days
        ttk.Label(parent, text="Keep log files for (days):").pack(anchor='w', pady=(10, 5))
        self.keep_logs_days = tk.IntVar(value=self.settings.get('logging.keep_logs_days', 30))
        days_frame = ttk.Frame(parent)
        days_frame.pack(fill='x', pady=5)
        ttk.Scale(days_frame, from_=1, to=365, variable=self.keep_logs_days, 
                 orient='horizontal').pack(side='left', expand=True, fill='x')
        ttk.Label(days_frame, textvariable=self.keep_logs_days, width=4).pack(side='right')
        
        # Console logging
        self.log_to_console = tk.BooleanVar(value=self.settings.get('logging.log_to_console', True))
        ttk.Checkbutton(parent, text="Enable console logging", 
                       variable=self.log_to_console).pack(anchor='w', pady=5)
    
    def save_and_close(self):
        """Save settings and close dialog."""
        try:
            # Save GUI settings
            self.settings.set('gui.remember_auth', self.remember_auth.get())
            self.settings.set('gui.auto_load_repos', self.auto_load_repos.get())
            self.settings.set('gui.confirm_destructive_actions', self.confirm_actions.get())
            
            # Save scanning settings
            self.settings.set('scanning.max_commits', self.max_commits.get())
            self.settings.set('scanning.scan_depth', self.scan_depth.get())
            self.settings.set('scanning.exclude_build_folders', self.exclude_build.get())
            self.settings.set('scanning.exclude_dependencies', self.exclude_deps.get())
            self.settings.set('scanning.parallel_scanning', self.parallel_scan.get())
            
            # Save detection settings
            self.settings.set('detection.entropy_threshold', self.entropy_threshold.get())
            self.settings.set('detection.min_secret_length', self.min_secret_length.get())
            self.settings.set('detection.exclude_test_files', self.exclude_tests.get())
            self.settings.set('detection.custom_patterns_enabled', self.custom_patterns.get())
            
            # Save export settings
            self.settings.set('export.default_format', self.export_format.get())
            self.settings.set('export.include_low_risk', self.include_low_risk.get())
            self.settings.set('export.include_file_content', self.include_content.get())
            self.settings.set('export.auto_timestamp_files', self.auto_timestamp.get())
            
            # Save logging settings
            self.settings.set('logging.log_level', self.log_level.get())
            self.settings.set('logging.max_log_size_mb', self.max_log_size.get())
            self.settings.set('logging.keep_logs_days', self.keep_logs_days.get())
            self.settings.set('logging.log_to_console', self.log_to_console.get())
            
            # Save to file
            if self.settings.save_settings():
                messagebox.showinfo("Settings Saved", "Settings have been saved successfully.")
                self.dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to save settings.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings:\n{e}")
    
    def reset_to_defaults(self):
        """Reset all settings to default values."""
        if messagebox.askyesno("Reset Settings", "Reset all settings to default values?"):
            self.settings.reset_to_defaults()
            self.settings.save_settings()
            messagebox.showinfo("Reset Complete", "Settings have been reset to defaults.\nClose and reopen the settings dialog to see the changes.")


def main():
    """Main entry point for the complete GUI application."""
    app = GitGuardGUI()
    app.run()


if __name__ == "__main__":
    main()