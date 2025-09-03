# Employee Management System - User Management Module
# Complete implementation with GUI, database operations, and authentication

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import mysql.connector
from mysql.connector import Error
import hashlib
from datetime import datetime
import re

class DatabaseManager:
    """Handles all database operations for the User Management Module"""
    
    def __init__(self):
        self.connection = None
        self.connect_to_database()
        self.create_tables()
    
    def connect_to_database(self):
        """Establish connection to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host='localhost',
                database='employee_management',
                user='root',  # Change this to your MySQL username
                password='root'  # Change this to your MySQL password
            )
            if self.connection.is_connected():
                print("Successfully connected to MySQL database")
        except Error as e:
            print(f"Error while connecting to MySQL: {e}")
            # Create database if it doesn't exist
            try:
                temp_connection = mysql.connector.connect(
                    host='localhost',
                    user='root',  # Change this to your MySQL username
                    password='root'  # Change this to your MySQL password
                )
                cursor = temp_connection.cursor()
                cursor.execute("CREATE DATABASE IF NOT EXISTS employee_management")
                cursor.close()
                temp_connection.close()
                
                # Now connect to the created database
                self.connection = mysql.connector.connect(
                    host='localhost',
                    database='employee_management',
                    user='root',  # Change this to your MySQL username
                    password='root'  # Change this to your MySQL password
                )
                print("Database created and connected successfully")
            except Error as create_error:
                print(f"Error creating database: {create_error}")
    
    def create_tables(self):
        """Create necessary tables if they don't exist"""
        if self.connection and self.connection.is_connected():
            cursor = self.connection.cursor()
            
            # Create Users table
            create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                UserID INT AUTO_INCREMENT PRIMARY KEY,
                Username VARCHAR(50) UNIQUE NOT NULL,
                Email VARCHAR(100) UNIQUE NOT NULL,
                PasswordHash VARCHAR(64) NOT NULL,
                FirstName VARCHAR(50) NOT NULL,
                LastName VARCHAR(50) NOT NULL,
                Department VARCHAR(100),
                Role ENUM('Employee', 'Manager', 'HR', 'Admin') DEFAULT 'Employee',
                ManagerID INT,
                IsActive BOOLEAN DEFAULT TRUE,
                CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ManagerID) REFERENCES users(UserID) ON DELETE SET NULL
            )
            """
            
            try:
                cursor.execute(create_users_table)
                self.connection.commit()
                print("Users table created successfully")
                
                # Create default admin user if no users exist
                self.create_default_admin()
                
            except Error as e:
                print(f"Error creating tables: {e}")
            finally:
                cursor.close()
    
    def create_default_admin(self):
        """Create a default admin user for initial access"""
        cursor = self.connection.cursor()
        
        # Check if any users exist
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        
        if count == 0:
            # Create default admin user
            admin_password = self.hash_password("admin123")
            insert_admin = """
            INSERT INTO users (Username, Email, PasswordHash, FirstName, LastName, 
                             Department, Role, IsActive)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            admin_data = ("admin", "admin@company.com", admin_password, "System", 
                         "Administrator", "IT", "Admin", True)
            
            try:
                cursor.execute(insert_admin, admin_data)
                self.connection.commit()
                print("Default admin user created - Username: admin, Password: admin123")
            except Error as e:
                print(f"Error creating default admin: {e}")
        
        cursor.close()
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        cursor = self.connection.cursor()
        hashed_password = self.hash_password(password)
        
        query = """
        SELECT UserID, Username, FirstName, LastName, Role, Department, ManagerID
        FROM users 
        WHERE Username = %s AND PasswordHash = %s AND IsActive = TRUE
        """
        
        try:
            cursor.execute(query, (username, hashed_password))
            user = cursor.fetchone()
            cursor.close()
            return user
        except Error as e:
            print(f"Authentication error: {e}")
            cursor.close()
            return None
    
    def add_user(self, user_data):
        """Add a new user to the database"""
        cursor = self.connection.cursor()
        
        # Hash the password
        user_data['PasswordHash'] = self.hash_password(user_data['Password'])
        
        insert_query = """
        INSERT INTO users (Username, Email, PasswordHash, FirstName, LastName, 
                         Department, Role, ManagerID, IsActive)
        VALUES (%(Username)s, %(Email)s, %(PasswordHash)s, %(FirstName)s, 
                %(LastName)s, %(Department)s, %(Role)s, %(ManagerID)s, %(IsActive)s)
        """
        
        try:
            cursor.execute(insert_query, user_data)
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error adding user: {e}")
            cursor.close()
            return False
    
    def update_user(self, user_id, user_data):
        """Update existing user information"""
        cursor = self.connection.cursor()
        
        # If password is being updated, hash it
        if 'Password' in user_data and user_data['Password']:
            user_data['PasswordHash'] = self.hash_password(user_data['Password'])
            update_query = """
            UPDATE users SET Username = %(Username)s, Email = %(Email)s, 
                           PasswordHash = %(PasswordHash)s, FirstName = %(FirstName)s, 
                           LastName = %(LastName)s, Department = %(Department)s, 
                           Role = %(Role)s, ManagerID = %(ManagerID)s, IsActive = %(IsActive)s
            WHERE UserID = %(UserID)s
            """
        else:
            update_query = """
            UPDATE users SET Username = %(Username)s, Email = %(Email)s, 
                           FirstName = %(FirstName)s, LastName = %(LastName)s, 
                           Department = %(Department)s, Role = %(Role)s, 
                           ManagerID = %(ManagerID)s, IsActive = %(IsActive)s
            WHERE UserID = %(UserID)s
            """
        
        user_data['UserID'] = user_id
        
        try:
            cursor.execute(update_query, user_data)
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error updating user: {e}")
            cursor.close()
            return False
    
    def delete_user(self, user_id):
        """Soft delete user by setting IsActive to False"""
        cursor = self.connection.cursor()
        
        update_query = "UPDATE users SET IsActive = FALSE WHERE UserID = %s"
        
        try:
            cursor.execute(update_query, (user_id,))
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error deleting user: {e}")
            cursor.close()
            return False
    
    def get_all_users(self):
        """Retrieve all active users"""
        cursor = self.connection.cursor()
        
        query = """
        SELECT u.UserID, u.Username, u.Email, u.FirstName, u.LastName, 
               u.Department, u.Role, u.ManagerID, 
               CONCAT(m.FirstName, ' ', m.LastName) as ManagerName, u.IsActive
        FROM users u
        LEFT JOIN users m ON u.ManagerID = m.UserID
        WHERE u.IsActive = TRUE
        ORDER BY u.LastName, u.FirstName
        """
        
        try:
            cursor.execute(query)
            users = cursor.fetchall()
            cursor.close()
            return users
        except Error as e:
            print(f"Error retrieving users: {e}")
            cursor.close()
            return []
    
    def get_managers(self):
        """Get all users who can be managers (Manager, HR, Admin roles)"""
        cursor = self.connection.cursor()
        
        query = """
        SELECT UserID, CONCAT(FirstName, ' ', LastName, ' (', Role, ')') as ManagerName
        FROM users 
        WHERE Role IN ('Manager', 'HR', 'Admin') AND IsActive = TRUE
        ORDER BY FirstName, LastName
        """
        
        try:
            cursor.execute(query)
            managers = cursor.fetchall()
            cursor.close()
            return managers
        except Error as e:
            print(f"Error retrieving managers: {e}")
            cursor.close()
            return []
    
    def close_connection(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("MySQL connection is closed")

class UserSession:
    """Manages user session data"""
    
    def __init__(self):
        self.current_user = None
        self.user_id = None
        self.username = None
        self.role = None
        self.full_name = None
        self.department = None
        self.manager_id = None
    
    def login(self, user_data):
        """Set session data after successful login"""
        self.user_id, self.username, first_name, last_name, self.role, \
        self.department, self.manager_id = user_data
        self.full_name = f"{first_name} {last_name}"
        self.current_user = user_data
    
    def logout(self):
        """Clear session data"""
        self.current_user = None
        self.user_id = None
        self.username = None
        self.role = None
        self.full_name = None
        self.department = None
        self.manager_id = None
    
    def is_logged_in(self):
        """Check if user is logged in"""
        return self.current_user is not None
    
    def has_permission(self, required_role):
        """Check if current user has required permission level"""
        role_hierarchy = {'Employee': 1, 'Manager': 2, 'HR': 3, 'Admin': 4}
        current_level = role_hierarchy.get(self.role, 0)
        required_level = role_hierarchy.get(required_role, 5)
        return current_level >= required_level

class LoginWindow:
    """Login interface window"""
    
    def __init__(self, db_manager, session, on_login_success):
        self.db_manager = db_manager
        self.session = session
        self.on_login_success = on_login_success
        
        self.root = tk.Tk()
        self.root.title("Employee Management System - Login")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        # Center the window
        self.center_window()
        
        self.create_widgets()
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.root.winfo_screenheight() // 2) - (300 // 2)
        self.root.geometry(f"400x300+{x}+{y}")
    
    def create_widgets(self):
        """Create login form widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Employee Management System", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Login form
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Username
        ttk.Label(form_frame, text="Username:").pack(anchor=tk.W, pady=(0, 5))
        self.username_entry = ttk.Entry(form_frame, width=30, font=("Arial", 10))
        self.username_entry.pack(pady=(0, 10))
        
        # Password
        ttk.Label(form_frame, text="Password:").pack(anchor=tk.W, pady=(0, 5))
        self.password_entry = ttk.Entry(form_frame, width=30, show="*", font=("Arial", 10))
        self.password_entry.pack(pady=(0, 20))
        
        # Login button
        login_button = ttk.Button(form_frame, text="Login", command=self.login)
        login_button.pack(pady=(0, 10))
        
        # Default credentials info
        info_frame = ttk.Frame(form_frame)
        info_frame.pack(pady=(20, 0))
        
        info_label = ttk.Label(info_frame, text="Default Login:", font=("Arial", 9, "bold"))
        info_label.pack()
        
        ttk.Label(info_frame, text="Username: admin", font=("Arial", 8)).pack()
        ttk.Label(info_frame, text="Password: admin123", font=("Arial", 8)).pack()
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.login())
        
        # Focus on username entry
        self.username_entry.focus()
    
    def login(self):
        """Handle login attempt"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        user_data = self.db_manager.authenticate_user(username, password)
        
        if user_data:
            self.session.login(user_data)
            self.root.destroy()
            self.on_login_success()
        else:
            messagebox.showerror("Error", "Invalid username or password")
            self.password_entry.delete(0, tk.END)
    
    def show(self):
        """Show the login window"""
        self.root.mainloop()

class UserManagementWindow:
    """Main user management interface"""
    
    def __init__(self, db_manager, session):
        self.db_manager = db_manager
        self.session = session
        
        self.root = tk.Tk()
        self.root.title("Employee Management System - User Management")
        self.root.geometry("1000x600")
        
        # Center the window
        self.center_window()
        
        self.create_widgets()
        self.refresh_user_list()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1000 // 2)
        y = (self.root.winfo_screenheight() // 2) - (600 // 2)
        self.root.geometry(f"1000x600+{x}+{y}")
    
    def create_widgets(self):
        """Create main interface widgets"""
        # Top frame with user info and logout
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        welcome_label = ttk.Label(top_frame, text=f"Welcome, {self.session.full_name} ({self.session.role})", 
                                 font=("Arial", 12, "bold"))
        welcome_label.pack(side=tk.LEFT)
        
        logout_button = ttk.Button(top_frame, text="Logout", command=self.logout)
        logout_button.pack(side=tk.RIGHT)
        
        # Main content frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - User list
        left_frame = ttk.LabelFrame(main_frame, text="User List", padding="5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # User list with scrollbar
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for user list
        columns = ("ID", "Name", "Username", "Email", "Department", "Role", "Manager")
        self.user_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.user_tree.heading("ID", text="ID")
        self.user_tree.heading("Name", text="Name")
        self.user_tree.heading("Username", text="Username")
        self.user_tree.heading("Email", text="Email")
        self.user_tree.heading("Department", text="Department")
        self.user_tree.heading("Role", text="Role")
        self.user_tree.heading("Manager", text="Manager")
        
        # Column widths
        self.user_tree.column("ID", width=50)
        self.user_tree.column("Name", width=150)
        self.user_tree.column("Username", width=100)
        self.user_tree.column("Email", width=150)
        self.user_tree.column("Department", width=100)
        self.user_tree.column("Role", width=80)
        self.user_tree.column("Manager", width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=scrollbar.set)
        
        self.user_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right panel - Controls
        right_frame = ttk.LabelFrame(main_frame, text="Actions", padding="5")
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        # Action buttons
        if self.session.has_permission("HR"):
            ttk.Button(right_frame, text="Add User", command=self.add_user, width=15).pack(pady=2)
        
        ttk.Button(right_frame, text="View Details", command=self.view_user, width=15).pack(pady=2)
        
        if self.session.has_permission("HR"):
            ttk.Button(right_frame, text="Edit User", command=self.edit_user, width=15).pack(pady=2)
            ttk.Button(right_frame, text="Delete User", command=self.delete_user, width=15).pack(pady=2)
        
        ttk.Separator(right_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        ttk.Button(right_frame, text="Refresh List", command=self.refresh_user_list, width=15).pack(pady=2)
        
        if self.session.has_permission("Admin"):
            ttk.Button(right_frame, text="User Statistics", command=self.show_statistics, width=15).pack(pady=2)
        
        # Bind double-click to view details
        self.user_tree.bind("<Double-1>", lambda event: self.view_user())
    
    def refresh_user_list(self):
        """Refresh the user list from database"""
        # Clear existing items
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        # Get users from database
        users = self.db_manager.get_all_users()
        
        for user in users:
            user_id, username, email, first_name, last_name, department, role, \
            manager_id, manager_name, is_active = user
            
            full_name = f"{first_name} {last_name}"
            manager_display = manager_name if manager_name else "None"
            
            self.user_tree.insert("", tk.END, values=(
                user_id, full_name, username, email, department, role, manager_display
            ))
    
    def get_selected_user(self):
        """Get the selected user from the tree"""
        selection = self.user_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user first")
            return None
        
        item = self.user_tree.item(selection[0])
        return item['values']
    
    def add_user(self):
        """Open add user dialog"""
        if not self.session.has_permission("HR"):
            messagebox.showerror("Access Denied", "You don't have permission to add users")
            return
        
        UserFormDialog(self.root, self.db_manager, self.session, None, self.refresh_user_list)
    
    def edit_user(self):
        """Open edit user dialog"""
        if not self.session.has_permission("HR"):
            messagebox.showerror("Access Denied", "You don't have permission to edit users")
            return
        
        selected_user = self.get_selected_user()
        if selected_user:
            UserFormDialog(self.root, self.db_manager, self.session, selected_user, self.refresh_user_list)
    
    def view_user(self):
        """View user details"""
        selected_user = self.get_selected_user()
        if selected_user:
            UserDetailsDialog(self.root, selected_user)
    
    def delete_user(self):
        """Delete selected user"""
        if not self.session.has_permission("HR"):
            messagebox.showerror("Access Denied", "You don't have permission to delete users")
            return
        
        selected_user = self.get_selected_user()
        if not selected_user:
            return
        
        user_id = selected_user[0]
        user_name = selected_user[1]
        
        # Confirm deletion
        if messagebox.askyesno("Confirm Deletion", 
                              f"Are you sure you want to delete user '{user_name}'?\nThis action cannot be undone."):
            if self.db_manager.delete_user(user_id):
                messagebox.showinfo("Success", "User deleted successfully")
                self.refresh_user_list()
            else:
                messagebox.showerror("Error", "Failed to delete user")
    
    def show_statistics(self):
        """Show user statistics"""
        if not self.session.has_permission("Admin"):
            messagebox.showerror("Access Denied", "You don't have permission to view statistics")
            return
        
        users = self.db_manager.get_all_users()
        
        # Calculate statistics
        total_users = len(users)
        role_counts = {}
        department_counts = {}
        
        for user in users:
            role = user[6]  # Role column
            department = user[5]  # Department column
            
            role_counts[role] = role_counts.get(role, 0) + 1
            if department:
                department_counts[department] = department_counts.get(department, 0) + 1
        
        # Create statistics window
        stats_window = tk.Toplevel(self.root)
        stats_window.title("User Statistics")
        stats_window.geometry("400x300")
        stats_window.resizable(False, False)
        
        # Center the window
        stats_window.update_idletasks()
        x = (stats_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (stats_window.winfo_screenheight() // 2) - (300 // 2)
        stats_window.geometry(f"400x300+{x}+{y}")
        
        main_frame = ttk.Frame(stats_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Total users
        ttk.Label(main_frame, text=f"Total Users: {total_users}", 
                 font=("Arial", 12, "bold")).pack(pady=(0, 10))
        
        # Role distribution
        ttk.Label(main_frame, text="Users by Role:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        for role, count in role_counts.items():
            ttk.Label(main_frame, text=f"  {role}: {count}").pack(anchor=tk.W)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Department distribution
        ttk.Label(main_frame, text="Users by Department:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        for department, count in department_counts.items():
            ttk.Label(main_frame, text=f"  {department}: {count}").pack(anchor=tk.W)
        
        ttk.Button(main_frame, text="Close", command=stats_window.destroy).pack(pady=20)
    
    def logout(self):
        """Logout current user"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.session.logout()
            self.root.destroy()
            # Restart login process
            login_window = LoginWindow(self.db_manager, self.session, self.show_main_window)
            login_window.show()
    
    def show_main_window(self):
        """Show main window after login"""
        new_window = UserManagementWindow(self.db_manager, self.session)
        new_window.show()
    
    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            self.db_manager.close_connection()
            self.root.destroy()
    
    def show(self):
        """Show the main window"""
        self.root.mainloop()

class UserFormDialog:
    """Dialog for adding/editing users"""
    
    def __init__(self, parent, db_manager, session, user_data, refresh_callback):
        self.db_manager = db_manager
        self.session = session
        self.user_data = user_data
        self.refresh_callback = refresh_callback
        self.is_edit = user_data is not None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Edit User" if self.is_edit else "Add User")
        self.dialog.geometry("400x500")
        self.dialog.resizable(False, False)
        self.dialog.grab_set()  # Make dialog modal
        
        # Center the dialog
        self.center_dialog()
        
        self.create_widgets()
        
        if self.is_edit:
            self.populate_fields()
    
    def center_dialog(self):
        """Center the dialog on parent window"""
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (500 // 2)
        self.dialog.geometry(f"400x500+{x}+{y}")
    
    def create_widgets(self):
        """Create form widgets"""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Form fields
        # Username
        ttk.Label(main_frame, text="Username:*").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=30)
        self.username_entry.pack(pady=(0, 10))
        
        # Email
        ttk.Label(main_frame, text="Email:*").pack(anchor=tk.W)
        self.email_var = tk.StringVar()
        self.email_entry = ttk.Entry(main_frame, textvariable=self.email_var, width=30)
        self.email_entry.pack(pady=(0, 10))
        
        # Password
        ttk.Label(main_frame, text=f"Password:{'*' if not self.is_edit else ' (leave empty to keep current)'}").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(pady=(0, 10))
        
        # First Name
        ttk.Label(main_frame, text="First Name:*").pack(anchor=tk.W)
        self.first_name_var = tk.StringVar()
        self.first_name_entry = ttk.Entry(main_frame, textvariable=self.first_name_var, width=30)
        self.first_name_entry.pack(pady=(0, 10))
        
        # Last Name
        ttk.Label(main_frame, text="Last Name:*").pack(anchor=tk.W)
        self.last_name_var = tk.StringVar()
        self.last_name_entry = ttk.Entry(main_frame, textvariable=self.last_name_var, width=30)
        self.last_name_entry.pack(pady=(0, 10))
        
        # Department
        ttk.Label(main_frame, text="Department:").pack(anchor=tk.W)
        self.department_var = tk.StringVar()
        department_values = ["IT", "HR", "Finance", "Marketing", "Operations", "Sales", "Other"]
        self.department_combo = ttk.Combobox(main_frame, textvariable=self.department_var, 
                                           values=department_values, width=27)
        self.department_combo.pack(pady=(0, 10))
        
        # Role
        ttk.Label(main_frame, text="Role:*").pack(anchor=tk.W)
        self.role_var = tk.StringVar()
        role_values = ["Employee", "Manager", "HR", "Admin"]
        self.role_combo = ttk.Combobox(main_frame, textvariable=self.role_var, 
                                     values=role_values, width=27, state="readonly")
        self.role_combo.pack(pady=(0, 10))
        
        # Manager
        ttk.Label(main_frame, text="Manager:").pack(anchor=tk.W)
        self.manager_var = tk.StringVar()
        self.manager_combo = ttk.Combobox(main_frame, textvariable=self.manager_var, 
                                        width=27, state="readonly")
        self.load_managers()
        self.manager_combo.pack(pady=(0, 10))
        
        # Active status
        self.is_active_var = tk.BooleanVar(value=True)
        self.active_check = ttk.Checkbutton(main_frame, text="Active User", 
                                          variable=self.is_active_var)
        self.active_check.pack(anchor=tk.W, pady=(0, 20))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        save_text = "Update" if self.is_edit else "Save"
        ttk.Button(button_frame, text=save_text, command=self.save_user).pack(side=tk.RIGHT)
        
        # Required fields note
        ttk.Label(main_frame, text="* Required fields", font=("Arial", 8), 
                 foreground="gray").pack(anchor=tk.W, pady=(10, 0))
    
    def load_managers(self):
        """Load available managers into combobox"""
        managers = self.db_manager.get_managers()
        manager_list = ["None"]
        self.manager_map = {None: None}
        
        for manager_id, manager_name in managers:
            # Don't include current user as their own manager
            if not self.is_edit or manager_id != int(self.user_data[0]):
                manager_list.append(manager_name)
                self.manager_map[manager_name] = manager_id
        
        self.manager_combo['values'] = manager_list
        self.manager_combo.set("None")
    
    def populate_fields(self):
        """Populate fields with existing user data"""
        if self.user_data:
            user_id, full_name, username, email, department, role, manager_name = self.user_data
            
            # Split full name
            name_parts = full_name.split(' ', 1)
            first_name = name_parts[0] if name_parts else ""
            last_name = name_parts[1] if len(name_parts) > 1 else ""
            
            self.username_var.set(username)
            self.email_var.set(email)
            self.first_name_var.set(first_name)
            self.last_name_var.set(last_name)
            self.department_var.set(department or "")
            self.role_var.set(role)
            
            # Set manager
            if manager_name and manager_name != "None":
                # Find the manager in the combo values
                for value in self.manager_combo['values']:
                    if manager_name in value:
                        self.manager_var.set(value)
                        break
            else:
                self.manager_var.set("None")
    
    def validate_form(self):
        """Validate form data"""
        errors = []
        
        # Required fields
        if not self.username_var.get().strip():
            errors.append("Username is required")
        
        if not self.email_var.get().strip():
            errors.append("Email is required")
        
        if not self.is_edit and not self.password_var.get():
            errors.append("Password is required for new users")
        
        if not self.first_name_var.get().strip():
            errors.append("First name is required")
        
        if not self.last_name_var.get().strip():
            errors.append("Last name is required")
        
        if not self.role_var.get():
            errors.append("Role is required")
        
        # Email format validation
        email = self.email_var.get().strip()
        if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email):
            errors.append("Please enter a valid email address")
        
        # Username format validation
        username = self.username_var.get().strip()
        if username and not re.match(r'^[a-zA-Z0-9_]+', username):
            errors.append("Username can only contain letters, numbers, and underscores")
        
        # Password strength (only for new users or when password is provided)
        password = self.password_var.get()
        if password and len(password) < 6:
            errors.append("Password must be at least 6 characters long")
        
        if errors:
            messagebox.showerror("Validation Error", "\n".join(errors))
            return False
        
        return True
    
    def save_user(self):
        """Save user data"""
        if not self.validate_form():
            return
        
        # Prepare user data
        user_data = {
            'Username': self.username_var.get().strip(),
            'Email': self.email_var.get().strip(),
            'FirstName': self.first_name_var.get().strip(),
            'LastName': self.last_name_var.get().strip(),
            'Department': self.department_var.get().strip() or None,
            'Role': self.role_var.get(),
            'IsActive': self.is_active_var.get()
        }
        
        # Handle password
        if self.password_var.get():
            user_data['Password'] = self.password_var.get()
        
        # Handle manager
        manager_selection = self.manager_var.get()
        user_data['ManagerID'] = self.manager_map.get(manager_selection)
        
        try:
            if self.is_edit:
                # Update existing user
                user_id = self.user_data[0]
                if self.db_manager.update_user(user_id, user_data):
                    messagebox.showinfo("Success", "User updated successfully")
                    self.refresh_callback()
                    self.dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to update user")
            else:
                # Add new user
                if self.db_manager.add_user(user_data):
                    messagebox.showinfo("Success", "User added successfully")
                    self.refresh_callback()
                    self.dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to add user. Username or email might already exist.")
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

class UserDetailsDialog:
    """Dialog for viewing user details"""
    
    def __init__(self, parent, user_data):
        self.user_data = user_data
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("User Details")
        self.dialog.geometry("400x350")
        self.dialog.resizable(False, False)
        self.dialog.grab_set()
        
        # Center the dialog
        self.center_dialog()
        
        self.create_widgets()
    
    def center_dialog(self):
        """Center the dialog on parent window"""
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (350 // 2)
        self.dialog.geometry(f"400x350+{x}+{y}")
    
    def create_widgets(self):
        """Create detail display widgets"""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = ttk.Label(main_frame, text="User Information", 
                         font=("Arial", 14, "bold"))
        title.pack(pady=(0, 20))
        
        # User details
        details_frame = ttk.Frame(main_frame)
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        user_id, full_name, username, email, department, role, manager_name = self.user_data
        
        # Create detail rows
        self.create_detail_row(details_frame, "User ID:", str(user_id))
        self.create_detail_row(details_frame, "Full Name:", full_name)
        self.create_detail_row(details_frame, "Username:", username)
        self.create_detail_row(details_frame, "Email:", email)
        self.create_detail_row(details_frame, "Department:", department or "Not specified")
        self.create_detail_row(details_frame, "Role:", role)
        self.create_detail_row(details_frame, "Manager:", manager_name or "None")
        
        # Close button
        ttk.Button(main_frame, text="Close", command=self.dialog.destroy).pack(pady=(20, 0))
    
    def create_detail_row(self, parent, label_text, value_text):
        """Create a detail row with label and value"""
        row_frame = ttk.Frame(parent)
        row_frame.pack(fill=tk.X, pady=2)
        
        label = ttk.Label(row_frame, text=label_text, font=("Arial", 9, "bold"), width=12)
        label.pack(side=tk.LEFT, anchor=tk.W)
        
        value = ttk.Label(row_frame, text=value_text, font=("Arial", 9))
        value.pack(side=tk.LEFT, anchor=tk.W, padx=(10, 0))

class EmployeeManagementApp:
    """Main application class"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.session = UserSession()
    
    def start(self):
        """Start the application"""
        if self.db_manager.connection and self.db_manager.connection.is_connected():
            login_window = LoginWindow(self.db_manager, self.session, self.show_main_window)
            login_window.show()
        else:
            messagebox.showerror("Database Error", 
                               "Could not connect to database. Please check your MySQL setup.")
    
    def show_main_window(self):
        """Show main application window after successful login"""
        main_window = UserManagementWindow(self.db_manager, self.session)
        main_window.show()

def main():
    """Main function to start the application"""
    print("Starting Employee Management System...")
    print("Make sure MySQL is running and accessible with the configured credentials.")
    print("Default database connection: host='localhost', user='root', password='password'")
    print("You can modify the database connection settings in the DatabaseManager class.")
    print()
    
    app = EmployeeManagementApp()
    app.start()

if __name__ == "__main__":
    main()