import tkinter as tk
from tkinter import ttk, messagebox
from password_generator import PasswordGenerator
from password_manager import PasswordManager

class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator & Manager")
        self.root.geometry("600x700")
        
        self.password_generator = PasswordGenerator()
        self.password_manager = PasswordManager()
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, expand=True)
        
        self.generator_frame = ttk.Frame(self.notebook)
        self.manager_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.generator_frame, text="Generator")
        self.notebook.add(self.manager_frame, text="Manager")
        
        self._setup_generator_tab()
        self._setup_manager_tab()

    def _setup_generator_tab(self):
        ttk.Label(self.generator_frame, text="Password Generation Options", font=('Helvetica', 12, 'bold')).pack(pady=10)
        length_frame = ttk.Frame(self.generator_frame)
        length_frame.pack(pady=5)
        ttk.Label(length_frame, text="Length:").pack(side=tk.LEFT)
        self.length_var = tk.StringVar(value="12")
        self.length_entry = ttk.Entry(length_frame, textvariable=self.length_var, width=5)
        self.length_entry.pack(side=tk.LEFT, padx=5)
        
        self.uppercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.special_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(self.generator_frame, text="Include Uppercase", variable=self.uppercase_var).pack(pady=5)
        ttk.Checkbutton(self.generator_frame, text="Include Numbers", variable=self.digits_var).pack(pady=5)
        ttk.Checkbutton(self.generator_frame, text="Include Special Characters", variable=self.special_var).pack(pady=5)
        
        ttk.Button(self.generator_frame, text="Generate Password", command=self.generate_password).pack(pady=10)
        
        self.password_var = tk.StringVar()
        password_frame = ttk.Frame(self.generator_frame)
        password_frame.pack(pady=10, fill=tk.X, padx=20)
        
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, font=('Courier', 12))
        self.password_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        ttk.Button(password_frame, text="Copy", command=self.copy_password).pack(side=tk.LEFT, padx=5)
        
        self.strength_frame = ttk.LabelFrame(self.generator_frame, text="Password Strength")
        self.strength_frame.pack(pady=10, padx=20, fill=tk.X)
        
        self.strength_label = ttk.Label(self.strength_frame, text="")
        self.strength_label.pack(pady=5)
        
        self.feedback_label = ttk.Label(self.strength_frame, text="")
        self.feedback_label.pack(pady=5)

    def _setup_manager_tab(self):
        ttk.Label(self.manager_frame, text="Password Manager", font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        entry_frame = ttk.Frame(self.manager_frame)
        entry_frame.pack(pady=10, padx=20, fill=tk.X)
        
        ttk.Label(entry_frame, text="Service:").grid(row=0, column=0, pady=5)
        self.service_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.service_var).grid(row=0, column=1, pady=5, sticky='ew')
        
        ttk.Label(entry_frame, text="Username:").grid(row=1, column=0, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.username_var).grid(row=1, column=1, pady=5, sticky='ew')
        
        ttk.Label(entry_frame, text="Password:").grid(row=2, column=0, pady=5)
        self.manager_password_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=self.manager_password_var, show="*").grid(row=2, column=1, pady=5, sticky='ew')
        
        entry_frame.grid_columnconfigure(1, weight=1)
        
        button_frame = ttk.Frame(self.manager_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Save", command=self.save_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=self.delete_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Show/Hide", command=self.toggle_password_visibility).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.manager_frame, text="Stored Passwords", font=('Helvetica', 10, 'bold')).pack(pady=10)
        
        self.password_listbox = tk.Listbox(self.manager_frame, height=10)
        self.password_listbox.pack(pady=5, padx=20, fill=tk.X)
        self.password_listbox.bind('<<ListboxSelect>>', self.on_select_password)
        
        self.refresh_password_list()

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 8:
                messagebox.showwarning("Warning", "Password length should be at least 8 characters")
                return
            
            password = self.password_generator.generate_password(
                length=length,
                use_uppercase=self.uppercase_var.get(),
                use_digits=self.digits_var.get(),
                use_special=self.special_var.get()
            )
            
            self.password_var.set(password)
            self.check_password_strength(password)
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for length")

    def check_password_strength(self, password):
        result = self.password_generator.check_password_strength(password)
        self.strength_label.config(text=f"Strength: {result['strength']}")
        self.feedback_label.config(text="\n".join(result['feedback']))

    def copy_password(self):
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")

    def save_password(self):
        service = self.service_var.get().strip()
        username = self.username_var.get().strip()
        password = self.manager_password_var.get()
        
        if not all([service, username, password]):
            messagebox.showwarning("Warning", "Please fill in all fields")
            return
            
        self.password_manager.add_password(service, username, password)
        self.refresh_password_list()
        messagebox.showinfo("Success", "Password saved successfully!")
        
        self.service_var.set("")
        self.username_var.set("")
        self.manager_password_var.set("")

    def delete_password(self):
        service = self.service_var.get().strip()
        if not service:
            messagebox.showwarning("Warning", "Please select a password to delete")
            return
            
        if messagebox.askyesno("Confirm", f"Delete password for {service}?"):
            if self.password_manager.delete_password(service):
                self.refresh_password_list()
                messagebox.showinfo("Success", "Password deleted successfully!")
                
                self.service_var.set("")
                self.username_var.set("")
                self.manager_password_var.set("")

    def refresh_password_list(self):
        self.password_listbox.delete(0, tk.END)
        for service in self.password_manager.get_all_services():
            self.password_listbox.insert(tk.END, service)

    def on_select_password(self, event):
        selection = self.password_listbox.curselection()
        if selection:
            service = self.password_listbox.get(selection[0])
            password_data = self.password_manager.get_password(service)
            
            self.service_var.set(service)
            self.username_var.set(password_data["username"])
            self.manager_password_var.set(password_data["password"])

    def toggle_password_visibility(self):
        current_show = self.manager_password_var.get()
        entry_widgets = [widget for widget in self.manager_frame.winfo_children() 
                        if isinstance(widget, ttk.Frame)]
        
        for frame in entry_widgets:
            for widget in frame.winfo_children():
                if isinstance(widget, ttk.Entry) and widget.cget("show") == "*":
                    widget.config(show="")
                elif isinstance(widget, ttk.Entry) and widget.cget("show") == "":
                    widget.config(show="*")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop() 