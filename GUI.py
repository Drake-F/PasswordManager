import secrets
import string
import tkinter as tk
import json
from tkinter import ttk, messagebox, filedialog
from PasswordGenerator import generate_password
from Encryption import encrypt_file, decrypt_file

# Make a way for new users to create their first encrypted file - part of the installer/startup?
# Finally, make it a desktop icon and package it all for github

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("920x650")
        self.root.minsize(820, 580)

        self.entries = []
        self.session_active = False
        self.clipboard_clear_job = None

        self.vault_data = None
        self.vault_modified = False

        self._configure_style()
        self._build_layout()

    def _configure_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Title.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 9))
        style.configure("Action.TButton", padding=(10, 6))
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_layout(self):
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=1, uniform="columns")
        outer.columnconfigure(1, weight=1, uniform="columns")
        outer.rowconfigure(0, weight=0)
        outer.rowconfigure(1, weight=1)

        self._build_vault_panel(outer)
        self._build_generator_panel(outer)
        self._build_add_panel(outer)
        self._build_entries_panel(outer)

    def _panel(self, parent, title, row, column):
        frame = ttk.LabelFrame(parent, text=title, padding=12)
        frame.grid(
            row=row, column=column, sticky="nsew",
            padx=(0, 6) if column == 0 else (6, 0),
            pady=(0, 6) if row == 0 else (6, 0)
        )
        return frame

    def _build_vault_panel(self, parent):
        frame = self._panel(parent, "Vault Controls", 0, 0)
        frame.columnconfigure(1, weight=1)

        # Vault file selection
        ttk.Label(frame, text="Vault File:").grid(
            row=0, column=0, sticky="w", padx=(0, 8), pady=5
        )

        self.vault_path = tk.StringVar()

        self.vault_path_entry = ttk.Entry(
            frame,
            textvariable=self.vault_path,
            state="readonly"
        )
        self.vault_path_entry.grid(
            row=0, column=1, sticky="ew", pady=5
        )

        self.browse_button = ttk.Button(
            frame,
            text="Browse",
            command=self.browse_vault
        )
        self.browse_button.grid(
            row=0, column=2, padx=(5, 0), pady=5
        )

        # Vault password
        ttk.Label(frame, text="Vault Password:").grid(
            row=1, column=0, sticky="w", padx=(0, 8), pady=5
        )

        self.master_password = tk.StringVar()

        self.master_entry = ttk.Entry(
            frame,
            textvariable=self.master_password,
            show="*"
        )
        self.master_entry.grid(
            row=1, column=1, sticky="ew", pady=5
        )

        self.master_entry.bind(
            "<Return>", lambda _event: self.toggle_session()
        )

        self.master_visibility_button = ttk.Button(
            frame,
            text="Show",
            command=lambda: self.toggle_password_visibility(
                self.master_entry,
                self.master_visibility_button
            )
        )
        self.master_visibility_button.grid(row=1, column=2, padx=(5, 0), pady=5)

        # Lock / Unlock controls
        self.unlock_button = ttk.Button(
            frame,
            text="Unlock Vault",
            style="Action.TButton",
            command=self.toggle_session
        )
        self.unlock_button.grid(
            row=2, column=0, columnspan=3,
            sticky="ew", padx=35, pady=10
        )

        # Session status
        self.vault_status = tk.StringVar(
            value="Session Status: Locked"
        )

        ttk.Label(
            frame,
            textvariable=self.vault_status,
            style="Status.TLabel"
        ).grid(
            row=3, column=0, columnspan=3, sticky="w"
        )
    
    def browse_vault(self):
        file_path = filedialog.askopenfilename(
            title="Select Vault File",
            filetypes=[("All Files", "*.*")]
        )

        if file_path:
            self.vault_path.set(file_path)

    def load_vault_file(self):
        # Decrypt selected vault
        plaintext = decrypt_file(
            self.vault_path.get(),
            self.master_password.get()
        )

        # Parse decrypted JSON data
        vault_data = self.parse_vault_data(plaintext)

        # Keep decrypted data in memory
        self.vault_data = vault_data

        # Clear existing entries
        self.tree.delete(*self.tree.get_children())
        self.entries = None

        # Populate entries from parsed data
        self.entries = self.vault_data["entries"]

        for index, entry in enumerate(self.entries):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    entry["site"],
                    entry["username"]
                )
            )

    def _build_generator_panel(self, parent):
        frame = self._panel(parent, "Password Generator", 0, 1)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Length:").grid(row=0, column=0, sticky="w", pady=4)
        self.length_var = tk.StringVar(value="12")
        ttk.Entry(frame, textvariable=self.length_var, width=9).grid(
            row=0, column=1, sticky="w", pady=4
        )

        self.upper_var = tk.BooleanVar(value=False)
        self.lower_var = tk.BooleanVar(value=False)
        self.num_var = tk.BooleanVar(value=False)
        self.special_var = tk.BooleanVar(value=False)
        self.super_var = tk.BooleanVar(value=False)

        options = [
            ("Uppercase Letters", self.upper_var),
            ("Lowercase Letters", self.lower_var),
            ("Numbers", self.num_var),
            ("Special Characters", self.special_var),
            ("Super Special Characters", self.super_var),
        ]

        for row, (label, variable) in enumerate(options, start=1):
            ttk.Label(frame, text=label + ":").grid(
                row=row, column=0, sticky="w", pady=2
            )
            ttk.Checkbutton(frame, variable=variable).grid(
                row=row, column=1, sticky="w", pady=2
            )

        # Generated password - row 6
        ttk.Label(frame, text="Generated Password:").grid(
            row=6, column=0, sticky="w", pady=(10, 4)
        )

        self.generated_var = tk.StringVar()
        self.generated_entry = ttk.Entry(
            frame, textvariable=self.generated_var
        )
        self.generated_entry.grid(
            row=6, column=1, sticky="ew", pady=(10, 4)
        )

        # Buttons - row 7
        actions = ttk.Frame(frame)
        actions.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(5, 0))

        ttk.Button(
            actions, text="Generate", command=self.gen_pass
        ).pack(side="left", expand=True, fill="x", padx=(0, 4))

        ttk.Button(
            actions, text="Copy", command=self.copy_generated
        ).pack(side="left", expand=True, fill="x", padx=(4, 4))
        
        ttk.Button(
            actions, text="Clear", command=self.clear_generated_password
        ).pack(side="left", expand=True, fill="x", padx=(4, 0))

    def gen_pass(self):
        try:
            length = int(self.length_var.get())

            password = generate_password(length, self.upper_var.get(), self.lower_var.get(), self.num_var.get(), self.special_var.get(), self.super_var.get())
            self.generated_var.set(password)

        except ValueError as error:
            messagebox.showerror("Password Generation Error: ", str(error))

    def _build_add_panel(self, parent):
        frame = self._panel(parent, "Add Entry", 1, 0)
        frame.columnconfigure(1, weight=1)

        self.site_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        # Site
        ttk.Label(frame, text="Site / URL:").grid(
            row=0, column=0, sticky="e", padx=(0, 8), pady=6
        )
        self.site_entry = ttk.Entry(frame, textvariable=self.site_var)
        self.site_entry.grid(row=0, column=1, sticky="ew", pady=6)

        # Username
        ttk.Label(frame, text="User:").grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=6
        )
        self.username_entry = ttk.Entry(frame, textvariable=self.username_var)
        self.username_entry.grid(row=1, column=1, sticky="ew", pady=6)

        # Password
        ttk.Label(frame, text="Pass:").grid(
            row=2, column=0, sticky="e", padx=(0, 8), pady=6
        )

        self.password_entry = ttk.Entry(
            frame, textvariable=self.password_var, show="*"
        )
        self.password_entry.grid(row=2, column=1, sticky="ew", pady=6)

        # Password visibility toggle
        self.password_visibility_button = ttk.Button(
            frame,
            text="Show",
            command=lambda: self.toggle_password_visibility(
                self.password_entry,
                self.password_visibility_button
            )
        )
        
        self.password_visibility_button.grid(row=3, column=0, columnspan=2, sticky="ew", padx=25)

        ttk.Button(
            frame, text="Add Entry", style="Action.TButton",
            command=self.add_entry
        ).grid(row=4, column=0, columnspan=2, sticky="ew", padx=25, pady=14)

        ttk.Button(
            frame, text="Use Generated Password",
            command=self.use_generated_password
        ).grid(row=5, column=0, columnspan=2, sticky="ew", padx=25)

    def _build_entries_panel(self, parent):
        frame = self._panel(parent, "Entries", 1, 1)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        columns = ("site", "username")
        self.tree = ttk.Treeview(
            frame, columns=columns, show="headings", selectmode="browse"
        )
        self.tree.heading("site", text="Site")
        self.tree.heading("username", text="Username")
        self.tree.column("site", width=190, anchor="w")
        self.tree.column("username", width=170, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_entry)

        details = ttk.LabelFrame(frame, text="Selected Entry", padding=8)
        details.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        details.columnconfigure(1, weight=1)

        self.detail_site = tk.StringVar()
        self.detail_user = tk.StringVar()
        self.detail_pass = tk.StringVar()

        # Entry Details fields
        for row, (label, variable) in enumerate([
            ("Site:", self.detail_site),
            ("User:", self.detail_user),
            ("Pass:", self.detail_pass),
        ]):
            ttk.Label(details, text=label).grid(
                row=row, column=0, sticky="e", padx=(0, 8), pady=3
            )

            if variable == self.detail_pass:
                entry = ttk.Entry(
                    details, textvariable=variable,
                    state="readonly", show="*"
                )
                self.detail_password_entry = entry
            else:
                entry = ttk.Entry(
                    details, textvariable=variable, state="readonly"
                )

            entry.grid(row=row, column=1, sticky="ew", pady=3)

        # Action Buttons area
        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        # Show / Hide Password (full width)
        self.detail_password_visibility_button = ttk.Button(
            buttons,
            text="Show Password",
            command=lambda: self.toggle_password_visibility(
                self.detail_password_entry,
                self.detail_password_visibility_button
            )
        )
        self.detail_password_visibility_button.grid(
            row=0, column=0, columnspan=3, sticky="ew", pady=(0, 5)
        )

        # Three existing action buttons
        ttk.Button(
            buttons, text="Copy Username",
            command=lambda: self.copy_text(self.detail_user.get())
        ).grid(row=1, column=0, sticky="ew", padx=(0, 4))

        ttk.Button(
            buttons, text="Copy Password",
            command=lambda: self.copy_text(self.detail_pass.get())
        ).grid(row=1, column=1, sticky="ew", padx=4)

        ttk.Button(
            buttons, text="Delete Entry",
            command=self.delete_entry
        ).grid(row=1, column=2, sticky="ew", padx=(4, 0))

        # Make all three action columns expand equally
        for column in range(3):
            buttons.columnconfigure(column, weight=1)

    def toggle_session(self):

        # Unlock vault
        if not self.session_active:

            if not self.vault_path.get():
                messagebox.showwarning(
                    "No Vault Selected",
                    "Please select a vault file first."
                )
                return

            if not self.master_password.get():
                messagebox.showwarning(
                    "Password Required",
                    "Please enter your master password."
                )
                return

            try:
                self.load_vault_file()

            except Exception as error:
                messagebox.showerror(
                    "Vault Loading Error",
                    str(error)
                )
                return

            self.session_active = True
            self.vault_status.set("Session Status: Unlocked")
            self.unlock_button.configure(text="Lock Vault")
            self.master_entry.configure(state="disabled")
            self.browse_button.configure(state="disabled")

        # Lock vault
        else:
            self.session_active = False

            # Check to see if we need to update the encrypted file and clear the information stored in memory
            self.update_file()

            # Clear stored data
            self.vault_data = None
            self.entries = None
            self.master_password.set("")
            self.vault_status.set("Session Status: Locked")

            self.unlock_button.configure(text="Unlock Vault")
            self.master_entry.configure(state="normal")
            self.browse_button.configure(state="normal")

            # Clear loaded entries
            self.tree.delete(*self.tree.get_children())
            self.clear_selected_details()

    def update_file(self):
        if self.vault_modified == True:
            plaintext = json.dumps(
                self.vault_data,
                ensure_ascii=False,
                indent=4
            ).encode("utf-8")
            print(plaintext)
            print(type(plaintext))
            print(self.entries)
            print(type(self.entries))

            encrypt_file(
                self.vault_path.get(),
                self.master_password.get(),
                plaintext
                )

        self.vault_modified = False

    def parse_vault_data(self, plaintext: bytes):
        try:
            vault_data = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Vault contains invalid or unreadable data.") from error

        if not isinstance(vault_data, dict):
            raise ValueError("Invalid vault structure.")

        if vault_data.get("version") != 1:
            raise ValueError("Unsupported vault version.")

        entries = vault_data.get("entries")

        if not isinstance(entries, list):
            raise ValueError("Vault entries must be a list.")

        required_fields = ("site", "username", "password")

        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"Entry {index + 1} is invalid.")

            for field in required_fields:
                if not isinstance(entry.get(field), str):
                    raise ValueError(
                        f"Entry {index + 1} has an invalid {field} field."
                    )

            if "url" in entry and not isinstance(entry["url"], str):
                raise ValueError(f"Entry {index + 1} has an invalid URL.")

            entry.setdefault("url", "")

        return vault_data

    def copy_generated(self):
        value = self.generated_var.get()
        if not value:
            messagebox.showinfo("Nothing to Copy", "Generate a password first.")
            return
        self.copy_text(value)

    def copy_text(self, value):
        if not value:
            messagebox.showinfo("Nothing to Copy", "There is no value to copy.")
            return

        # Cancel any previously scheduled clipboard clearing
        if self.clipboard_clear_job:
            self.root.after_cancel(self.clipboard_clear_job)

        self.root.clipboard_clear()
        self.root.clipboard_append(value)

        # Schedule clipboard clearing after 30 seconds
        self.clipboard_clear_job = self.root.after(
            30000,
            lambda: self.clear_clipboard(value)
        )

    def clear_clipboard(self, copied_value):
        try:
            # Only clear if the clipboard still contains our password
            if self.root.clipboard_get() == copied_value:
                self.root.clipboard_clear()
        except tk.TclError:
            pass

        self.clipboard_clear_job = None

    def use_generated_password(self):
        value = self.generated_var.get()
        if not value:
            messagebox.showinfo("No Generated Password", "Generate a password first.")
            return
        self.password_var.set(value)

    def add_entry(self):
        if not self.session_active:
            messagebox.showwarning(
                "Session Inactive", "Start a session before adding entries."
            )
            return

        site = self.site_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not site or not username or not password:
            messagebox.showwarning(
                "Missing Information", "Enter a site, username, and password."
            )
            return

        self.entries.append({
            "site": site,
            "username": username,
            "password": password,
        })
        item_id = str(len(self.entries) - 1)
        self.tree.insert("", "end", iid=item_id, values=(site, username))
        self.clear_entry_fields()
        self.vault_modified = True

    def show_selected_entry(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if index >= len(self.entries):
            return
        entry = self.entries[index]
        self.detail_site.set(entry["site"])
        self.detail_user.set(entry["username"])
        self.detail_pass.set(entry["password"])

    def delete_entry(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Select an entry to delete.")
            return
        index = int(selection[0])
        if not messagebox.askyesno(
            "Delete Entry", "Permanently remove this entry from the current session?"
        ):
            return

        self.entries.pop(index)
        self.tree.delete(selection[0])
        self.clear_selected_details()
        self.vault_modified = True

    def clear_entry_fields(self):
        self.site_var.set("")
        self.username_var.set("")
        self.password_var.set("")

    def clear_selected_details(self):
        self.detail_site.set("")
        self.detail_user.set("")
        self.detail_pass.set("")
    
    def clear_generated_password(self):
        self.generated_entry.delete(0, tk.END)

    def toggle_password_visibility(self, entry, button):
        if entry.cget("show") == "*":
            entry.configure(show="")
            button.configure(text="Hide")
        else:
            entry.configure(show="*")
            button.configure(text="Show")

root = tk.Tk()
app = PasswordManagerGUI(root)
root.mainloop()