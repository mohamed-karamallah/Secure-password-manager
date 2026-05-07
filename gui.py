import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import elgamal
from modules import vault
from modules import export

# ── colours ──
BG       = "#1e1e2e"
SURFACE  = "#2a2a3d"
ACCENT   = "#7c3aed"
ACCENT2  = "#a78bfa"
TEXT     = "#e2e8f0"
MUTED    = "#94a3b8"
SUCCESS  = "#22c55e"
DANGER   = "#ef4444"
BORDER   = "#3f3f5c"
ENTRY_BG = "#33334d"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Password Manager")
        self.configure(bg=BG)
        self.geometry("720x560")
        self.resizable(False, False)

        self.current_user = None
        self.current_pw   = None

        self._build_styles()
        self._build_login_screen()

    # ── ttk styles ──
    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TFrame",   background=BG)
        style.configure("TLabel",   background=BG, foreground=TEXT,
                         font=("Segoe UI", 11))
        style.configure("Title.TLabel", background=BG, foreground=TEXT,
                         font=("Segoe UI", 18, "bold"))
        style.configure("Sub.TLabel", background=BG, foreground=MUTED,
                         font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=SURFACE)

        style.configure("Accent.TButton", background=ACCENT,
                         foreground="white", font=("Segoe UI", 11, "bold"),
                         padding=(16, 8))
        style.map("Accent.TButton",
                  background=[("active", ACCENT2)])

        style.configure("Danger.TButton", background=DANGER,
                         foreground="white", font=("Segoe UI", 10, "bold"),
                         padding=(12, 6))
        style.map("Danger.TButton",
                  background=[("active", "#dc2626")])

        style.configure("Small.TButton", background=SURFACE,
                         foreground=TEXT, font=("Segoe UI", 10),
                         padding=(12, 6), bordercolor=BORDER)
        style.map("Small.TButton",
                  background=[("active", BORDER)])

    # ── helpers ──
    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def _make_entry(self, parent, label, show=None, row=0):
        ttk.Label(parent, text=label, style="Sub.TLabel").grid(
            row=row, column=0, sticky="w", pady=(8, 2))
        entry = tk.Entry(parent, show=show, font=("Segoe UI", 11),
                         bg=ENTRY_BG, fg=TEXT, insertbackground=TEXT,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightcolor=ACCENT, highlightbackground=BORDER)
        entry.grid(row=row + 1, column=0, sticky="ew", ipady=6)
        return entry

    def _status(self, msg, colour=SUCCESS):
        if hasattr(self, "status_var"):
            self.status_var.set(msg)
            self.status_label.configure(foreground=colour)

    # ══════════════════════════════════════════════
    #  LOGIN / REGISTER SCREEN
    # ══════════════════════════════════════════════
    def _build_login_screen(self):
        self._clear()
        frame = ttk.Frame(self, style="TFrame")
        frame.place(relx=0.5, rely=0.45, anchor="center")

        ttk.Label(frame, text="🔒 Secure Password Manager",
                  style="Title.TLabel").grid(row=0, column=0, columnspan=2,
                                              pady=(0, 4))
        ttk.Label(frame, text="Login or create a new user",
                  style="Sub.TLabel").grid(row=1, column=0, columnspan=2,
                                            pady=(0, 20))

        self.login_user = self._make_entry(frame, "Username", row=2)
        self.login_pw   = self._make_entry(frame, "Master Password",
                                           show="•", row=4)
        frame.columnconfigure(0, minsize=320)

        btn_frame = ttk.Frame(frame, style="TFrame")
        btn_frame.grid(row=6, column=0, pady=(20, 0), sticky="ew")
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        ttk.Button(btn_frame, text="Login", style="Accent.TButton",
                   command=self._do_login).grid(row=0, column=0,
                                                 padx=(0, 6), sticky="ew")
        ttk.Button(btn_frame, text="Register", style="Small.TButton",
                   command=self._do_register).grid(row=0, column=1,
                                                    padx=(6, 0), sticky="ew")

        self.login_msg = ttk.Label(frame, text="", style="Sub.TLabel")
        self.login_msg.grid(row=7, column=0, pady=(12, 0))

    def _do_register(self):
        uname = self.login_user.get().strip()
        pw    = self.login_pw.get().strip()
        if not uname or not pw:
            self.login_msg.configure(text="Fill in both fields.", foreground=DANGER)
            return
        try:
            elgamal.initialize_user(uname)
            vault.create_vault(uname, pw)
            self.login_msg.configure(
                text=f"User '{uname}' created! You can now login.",
                foreground=SUCCESS)
        except Exception as e:
            self.login_msg.configure(text=str(e), foreground=DANGER)

    def _do_login(self):
        uname = self.login_user.get().strip()
        pw    = self.login_pw.get().strip()
        if not uname or not pw:
            self.login_msg.configure(text="Fill in both fields.", foreground=DANGER)
            return
        try:
            vault.load_vault(uname, pw)
            self.current_user = uname
            self.current_pw   = pw
            self._build_dashboard()
        except Exception as e:
            self.login_msg.configure(text=str(e), foreground=DANGER)

    # ══════════════════════════════════════════════
    #  DASHBOARD
    # ══════════════════════════════════════════════
    def _build_dashboard(self):
        self._clear()

        # top bar
        top = ttk.Frame(self, style="TFrame")
        top.pack(fill="x", padx=20, pady=(16, 0))
        ttk.Label(top, text=f"🔓  {self.current_user}'s Vault",
                  style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Logout", style="Small.TButton",
                   command=self._logout).pack(side="right")

        # status bar
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(self, textvariable=self.status_var,
                                       style="Sub.TLabel")
        self.status_label.pack(fill="x", padx=20, pady=(4, 0))

        # credential list
        list_frame = ttk.Frame(self, style="Card.TFrame")
        list_frame.pack(fill="both", expand=True, padx=20, pady=(12, 0))

        columns = ("website", "username", "password")
        self.tree = ttk.Treeview(list_frame, columns=columns,
                                  show="headings", height=12)
        self.tree.heading("website",  text="Website")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password")
        self.tree.column("website",  width=200)
        self.tree.column("username", width=220)
        self.tree.column("password", width=200)

        # treeview colours
        style = ttk.Style()
        style.configure("Treeview",
                         background=SURFACE, foreground=TEXT,
                         fieldbackground=SURFACE, rowheight=28,
                         font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                         background=BORDER, foreground=TEXT,
                         font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)])

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical",
                                   command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # bottom buttons
        btn_bar = ttk.Frame(self, style="TFrame")
        btn_bar.pack(fill="x", padx=20, pady=(12, 16))

        buttons = [
            ("Add",    self._add_cred),
            ("View",   self._view_cred),
            ("Update", self._update_cred),
            ("Delete", self._delete_cred),
            ("Export", self._export_vault),
        ]
        for i, (label, cmd) in enumerate(buttons):
            s = "Danger.TButton" if label == "Delete" else "Small.TButton"
            ttk.Button(btn_bar, text=label, style=s,
                       command=cmd).grid(row=0, column=i, padx=4, sticky="ew")
            btn_bar.columnconfigure(i, weight=1)

        self._refresh_list()

    def _refresh_list(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        try:
            creds = vault.load_vault(self.current_user, self.current_pw)
            for c in creds:
                masked_pw = "•" * len(c["password"])
                self.tree.insert("", "end",
                                  values=(c["website"], c["username"], masked_pw))
        except Exception as e:
            self._status(str(e), DANGER)

    def _logout(self):
        self.current_user = None
        self.current_pw   = None
        self._build_login_screen()

    # ── credential actions ──
    def _add_cred(self):
        win = tk.Toplevel(self)
        win.title("Add Credential")
        win.configure(bg=BG)
        win.geometry("360x280")
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        f = ttk.Frame(win, style="TFrame")
        f.pack(padx=20, pady=20, fill="both")
        f.columnconfigure(0, weight=1)

        e_site = self._make_entry(f, "Website", row=0)
        e_user = self._make_entry(f, "Username / Email", row=2)
        e_pw   = self._make_entry(f, "Password", show="•", row=4)

        def save():
            try:
                vault.add_credential(self.current_user, self.current_pw,
                                     e_site.get().strip(),
                                     e_user.get().strip(),
                                     e_pw.get().strip())
                self._refresh_list()
                self._status("Credential added.", SUCCESS)
                win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=win)

        ttk.Button(f, text="Save", style="Accent.TButton",
                   command=save).grid(row=6, column=0, pady=(16, 0), sticky="ew")

    def _view_cred(self):
        sel = self.tree.selection()
        if not sel:
            self._status("Select a credential first.", MUTED)
            return
        website = self.tree.item(sel[0])["values"][0]
        try:
            entry = vault.get_credential(self.current_user, self.current_pw,
                                          website)
            if entry:
                messagebox.showinfo(
                    "Credential",
                    f"Website:   {entry['website']}\n"
                    f"Username: {entry['username']}\n"
                    f"Password:  {entry['password']}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _update_cred(self):
        sel = self.tree.selection()
        if not sel:
            self._status("Select a credential first.", MUTED)
            return
        website = self.tree.item(sel[0])["values"][0]
        new_pw = simpledialog.askstring("Update Password",
                                        f"New password for {website}:",
                                        show="•", parent=self)
        if new_pw:
            try:
                vault.update_credential(self.current_user, self.current_pw,
                                        website, new_pw)
                self._refresh_list()
                self._status(f"Password updated for {website}.", SUCCESS)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _delete_cred(self):
        sel = self.tree.selection()
        if not sel:
            self._status("Select a credential first.", MUTED)
            return
        website = self.tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm", f"Delete '{website}'?"):
            try:
                vault.delete_credential(self.current_user, self.current_pw,
                                        website)
                self._refresh_list()
                self._status(f"Deleted {website}.", SUCCESS)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _export_vault(self):
        win = tk.Toplevel(self)
        win.title("Export Vault")
        win.configure(bg=BG)
        win.geometry("360x240")
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        f = ttk.Frame(win, style="TFrame")
        f.pack(padx=20, pady=20, fill="both")
        f.columnconfigure(0, weight=1)

        e_recv = self._make_entry(f, "Receiver Username", row=0)
        e_rpw  = self._make_entry(f, "Receiver Master Password",
                                  show="•", row=2)

        def do_export():
            recv = e_recv.get().strip()
            rpw  = e_rpw.get().strip()
            if not recv or not rpw:
                messagebox.showwarning("Missing Fields",
                                       "Fill in both fields.", parent=win)
                return
            win.configure(cursor="wait")
            win.update()
            try:
                result = export.export_vault(
                    self.current_user, self.current_pw, recv, rpw)
                win.configure(cursor="")
                messagebox.showinfo(
                    "Export Complete",
                    f"Successfully exported {len(result)} credential(s) "
                    f"to '{recv}'.", parent=win)
                self._status(f"Vault exported to {recv}.", SUCCESS)
                win.destroy()
            except Exception as e:
                win.configure(cursor="")
                messagebox.showerror("Export Failed", str(e), parent=win)

        ttk.Button(f, text="Export", style="Accent.TButton",
                   command=do_export).grid(row=4, column=0,
                                            pady=(16, 0), sticky="ew")


if __name__ == "__main__":
    app = App()
    app.mainloop()
