"""Graphical launcher for the B&R OPC UA BrowsePath Finder."""
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import sys

from opcua_browse import (
    SECURITY_MODES, SECURITY_POLICIES,
    escape_browse_name, validate_endpoint, BrowserSession, ROOT_PREFIX,
)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.iconbitmap(str(resource_path("assets/ASImage.ico")))
        self.title("B&R OPC UA BrowsePath Finder")
        self.geometry("950x850")
        self.minsize(740, 760)
        self.events = queue.Queue()
        self.endpoint = tk.StringVar(value="opc.tcp://127.0.0.1:4840")
        self.mode = tk.StringVar(value="None")
        self.policy = tk.StringVar(value="None")
        self.identity = tk.StringVar(value="Anonymous")
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.commands = queue.Queue()
        self.connected = False
        self.nodes = {}
        self.pending = set()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.found_type = tk.StringVar()
        self.relative_path = tk.StringVar()
        self.status = tk.StringVar(value="Ready")
        self.matches = []
        self.namespace_uris = []
        self.namespace_mapping = {}
        self._build()
        self.after(100, self._drain)

    def _build(self):
        main = ttk.Frame(self, padding=16)
        main.pack(fill="both", expand=True)
        ttk.Label(main, text="OPC UA connection", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._entry(main, "ServerEndpointUrl", self.endpoint)
        line = ttk.Frame(main)
        line.pack(fill="x", pady=5)
        for label, value, choices in (("SecurityMessageMode", self.mode, SECURITY_MODES), ("SecurityPolicy", self.policy, SECURITY_POLICIES)):
            group = ttk.Frame(line)
            group.pack(side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Label(group, text=label).pack(anchor="w")
            ttk.Combobox(group, textvariable=value, values=choices, state="readonly").pack(fill="x")
        ttk.Label(main, text="UserIdentityToken").pack(anchor="w", pady=(6, 0))
        auth = ttk.Frame(main)
        auth.pack(fill="x")
        for name in ("Anonymous", "Username"):
            ttk.Radiobutton(auth, text=name, variable=self.identity, value=name, command=self._show_auth).pack(side="left", padx=(0, 15))
        self.auth_frame = ttk.Frame(main)
        self.auth_frame.pack(fill="x")
        self._show_auth()
        ttk.Separator(main).pack(fill="x", pady=12)
        ttk.Label(main, text="Variable lookup", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        # Use a prominent native Tk button instead of the theme-dependent ttk style.
        self.go = tk.Button(
            main,
            text="Connect",
            width=14,
            command=self._start,
            bg="#FF8800",
            fg="white",
            activebackground="#FF8800",
            activeforeground="white",
            font=("Segoe UI", 10, "bold"),
            relief="raised",
            borderwidth=2,
            padx=18,
            pady=10,
            cursor="hand2",
        )
        self.go.pack(anchor="center", pady=(10, 8))
        self.disconnect = tk.Button(
            main,
            text="Disconnect",
            width=14,
            command=self._disconnect,
            state="disabled",
            bg="#FF8800",
            fg="white",
            activebackground="#FF8800",
            activeforeground="white",
            font=("Segoe UI", 10, "bold"),
            relief="raised",
            borderwidth=2,
            padx=18,
            pady=10,
            cursor="hand2",
        )
        self.disconnect.pack()
        browser = ttk.Frame(main)
        browser.pack(fill="x", expand=True, pady=6)
        self.tree = ttk.Treeview(browser, columns=("kind",), selectmode="browse", height=6)
        self.tree.heading("#0", text="Browse server — expand folders and select a variable")
        self.tree.heading("kind", text="Node class")
        self.tree.column("kind", width=110, stretch=False)
        scroll = ttk.Scrollbar(browser, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewOpen>>", self._expand)
        self.tree.bind("<<TreeviewSelect>>", self._select)
        self.bar = ttk.Progressbar(main, mode="indeterminate")
        self.bar.pack(fill="x", pady=(7, 3))
        ttk.Label(main, textvariable=self.status).pack(anchor="w")
        ttk.Separator(main).pack(fill="x", pady=12)
        ttk.Label(main, text="Result — OpcUa_any configuration", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self._entry(main, "Detected B&R data type", self.found_type, readonly=True)
        ttk.Label(main, text="StartingNode (leave empty in OpcUa_any)").pack(anchor="w", pady=(5, 0))
        self._result_entry(main, "RelativePath (complete path from Root)", self.relative_path)

    def _entry(self, parent, name, var, readonly=False):
        ttk.Label(parent, text=name).pack(anchor="w", pady=(5, 0))
        widget = ttk.Entry(parent, textvariable=var, state="readonly" if readonly else "normal")
        widget.pack(fill="x", pady=(1, 3))
        return widget

    def _result_entry(self, parent, label, variable):
        ttk.Label(parent, text=label).pack(anchor="w", pady=(5, 0))
        line = ttk.Frame(parent)
        line.pack(fill="x", pady=(1, 3))
        ttk.Entry(line, textvariable=variable, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(line, text="Copy", command=lambda: self._copy(variable.get())).pack(side="left", padx=(6, 0))

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()

    def _show_auth(self):
        for child in self.auth_frame.winfo_children():
            child.destroy()
        if self.identity.get() == "Username":
            for name, variable, hidden in (("Username", self.username, False), ("Password", self.password, True)):
                ttk.Label(self.auth_frame, text=name).pack(anchor="w", pady=(3, 0))
                ttk.Entry(self.auth_frame, textvariable=variable, show="*" if hidden else "").pack(fill="x")

    def _start(self):
        endpoint = self.endpoint.get().strip()
        if not validate_endpoint(endpoint):
            messagebox.showerror("Invalid URL", "Use an endpoint such as opc.tcp://192.168.0.1:4840")
            return
        if self.identity.get() == "Username" and not self.username.get():
            messagebox.showerror("Username required", "Please enter a username.")
            return
        if (self.mode.get() == "None") != (self.policy.get() == "None"):
            messagebox.showerror(
                "Invalid security combination",
                "Choose None/None or Sign/SignEncrypt with a non-None security policy.",
                parent=self,
            )
            return
        self.go.configure(state="disabled")
        self.commands = queue.Queue()
        self.nodes.clear()
        self.pending.clear()
        self.tree.delete(*self.tree.get_children())
        self.relative_path.set("")
        self.found_type.set("")
        self.status.set("Starting...")
        self.bar.start(12)
        config = dict(endpoint=endpoint, mode=self.mode.get(), policy=self.policy.get(),
                      identity=self.identity.get(), username=self.username.get(), password=self.password.get())
        threading.Thread(target=BrowserSession(config, self.commands, self.events).run,
                         daemon=True).start()

    def _disconnect(self):
        self.connected = False
        self.disconnect.configure(state="disabled")

        # Clear the server browser immediately.
        self.tree.delete(*self.tree.get_children())
        self.nodes.clear()
        self.pending.clear()

        self.relative_path.set("")
        self.found_type.set("")

        self.commands.put(("disconnect", "", ""))
        self.status.set("Disconnecting...")

    def _close(self):
        self.commands.put(("disconnect", "", ""))
        self.destroy()

    def _expand(self, event=None):
        item = self.tree.focus()
        self._load(item)

    def _load(self, item):
        data = self.nodes.get(item)
        if not self.connected or not data or data.get("loaded") or item in self.pending:
            return
        self.pending.add(item)
        self.status.set("Loading children...")
        self.commands.put(("browse", item, data["nodeid"]))

    def _select(self, event=None):
        self.relative_path.set("")
        self.found_type.set("")
        selection = self.tree.selection()
        if not self.connected or not selection:
            return
        item = selection[0]
        data = self.nodes.get(item)
        if data and data["kind"] == "Variable":
            self.status.set("Reading variable data type...")
            self.commands.put(("select", item, data["nodeid"]))

    def _drain(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "status":
                    self.status.set(payload)
                elif kind == "progress":
                    self.status.set(f"Browsing... {payload} nodes visited")
                elif kind == "trust_request":
                    # Only the Tk main thread may display dialogs. Always release
                    # the worker, including if the dialog cannot be displayed.
                    payload["response"]["decision"] = False
                    try:
                        payload["response"]["decision"] = messagebox.askyesno(
                            "Trust OPC UA server certificate?",
                            "The server presented a certificate not previously "
                            "trusted by this tool.\n\n"
                            f"Server: {payload['server']}\n\n"
                            "SHA-256 fingerprint:\n"
                            f"{payload['fingerprint']}\n\n"
                            "Verify this fingerprint using a trusted channel "
                            "before approving.\n\n"
                            "Trust this certificate for future connections?",
                            parent=self,
                        )
                    finally:
                        payload["signal"].set()
                elif kind == "connected":
                    self.bar.stop()
                    self.connected = True
                    self.disconnect.configure(state="normal")
                    self.namespace_uris, nodeid = payload
                    root = self.tree.insert("", "end", text="Objects", values=("Object",), open=True)
                    self.nodes[root] = dict(nodeid=nodeid, segments=ROOT_PREFIX, kind="Object", ancestors=(nodeid,))
                    self._load(root)
                elif kind == "children":
                    item, children, errors = payload
                    self.pending.discard(item)
                    if not self.connected or item not in self.nodes:
                        continue
                    self.tree.delete(*self.tree.get_children(item))
                    parent = self.nodes[item]
                    parent["loaded"] = True
                    for data in sorted(children, key=lambda d: (d["name"].casefold(), d["ns"])):
                        # Suppress cycles on this path, retaining shared nodes under other parents.
                        if data["nodeid"] in parent["ancestors"]:
                            continue
                        data["segments"] = parent["segments"] + ((data["ns"], data["name"]),)
                        data["ancestors"] = parent["ancestors"] + (data["nodeid"],)
                        child = self.tree.insert(item, "end", text=f'{data["ns"]}:{data["name"]}', values=(data["kind"],))
                        self.nodes[child] = data
                        self.tree.insert(child, "end", text="Expand to load...")
                    self.status.set(f"Loaded {len(children)} nodes; {errors} unreadable. Select a variable.")
                elif kind == "selected":
                    item, dtype = payload
                    if self.connected and self.tree.selection() == (item,):
                        self.found_type.set(dtype)
                        segments = self.nodes[item]["segments"]
                        # Retain server namespace indexes; do not invent a new URI mapping.
                        self.relative_path.set("/" + "/".join(
                            f"{ns}:{escape_browse_name(name)}" for ns, name in segments))
                        self.status.set("Variable selected. Path uses server namespace indexes; verify OpcUa_any namespace configuration.")
                elif kind == "operation_error":
                    action, item, error = payload
                    self.pending.discard(item)
                    self.status.set("Operation failed. Collapse and expand to retry.")
                    messagebox.showerror("OPC UA error", error, parent=self)
                elif kind == "disconnected":
                    self.connected = False
                    self.pending.clear()
                    self.bar.stop()
                    self.go.configure(state="normal")
                    self.disconnect.configure(state="disabled")
                    self.relative_path.set("")
                    self.found_type.set("")
                    self.status.set("Disconnected")
                elif kind == "error":
                    self.bar.stop()
                    self.go.configure(state="normal")
                    self.status.set("Connection or browse failed")
                    messagebox.showerror("OPC UA error", payload)
        except queue.Empty:
            pass
        self.after(100, self._drain)

def resource_path(relative_path):
    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).resolve().parent.parent

    return base_path / relative_path

if __name__ == "__main__":
    App().mainloop()