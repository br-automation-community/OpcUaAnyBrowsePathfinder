"""Graphical launcher for the B&R OPC UA BrowsePath Finder."""
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import sys

from opcua_browse import (
    SECURITY_MODES, SECURITY_POLICIES,
    escape_browse_name, validate_endpoint, search_server,
)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.iconbitmap(str(resource_path("assets/ASImage.ico")))
        self.title("B&R OPC UA BrowsePath Finder")
        self.geometry("900x605")
        self.minsize(740, 520)
        self.events = queue.Queue()
        self.endpoint = tk.StringVar(value="opc.tcp://127.0.0.1:4840")
        self.mode = tk.StringVar(value="None")
        self.policy = tk.StringVar(value="None")
        self.identity = tk.StringVar(value="Anonymous")
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.node_name = tk.StringVar()
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
        self._entry(main, "Node Name (exact BrowseName)", self.node_name)
        # Use a prominent native Tk button instead of the theme-dependent ttk style.
        self.go = tk.Button(
            main,
            text="Connect, Browse & Retrieve",
            command=self._start,
            bg="#0875C9",
            fg="white",
            activebackground="#065A9B",
            activeforeground="white",
            font=("Segoe UI", 10, "bold"),
            relief="raised",
            borderwidth=2,
            padx=18,
            pady=10,
            cursor="hand2",
        )
        self.go.pack(anchor="center", pady=(10, 8))
        self.bar = ttk.Progressbar(main, mode="indeterminate")
        self.bar.pack(fill="x", pady=(7, 3))
        ttk.Label(main, textvariable=self.status).pack(anchor="w")
        ttk.Separator(main).pack(fill="x", pady=12)
        ttk.Label(main, text="Result — OpcUa_any configuration", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(main, text="Matching nodes — select by parent path (if multiple)").pack(anchor="w", pady=(8, 0))
        self.match_list = ttk.Combobox(main, state="readonly")
        self.match_list.pack(fill="x")
        self.match_list.bind("<<ComboboxSelected>>", self._display_match)
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
        if not self.node_name.get().strip():
            messagebox.showerror("Node required", "Enter the exact BrowseName to search for.")
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
        self.matches = []
        self.namespace_mapping = {}
        self.match_list.configure(values=[])
        self.relative_path.set("")
        self.found_type.set("")
        self.match_list.set("")
        self.status.set("Starting...")
        self.bar.start(12)
        config = dict(endpoint=endpoint, mode=self.mode.get(), policy=self.policy.get(), identity=self.identity.get(), username=self.username.get(),
                      password=self.password.get(), node_name=self.node_name.get().strip())
        threading.Thread(target=self._worker, args=(config,), daemon=True).start()

    def _worker(self, config):
        try:
            search_server(config, self.events)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            self.events.put((
                "error",
                f"{type(exc).__name__}: {exc}\n\n"
                "See terminal for the complete traceback.",
            ))

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
                elif kind == "done":
                    self.bar.stop()
                    self.go.configure(state="normal")
                    uris, matches, count, errors = payload
                    self.matches = matches
                    self.namespace_uris = uris
                    # Namespace zero is defined by the OPC UA standard. Every other
                    # namespace used in result paths is assigned a stable local index.
                    used = sorted({ns for _, segments, _ in matches for ns, _ in segments if ns != 0})
                    self.namespace_mapping = {ns: i + 1 for i, ns in enumerate(used)}
                    self.match_list.configure(values=[
                        f"Parent: /{'/'.join(n for _, n in segments[:-1]) or '(Objects)'}  |  Type: {dtype}"
                        for nodeid, segments, dtype in matches
                    ])
                    if matches:
                        self.match_list.current(0)
                        self._display_match()
                    self.status.set(f"Finished: {count} nodes inspected, {len(matches)} matches, {errors} unreadable nodes/edges")
                    if not matches:
                        messagebox.showinfo("Not found", "No variable with that BrowseName was found in the browsable Objects hierarchy.")
                elif kind == "error":
                    self.bar.stop()
                    self.go.configure(state="normal")
                    self.status.set("Connection or browse failed")
                    messagebox.showerror("OPC UA error", payload)
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _display_match(self, event=None):
        index = self.match_list.current()
        if index < 0 or index >= len(self.matches):
            return
        nodeid, segments, dtype = self.matches[index]
        self.found_type.set(dtype)
        # Include Root and Objects, with no StartingNode. Server namespace
        # indexes are translated using the displayed B&R namespace URI mapping.
        def relative_ns(server_ns):
            if server_ns == 0:
                return 0
            return self.namespace_mapping[server_ns]

        self.relative_path.set("/" + "/".join(
            f"{relative_ns(ns)}:{escape_browse_name(name)}" for ns, name in segments
        ))

def resource_path(relative_path):
    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).resolve().parent.parent

    return base_path / relative_path

if __name__ == "__main__":
    App().mainloop()