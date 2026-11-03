# B&R OPC UA BrowsePath Finder

Windows utility that browses an OPC UA server, finds variables by **BrowseName**, retrieves their data types, lets you choose between duplicates using the parent path, and prepares the **complete RelativePath from Root** for Automation Studio `OpcUa_any`.

> Unofficial B&R community utility. Live OPC UA browsing and Automation Studio compatibility still require testing.

## Project structure

```text
OpcUaBrowsePathFinder/
├── assets/                 # Icons and other application assets (add when needed)
├── build/                  # PyInstaller temporary output (generated, Git-ignored)
├── dist/                   # Windows executable (generated, Git-ignored)
├── docs/
│   └── OPCUA_ANY.md
├── src/
│   ├── gui_launcher.py     # Tkinter GUI
│   └── opcua_browse.py     # OPC UA connection and search
├── .gitignore
├── LICENSE
├── OpcUaBrowsePathFinder.spec
├── README.md
└── requirements-dev.txt
```

## Run from source

```powershell
py -m pip install -r requirements-dev.txt
py src/gui_launcher.py
```

## Build the Windows EXE

Run in the project root:

```powershell
py -m PyInstaller --noconfirm --clean OpcUaBrowsePathFinder.spec
```

Output: `dist/OpcUaBrowsePathFinder.exe`.

## Configuration and limitations

Select `None` for both SecurityMessageMode and SecurityPolicy in this prototype; other modes and BestAvailable are not implemented yet. Username/password only over a None/None channel is not appropriate on untrusted networks.

Namespace numbers generated in RelativePath are **relative indexes for the URI table shown by the application**. Reconcile that table with any existing Automation Studio configuration.

Some servers limit browsing permissions; a live server is required to validate generated paths and datatypes.

## License

MIT — see `LICENSE`.
