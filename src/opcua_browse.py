"""B&R OPC UA BrowsePath Finder — full BrowsePath prototype.

Install: pip install asyncua
Run: python main.py
This first implementation supports SecurityPolicy=None / MessageSecurityMode=None.
Secure modes require explicit certificate/trust configuration and are not silently downgraded.
"""
from collections import deque
from urllib.parse import urlsplit

SECURITY_MODES = ["None", "Sign", "SignEncrypt"]
SECURITY_POLICIES = ["None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep"]
UA_TO_BR = {"Boolean": "BOOL", "Byte": "USINT", "SByte": "SINT", "UInt16": "UINT", "Int16": "INT", "UInt32": "UDINT", "Int32": "DINT", "Float": "REAL"}
RESERVED = set("./:!#&<>")
ROOT_PREFIX = ((0, "Root"), (0, "Objects"))


def escape_browse_name(value):
    return "".join("&" + c if c in RESERVED else c for c in value)


def validate_endpoint(endpoint):
    try:
        parts = urlsplit(endpoint)
        if parts.scheme != "opc.tcp" or not parts.hostname or not (1 <= parts.port <= 65535):
            return False
        return True
    except (ValueError, TypeError):
        return False


def search_server(config, events):
    """Runs off Tk main thread. Traverse Objects and collect all matching BrowseNames."""
    from asyncua.sync import Client
    from asyncua import ua

    client = Client(config["endpoint"], timeout=10)
    try:
        if config["identity"] == "Username":
            client.set_user(config["username"])
            client.set_password(config["password"])
        events.put(("status", "Connecting to server..."))
        client.connect()
        events.put(("status", "Connected. Reading namespace URIs..."))
        namespace_uris = client.get_namespace_array()
        # Keep every entry, including index 0. A server index is *not* assumed
        # to be a B&R relative index; explicit mapping is shown in results.
        root = client.nodes.objects
        paths = deque([(root, ROOT_PREFIX)])
        visited = set()
        count = 0
        matches = []
        errors = 0
        while paths:
            node, segments = paths.popleft()
            nodeid = node.nodeid.to_string()
            if nodeid in visited:
                continue
            visited.add(nodeid)
            count += 1
            if count % 20 == 0:
                events.put(("progress", count))
            try:
                children = node.get_children()
            except Exception:
                errors += 1
                continue
            for child in children:
                try:
                    bn = child.read_browse_name()
                    child_segments = segments + ((bn.NamespaceIndex, bn.Name),)
                    if bn.Name == config["node_name"] and child.read_node_class() == ua.NodeClass.Variable:
                        variant = child.read_data_type_as_variant_type()
                        actual = UA_TO_BR.get(variant.name, f"Unsupported ({variant.name})")
                        matches.append((child.nodeid.to_string(), child_segments, actual))
                    if child.nodeid.to_string() not in visited:
                        paths.append((child, child_segments))
                except Exception:
                    errors += 1
        events.put(("progress", count))
        events.put(("done", (namespace_uris, matches, count, errors)))
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


