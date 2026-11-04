
"""B&R OPC UA BrowsePath Finder - OPC UA connection and browsing."""

import asyncio
import hashlib
import json
import os
import socket
import threading

from collections import deque
from pathlib import Path
from urllib.parse import urlsplit


SECURITY_MODES = [
    "None",
    "Sign",
    "SignEncrypt",
]

SECURITY_POLICIES = [
    "None",
    "Basic128Rsa15",
    "Basic256",
    "Basic256Sha256",
    "Aes128_Sha256_RsaOaep",
]

UA_TO_BR = {
    "Boolean": "BOOL",
    "Byte": "USINT",
    "SByte": "SINT",
    "UInt16": "UINT",
    "Int16": "INT",
    "UInt32": "UDINT",
    "Int32": "DINT",
    "Float": "REAL",
}

RESERVED = set("./:!#&<>")
ROOT_PREFIX = ((0, "Root"), (0, "Objects"))


def escape_browse_name(value):
    """Escape special characters in OPC UA BrowsePaths."""
    return "".join(
        "&" + char if char in RESERVED else char
        for char in value
    )


def validate_endpoint(endpoint):
    """Validate OPC UA endpoint URL."""
    try:
        parts = urlsplit(endpoint)

        return (
            parts.scheme == "opc.tcp"
            and bool(parts.hostname)
            and parts.port is not None
            and 1 <= parts.port <= 65535
        )
    except (ValueError, TypeError):
        return False


def app_data_dir():
    """Return persistent application data directory."""
    base = os.environ.get("LOCALAPPDATA")

    if not base:
        base = str(Path.home() / "AppData" / "Local")

    return Path(base) / "OpcUaBrowsePathFinder"


def _trusted_certificate(config, events, endpoint):
    """Check or request approval for the server certificate."""

    certificate = bytes(endpoint.ServerCertificate)

    if not certificate:
        raise RuntimeError(
            "The selected secure endpoint did not provide "
            "a server certificate."
        )

    fingerprint = hashlib.sha256(
        certificate
    ).hexdigest().upper()

    store = (
        app_data_dir()
        / "pki"
        / "trusted_servers.json"
    )

    if store.exists():
        known = json.loads(
            store.read_text(encoding="utf-8")
        )
    else:
        known = {}

    identity = (
        f'{config["endpoint"]}|'
        f'{config["mode"]}|'
        f'{config["policy"]}'
    )

    trusted_fingerprints = known.get(identity, [])

    # Support entries saved by the previous version.
    if isinstance(trusted_fingerprints, str):
        trusted_fingerprints = [trusted_fingerprints]

    if fingerprint not in trusted_fingerprints:
        response = {"decision": False}
        approved = threading.Event()

        events.put((
            "trust_request",
            {
                "server": config["endpoint"],
                "fingerprint": fingerprint,
                "response": response,
                "signal": approved,
            },
        ))

        if (
            not approved.wait(timeout=120)
            or not response["decision"]
        ):
            raise RuntimeError(
                "Server certificate not trusted. "
                "Connection cancelled."
            )

        store.parent.mkdir(parents=True, exist_ok=True)

        trusted_fingerprints.append(fingerprint)
        known[identity] = trusted_fingerprints

        store.write_text(
            json.dumps(known, indent=2),
            encoding="utf-8",
        )

    return certificate


def _prepare_client_certificate(client, events):
    """Generate or reuse the OPC UA application certificate."""

    from cryptography.x509.oid import ExtendedKeyUsageOID
    from asyncua.crypto.cert_gen import (
        setup_self_signed_certificate,
    )

    pki = app_data_dir() / "pki" / "own"
    pki.mkdir(parents=True, exist_ok=True)

    cert_file = pki / "client.der"
    key_file = pki / "client_key.pem"

    hostname = socket.gethostname()

    # Keep the application URI stable between connections.
    client.application_uri = (
        f"urn:{hostname}:"
        "BRCommunity:OpcUaBrowsePathFinder"
    )

    events.put((
        "status",
        "Preparing OPC UA client certificate...",
    ))

    # setup_self_signed_certificate is an asynchronous
    # standalone function, not a method of sync.Client.
    # This code runs in the background worker thread.
    asyncio.run(
        setup_self_signed_certificate(
            key_file,
            cert_file,
            client.application_uri,
            hostname,
            [ExtendedKeyUsageOID.CLIENT_AUTH],
            {
                "commonName": "OpcUaBrowsePathFinder",
            },
        )
    )

    return cert_file, key_file


def _configure_security(client, config, events):
    """Configure the requested OPC UA security policy and mode."""

    from asyncua import ua
    from asyncua.crypto import security_policies

    mode_name = config["mode"]
    policy_name = config["policy"]

    # Unsecured connection.
    if mode_name == "None" and policy_name == "None":
        return

    # Validate combinations.
    if (
        mode_name not in ("Sign", "SignEncrypt")
        or policy_name == "None"
    ):
        raise ValueError(
            "Invalid security combination. "
            "Choose None/None or a secure mode and policy."
        )

    policy_classes = {
        "Basic128Rsa15": "SecurityPolicyBasic128Rsa15",
        "Basic256": "SecurityPolicyBasic256",
        "Basic256Sha256": "SecurityPolicyBasic256Sha256",
        "Aes128_Sha256_RsaOaep":
            "SecurityPolicyAes128Sha256RsaOaep",
    }

    policy_class = getattr(
        security_policies,
        policy_classes[policy_name],
        None,
    )

    if policy_class is None:
        raise RuntimeError(
            f"The installed asyncua version does not "
            f"support security policy {policy_name}."
        )

    if mode_name == "Sign":
        security_mode = ua.MessageSecurityMode.Sign
    else:
        security_mode = (
            ua.MessageSecurityMode.SignAndEncrypt
        )

    # Discover available server endpoints.
    events.put((
        "status",
        "Discovering OPC UA server endpoints...",
    ))

    endpoints = (
        client.connect_and_get_server_endpoints()
    )

    selected_endpoint = next(
        (
            endpoint
            for endpoint in endpoints
            if (
                endpoint.SecurityPolicyUri
                == policy_class.URI
                and endpoint.SecurityMode == security_mode
            )
        ),
        None,
    )

    if selected_endpoint is None:
        raise RuntimeError(
            f"The server does not offer "
            f"{policy_name} / {mode_name}."
        )

    # Verify the server certificate.
    server_certificate = _trusted_certificate(
        config,
        events,
        selected_endpoint,
    )

    # Create or reuse the application certificate.
    cert_file, key_file = _prepare_client_certificate(
        client,
        events,
    )

    # Configure the secure channel.
    client.set_security(
        policy_class,
        str(cert_file),
        str(key_file),
        server_certificate=server_certificate,
        mode=security_mode,
    )

    events.put((
        "status",
        "Secure OPC UA channel configured...",
    ))


class BrowserSession:
    """Own the connection on one worker thread; serve lazy browse requests."""

    def __init__(self, config, commands, events):
        self.config, self.commands, self.events = config, commands, events

    def run(self):
        import traceback
        from asyncua.sync import Client
        from asyncua import ua

        client = Client(self.config["endpoint"], timeout=10)
        try:
            if self.config["identity"] == "Username":
                client.set_user(self.config["username"])
                client.set_password(self.config["password"])
            _configure_security(client, self.config, self.events)
            self.events.put(("status", "Connecting to OPC UA server..."))
            client.connect()
            self.events.put(("connected", (
                client.get_namespace_array(), client.nodes.objects.nodeid.to_string()
            )))
            while True:
                action, item, nodeid = self.commands.get()
                if action == "disconnect":
                    break
                try:
                    node = client.get_node(nodeid)
                    if action == "browse":
                        children = []
                        errors = 0
                        for child in node.get_children(refs=ua.ObjectIds.HierarchicalReferences):
                            try:
                                name = child.read_browse_name()
                                children.append(dict(
                                    nodeid=child.nodeid.to_string(),
                                    ns=name.NamespaceIndex, name=name.Name,
                                    kind=child.read_node_class().name,
                                ))
                            except Exception:
                                errors += 1
                        self.events.put(("children", (item, children, errors)))
                    elif action == "select":
                        variant = node.read_data_type_as_variant_type()
                        dtype = UA_TO_BR.get(variant.name, f"Unsupported ({variant.name})")
                        self.events.put(("selected", (item, dtype)))
                except Exception as exc:
                    traceback.print_exc()
                    self.events.put(("operation_error", (action, item, str(exc))))
        except Exception as exc:
            traceback.print_exc()
            self.events.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            try:
                client.disconnect()
            except Exception:
                import traceback
                traceback.print_exc()
            finally:
                self.events.put(("disconnected", None))