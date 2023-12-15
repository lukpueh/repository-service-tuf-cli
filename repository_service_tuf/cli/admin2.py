"""POC: alternative admin cli

Re-implement key loading and signing in admin cli subcommands.

Goals
-----
- configure online signer location via uri attached to public key
 (for repository-service-tuf/repository-service-tuf-worker#427)
- use state-of-the-art securesystemslib Signer API only
- make re-usable for similar cli
- simplify (e.g. avoid custom/redundant abstractions over
    python-tuf/securesystemslib Metadata API)

TODO
----
- polish enough so that reviewers can try it out:
    - handle errors from inputs
    - clarify and beautify outputs
- Integrate with existing admin cli

"""
from copy import deepcopy
from typing import Optional

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.pretty import pprint
from rich.prompt import Confirm, Prompt
from securesystemslib.exceptions import StorageError
from securesystemslib.signer import CryptoSigner, Key, Signer, SSlibKey
from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp
from tuf.api.serialization import DeserializationError

from repository_service_tuf.cli import console, rstuf

ONLINE_ROLE_NAMES = {Timestamp.type, Snapshot.type, Targets.type}

# see repository-service-tuf/repository-service-tuf-worker#427
ONLINE_KEY_URI_FIELD = "x-rstuf-online-key-uri"
KEY_LABEL_FIELD = "x-rstuf-key-label"


def _load_public() -> Key:
    """Ask for details to load public key, load and return."""
    # TODO: Give choice -- data (copy paste), hsm, aws, sigstore, ... -- and
    # consider configuring signer based on that choice. Note that for online and
    # offline signing, different choices might be interesting.

    while True:
        # TODO: clarify supported key types, format
        path = Prompt.ask("Enter public key path")
        try:
            with open(path, "rb") as f:
                public_pem = f.read()

            crypto = load_pem_public_key(public_pem)
            key = SSlibKey.from_crypto(crypto)
            break
        except (OSError, ValueError) as e:
            console.print(f"Cannot load public key: {e}\n\tTry again!\n")

    # TODO: keyids can be anything. we could just ask for a custom keyid
    # instead of a label.
    label = Prompt.ask("Enter key label (optional)")
    if label:
        key.unrecognized_fields[KEY_LABEL_FIELD] = label

    return key


def _configure_online_signer() -> str:
    """Ask for details to load online signer and return as URI."""
    # TODO: Give choice -- relative path, envvar, aws, gcp, azure, sigstore, ...

    # TODO: clarify supported key types, format, "unencryptedness" and where
    # the key will be used
    path = Prompt.ask("Enter full path to unencrypted online private key")
    uri = f"{CryptoSigner.FILE_URI_SCHEME}:{path}?encrypted=false"

    return uri


def _load_signer(public_key: Key) -> Signer:
    """Ask for details to load signer, load and return."""
    # TODO: Give choice -> hsm, sigstore, ...

    while True:
        # TODO: clarify supported key types, format
        path = Prompt.ask("Enter path to encrypted local private key")

        try:
            with open(path, "rb") as f:
                private_pem = f.read()

            password = Prompt.ask("Enter password", password=True)
            private_key = load_pem_private_key(private_pem, password.encode())
            signer = CryptoSigner(private_key, public_key)
            break
        except (OSError, ValueError) as e:
            console.print(f"Cannot load private key: {e}\n\tTry again!\n")

    return signer


def _configure_online_key(root: Root) -> None:
    console.print("Online key")
    while True:
        key = _load_public()
        uri = _configure_online_signer()
        key.unrecognized_fields[ONLINE_KEY_URI_FIELD] = uri
        # TODO: remove old online key first
        root.keys[key.keyid] = key
        for name in ONLINE_ROLE_NAMES:
            root.roles[name].keyids = [key.keyid]

        pprint(root.to_dict())
        if Confirm.ask("Done?"):
            break


def _configure_offline_keys(root: Root) -> None:
    console.print("Offline keys")
    while True:
        # TODO: add, remove, done, show stat
        console.print("Add")
        key = _load_public()
        root.add_key(key, Root.type)

        pprint(root.to_dict())
        if Confirm.ask("Done?"):
            break


def _sign_root(metadata: Metadata[Root], previous_root: Optional[Root] = None):
    console.print("Sign root metadata")

    keyids = set(metadata.signed.roles[Root.type].keyids)
    if previous_root:
        keyids |= set(previous_root.roles[Root.type].keyids)

    for keyid in keyids:
        console.print(f"Sign with key {keyid}")
        # TODO: yes, no, done, show stat
        key = metadata.signed.get_key(keyid)
        signer = _load_signer(key)
        try:
            metadata.sign(signer, append=True)
        # TODO: catch specific exception, based on supported signer impl
        except Exception as e:
            console.print(f"Cannot sign root metadata: {e}\n\tTry again!\n")

        pprint(metadata.to_dict())

        # TODO: check threshold (note special case root v1)
        # TODO: only ask if no more keys are left to sign with
        if Confirm.ask("Done?"):
            break


def _load_root() -> Metadata[Root]:
    while True:
        path = Prompt.ask("Enter path to root metadata")
        try:
            metadata = Metadata[Root].from_file(path)
            break

        except (StorageError, DeserializationError) as e:
            console.print(f"Cannot load root metadata: {e}\n\tTry again!\n")

    return metadata


@rstuf.group()  # type: ignore
def admin2():
    """POC: alternative admin interface"""


@admin2.command()  # type: ignore
def ceremony() -> None:
    """POC: Key-only Metadata Ceremony."""
    console.print("Ceremony")
    root = Root()
    _configure_online_key(root)
    _configure_offline_keys(root)
    root_md = Metadata(root)
    _sign_root(root_md)

    # TODO: make this configurable
    root_md.to_file("root.json")


@admin2.command()  # type: ignore
def update() -> None:
    """POC: Key-only Root Metadata Update."""
    console.print("Update")
    previous_root_metadata = _load_root()
    root = deepcopy(previous_root_metadata.signed)

    _configure_online_key(root)
    _configure_offline_keys(root)

    root_md = Metadata(root)
    _sign_root(root_md, previous_root_metadata.signed)

    # TODO: make this configurable
    root_md.to_file("root.json")


@admin2.command()  # type: ignore
def sign() -> None:
    """POC: Sign Root Metadata."""
    # TODO: allow passing previous root, to sign with old keys

    console.print("Sign")
    root_md = _load_root()
    _sign_root(root_md)

    # TODO: make this configurable
    root_md.to_file("root.json")
