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
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.pretty import pprint
from rich.prompt import Confirm, Prompt
from securesystemslib.exceptions import StorageError
from securesystemslib.signer import CryptoSigner, Key, Signer, SSlibKey
from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
    UnsignedMetadataError,
)
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

    # TODO: clarify supported key types, format
    path = Prompt.ask("Enter path to encrypted local private key")

    with open(path, "rb") as f:
        private_pem = f.read()

    password = Prompt.ask("Enter password", password=True)
    private_key = load_pem_private_key(private_pem, password.encode())
    return CryptoSigner(private_key, public_key)


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


def _get_verification_result(
    delegator: Root, delegate: Metadata[Root]
) -> Tuple[Dict[str, Key], str]:
    result = delegator.get_verification_result(
        Root.type, delegate.signed_bytes, delegate.signatures
    )
    msg = ""
    if not result.verified:
        missing = delegator.roles[Root.type].threshold - len(result.signed)
        msg = f"need {missing} signature(s) from any of {result.unsigned}"

    unsigned = {keyid: delegator.get_key(keyid) for keyid in result.unsigned}

    return unsigned, msg


def _sign_root(
    metadata: Metadata[Root],
    prev_root: Optional[Root] = None,
    should_review=True,
):
    """ """
    while True:
        unsigned_keys, missing_sig_msg = _get_verification_result(
            metadata.signed, metadata
        )
        if prev_root:
            prev_keys, prev_msg = _get_verification_result(prev_root, metadata)
            unsigned_keys.update(prev_keys)

            # Combine "missing signatures" messages from old and new root:
            # - show only non-empty message (filter)
            # - show only one message if both are equal (set)
            missing_sig_msg = "\n".join(
                filter(None, {missing_sig_msg, prev_msg})
            )

        if missing_sig_msg:
            console.print(missing_sig_msg)
        else:
            console.print("Metadata is fully signed.")
            return

        while True:
            if should_review and Confirm.ask("Review?"):
                _show_root(metadata.signed)

            # Ask only once.
            should_review = False

            if not Confirm.ask("Sign?"):
                return

            keyid = Prompt.ask("Choose key", choices=list(unsigned_keys))
            try:
                signer = _load_signer(unsigned_keys[keyid])
                metadata.sign(signer, append=True)
                console.print(f"Signed with key {keyid}")
                break

            except (ValueError, OSError, UnsignedMetadataError) as e:
                console.print(f"Cannot sign: {e}")


def _load_root(msg: str) -> Metadata[Root]:
    while True:
        path = Prompt.ask(msg)
        try:
            metadata = Metadata[Root].from_file(path)
            break

        except (StorageError, DeserializationError) as e:
            console.print(f"Cannot load metadata: {e}\n\tTry again!\n")

    return metadata


def _show_root(root: Root):
    pprint(root.to_dict())


def _save_root(metadata: Metadata[Root]):
    while True:
        if not Confirm.ask("Save?"):
            return

        path = Prompt.ask("Enter path to save root", default="root.json")
        try:
            # TODO: switch back to default serializer when done with debugging
            from tuf.api.serialization.json import JSONSerializer

            metadata.to_file(path, JSONSerializer(compact=False))
            console.print(f"Saved to '{path}'...")
            break

        except StorageError as e:
            console.print(f"Cannot save: {e}")


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
    previous_root_metadata = _load_root("Enter path to root to update")
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
    root_md = _load_root("Enter path to root to sign")
    prev_root = None
    if root_md.signed.version > 1:
        prev_root_md = _load_root("Enter path to previous root")
        prev_root = prev_root_md.signed

    orig_sigs = deepcopy(root_md.signatures)
    _sign_root(root_md, prev_root)

    if root_md.signatures != orig_sigs:
        _save_root(root_md)
    else:
        console.print("Not saving unchanged metadata.")

    console.print("Bye.")
