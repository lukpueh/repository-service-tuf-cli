"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

Goals
-----
- use state-of-the-art securesystemslib Signer API only
- simplify (e.g. avoid custom/redundant abstractions over Metadata API)
- configure online signer location via uri attached to public key
  (for repository-service-tuf/repository-service-tuf-worker#427)

TODO
----
- implement ceremony
- implement update
- polish enough so that reviewers can try it out
- Integrate with existing admin cli

"""
import os
from copy import deepcopy
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.pretty import pprint
from rich.prompt import Confirm, IntPrompt, Prompt
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

KEY_URI_FIELD = "x-rstuf-online-key-uri"
# TODO: consider "x-rstuf-" prefix
KEY_NAME_FIELD = "name"


def _load_public_key() -> Tuple[Key, str]:
    """Ask for details to load public key, load and return key and uri."""
    # TODO: Give choice -- data (copy paste), hsm, aws, sigstore, ... -- and
    # consider configuring signer based on that choice. Note that for online
    # and offline signing, different choices might be interesting.

    # TODO: clarify supported key types, format
    path = Prompt.ask("Please enter a public key path")
    with open(path, "rb") as f:
        public_pem = f.read()

    crypto = load_pem_public_key(public_pem)

    key = SSlibKey.from_crypto(crypto)

    # for file based keys, we use a "relative file path uri"
    # see repository-service-tuf/repository-service-tuf#580
    uri = f"fn:{os.path.basename(path)}"

    return key, uri


def _configure_root_keys(root: Root) -> None:
    """Prompt series with loop to add/remove root keys, and enter threshold.

    Loops until user exit (at least one root key must be set).

    """
    console.print("Root Key Configuration")

    # Get current keys
    root_role = root.get_delegated_role(Root.type)
    # TODO: _show_root_key()

    # Remove or add root keys
    while True:
        if not root_role.keyids:
            console.print("At least one root key is required.")
            choice = 1  # Add key

        else:
            choice = IntPrompt.ask(
                "Please press (1) to add a root key, "
                "or (2) to remove a root key, "
                "or press enter to continue",
                choices=["1", "2"],
                default=0,
                show_choices=False,
                show_default=False,
            )

        if choice == 0:
            break

        elif choice == 1:
            try:
                new_key, _ = _load_public_key()
            except (OSError, ValueError) as e:
                console.print(f"Cannot load: {e}")
            else:
                # TODO: clarify what the name is needed/used for
                # TODO: assert unique?
                name = Prompt.ask(
                    "Please enter a key name, "
                    "or press enter to continue without name",
                    show_default=False,
                )
                if name:
                    new_key.unrecognized_fields[KEY_NAME_FIELD] = name

                # TODO: handle cases, where key already exists:
                #  * If the key is already a root key, `add_key` is a noop.
                #  * If the key is already used as online key, the keyid is
                #    added to root keyids, but the key object remains unchanged
                #    in the metadata keystore, so the entered name is lost.
                # Maybe we should disallow re-using root and online key, as they
                # need different additional fields (name vs. uri)?
                root.add_key(new_key, Root.type)
                console.print(f"Added root key '{new_key.keyid}'")

        elif choice == 2:
            keyid = Prompt.ask(
                "Choose key to remove", choices=sorted(root_role.keyids)
            )
            root.revoke_key(keyid, Root.type)
            console.print(f"Removed root key '{keyid}'")

    default_threshold = min(root_role.threshold, len(root_role.keyids))
    IntPrompt.ask(
        "Please enter root signature threshold:",
        choices=[str(i) for i in range(1, len(root_role.keyids) + 1)],
        show_choices=False,
        default=default_threshold,
    )


def _configure_online_key(root: Root) -> None:
    """Prompt loop to change online key.

    Loops until user exit.
    """
    console.print("Online Key Configuration")
    # TODO: _show_online_key()

    while True:
        # Get current key
        # TODO: assert all online roles have same/single keyid
        # TODO: handle inconsistency -> fail
        # TODO: handle missing online key -> fail in update (unless bootstrap)
        ts_role = root.get_delegated_role(Timestamp.type)
        current_key = root.get_key(ts_role.keyids[0])

        # Allow user to skip online key change
        if not Confirm.ask("Do you want to change the online key?"):
            break

        # Load new key
        try:
            new_key, uri = _load_public_key()
        except (OSError, ValueError) as e:
            console.print(f"Cannot load: {e}")
            continue

        new_key.unrecognized_fields[KEY_URI_FIELD] = uri

        # Remove current and add new key
        for role_name in ONLINE_ROLE_NAMES:
            root.revoke_key(current_key.keyid, role_name)

            # TODO: handle case where key already exists as root key; disallow?
            root.add_key(new_key, role_name)

        console.print(f"Configured online key: '{new_key.keyid}'")


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


def _get_verification_result(
    delegator: Root, delegate: Metadata[Root]
) -> Tuple[Dict[str, Key], str]:
    """Get opinionated verification result.

    TODO: consider upstreaming features to `get_verification_result`:
    - return keys (e.g. as dict), not keyids!
    - missing signature count is convenient, but not necessary
    - could also just return threshold
    (IIRC threshold was removed from result, because it can't be unioned.
     Maybe threshold in the result is more useful, than the union method.)

    Returns dict of unused keys and a message, to tell how many signatures are
    missing and from which keys. Empty message means fully signed.
    """
    result = delegator.get_verification_result(
        Root.type, delegate.signed_bytes, delegate.signatures
    )
    msg = ""
    if not result.verified:
        missing = delegator.roles[Root.type].threshold - len(result.signed)
        msg = (
            f"need {missing} signature(s) from any of "
            f"{sorted(result.unsigned)}"
        )

    unused_keys = {
        keyid: delegator.get_key(keyid) for keyid in result.unsigned
    }

    return unused_keys, msg


def _sign(
    metadata: Metadata[Root],
    prev_root: Optional[Root] = None,
    should_review=True,
):
    """Prompt loop to add signatures to root based on verification result.

    Verification results will be showed at least once, before the user is asked
    if they wish to exit signing.

    Loops until fully signed or user exit.
    """
    while True:
        unused_keys, missing_sig_msg = _get_verification_result(
            metadata.signed, metadata
        )
        if prev_root:
            prev_keys, prev_msg = _get_verification_result(prev_root, metadata)
            unused_keys.update(prev_keys)

            # Combine "missing signatures" messages from old and new root:
            # - show only non-empty message (filter)
            # - show only one message, if both are equal (set)
            missing_sig_msg = "\n".join(
                filter(None, sorted({missing_sig_msg, prev_msg}))
            )

        if missing_sig_msg:
            console.print(missing_sig_msg)
        else:
            console.print("Metadata fully signed.")
            break

        # Optionally, ask once to review the metadata.
        if should_review and Confirm.ask("Review?"):
            _show(metadata.signed)
        should_review = False

        # User may signal that they are done signing.
        if not _sign_one(metadata, unused_keys):
            break


def _sign_one(metadata: Metadata, keys: Dict[str, Key]) -> bool:
    """Prompt loop to add one signature to ``metadata`` using ``keys``.

    Loops until success or user exit. Returns boolean to indicate user exit.
    """
    while Confirm.ask("Sign?"):
        keyid = Prompt.ask("Choose key", choices=sorted(keys))
        try:
            signer = _load_signer(keys[keyid])
            metadata.sign(signer, append=True)
            console.print(f"Signed with key {keyid}")
            return True

        except (ValueError, OSError, UnsignedMetadataError) as e:
            console.print(f"Cannot sign: {e}")

    return False


def _load(prompt: str) -> Metadata[Root]:
    """Prompt loop to load root from file.

    Loop until success.
    """
    while True:
        path = Prompt.ask(prompt)
        try:
            metadata = Metadata[Root].from_file(path)
            break

        except (StorageError, DeserializationError) as e:
            console.print(f"Cannot load: {e}")

    return metadata


def _show(root: Root):
    """Pretty print root metadata."""
    pprint(root.to_dict())


def _save(metadata: Metadata[Root]):
    """Prompt loop to save root to file.

    Loop until success or user exit.
    """
    while Confirm.ask("Save?"):
        path = Prompt.ask("Enter path to save root", default="root.json")
        try:
            metadata.to_file(path)
            console.print(f"Saved to '{path}'...")
            break

        except StorageError as e:
            console.print(f"Cannot save: {e}")


@rstuf.group()  # type: ignore
def admin2():
    """POC: alternative admin interface"""


@admin2.command()  # type: ignore
def update() -> None:
    """Update root metadata.

    Will ask for root metadata and signing key paths.
    """
    # 1. Load
    current_root_md = _load("Enter path to root to update")
    new_root = deepcopy(current_root_md.signed)

    # 2. Configure online key
    _configure_online_key(new_root)

    # 3. Configure root key
    _configure_root_keys(new_root)

    if new_root == current_root_md.signed:
        console.print("Not saving unchanged metadata.")

    else:
        # 4. Bump version
        # TODO: should we always bump?
        new_root.version += 1

        # 5. Sign
        new_root_md = Metadata(new_root)
        _sign(new_root_md, current_root_md.signed)

        # 6. Save
        _save(new_root_md)

    console.print("Bye.")


@admin2.command()  # type: ignore
def sign() -> None:
    """Add signatures to root metadata.

    Will ask for root metadata and signing key paths.
    """
    # 1. Load
    root_md = _load("Enter path to root to sign")
    prev_root = None
    if root_md.signed.version > 1:
        prev_root_md = _load("Enter path to previous root")
        prev_root = prev_root_md.signed

    # 2. Add missing signatures
    orig_sigs = deepcopy(root_md.signatures)
    _sign(root_md, prev_root)

    # 3. Save
    if root_md.signatures != orig_sigs:
        _save(root_md)
    else:
        console.print("Not saving unchanged metadata.")

    console.print("Bye.")
