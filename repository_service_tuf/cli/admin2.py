"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

Goals
-----
- use state-of-the-art securesystemslib Signer API only
- simplify (e.g. avoid custom/redundant abstractions over Metadata API)
- configure online signer location via uri attached to public key
  (for repository-service-tuf/repository-service-tuf-worker#427)


"""
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.pretty import pprint
from rich.prompt import Confirm, IntPrompt, InvalidResponse, Prompt
from securesystemslib.exceptions import StorageError
from securesystemslib.signer import (
    CryptoSigner,
    Key,
    Signature,
    Signer,
    SSlibKey,
)
from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
    UnsignedMetadataError,
)
from tuf.api.serialization import DeserializationError

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console, rstuf

ONLINE_ROLE_NAMES = {Timestamp.type, Snapshot.type, Targets.type}

KEY_URI_FIELD = "x-rstuf-online-key-uri"
# TODO: Consider using "x-rstuf-" prefix
KEY_NAME_FIELD = "name"

# Use locale's appropriate date representation to display the expiry date.
EXPIRY_FORMAT = "%x"


class _PositiveIntPrompt(IntPrompt):
    validate_error_message = (
        "[prompt.invalid]Please enter a valid positive integer number"
    )

    def process_response(self, value: str) -> int:
        return_value: int = super().process_response(value)
        if return_value < 1:
            raise InvalidResponse(self.validate_error_message)
        return return_value


def _load_public_key_from_file() -> Key:
    """Prompt for path to local public key, load and return."""

    path = Prompt.ask("Please enter a public key path")
    with open(path, "rb") as f:
        public_pem = f.read()

    crypto = load_pem_public_key(public_pem)

    key = SSlibKey.from_crypto(crypto)

    return key


def _show_root_key_info(root: Root) -> None:
    """Pretty print root keys and threshold."""
    # TODO: Make prettier and useful
    root_role = root.get_delegated_role(Root.type)
    console.print(f"Current Threshold: {root_role.threshold}")
    console.print("Current Keys:")
    for keyid in root_role.keyids:
        key = root.get_key(keyid)
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, "")
        if name:
            name = f"(name: {name})"
        console.print(f"keyid: {keyid}", name)


def _add_root_keys(root: Root) -> None:
    """Prompt loop to add root keys.

    Loops until user exit and threshold is met."""

    root_role = root.get_delegated_role(Root.type)

    while True:
        missing = root_role.threshold - len(root_role.keyids)
        if missing > 0:
            console.print(
                f"Please add {missing} key(s) "
                f"to meet threshold ({root_role.threshold})"
            )
        else:
            if not Confirm.ask("Do you want to add a root key?"):
                break

        try:
            new_key = _load_public_key_from_file()
        except (OSError, ValueError) as e:
            console.print(f"Cannot load: {e}")
            continue

        # TODO: Handle cases where key already exists:
        #  * If the key exists as root key the key object remains unchanged
        #    in the metadata keystore and a name change will not take effect.
        #  * If the key is already used as online key, the keyid is
        #    added to root keyids, but the key object also remains unchanged.
        # Lets just disallow re-adding a key here, even if it is for a
        # different role, given that different roles have different extra key
        # fields (root's "KEY_NAME_FIELD" vs. online roles' "KEY_URI_FIELD")

        # TODO: Should name be mandatory? Would be helpful to distinguish keys
        name = Prompt.ask(
            "Please enter a key name, "
            "or press enter to continue without name",
            show_default=False,
        )
        if name:
            new_key.unrecognized_fields[KEY_NAME_FIELD] = name

        root.add_key(new_key, Root.type)
        console.print(f"Added root key '{new_key.keyid}'")

        _show_root_key_info(root)


def _remove_root_keys(root: Root) -> None:
    """Prompt loop to remove root keys.

    Loops until no keys left or user exit (threshold is ignored)."""
    root_role = root.get_delegated_role(Root.type)

    while True:
        if not root_role.keyids:
            break

        if not Confirm.ask("Do you want to remove a root key?"):
            break

        keyid = Prompt.ask(
            "Choose key to remove", choices=sorted(root_role.keyids)
        )
        root.revoke_key(keyid, Root.type)
        console.print(f"Removed root key '{keyid}'")

        _show_root_key_info(root)


def _configure_root_keys(root: Root) -> None:
    """Prompt series with loop to add/remove root keys, and enter threshold.

    Loops until user exit (at least one root key must be set).

    """
    console.print("Root Key Configuration")

    # Get current keys
    root_role = root.get_delegated_role(Root.type)

    while True:
        _show_root_key_info(root)

        # Allow user to skip offline key change (assumes valid metadata)
        if not Confirm.ask("Do you want to change root keys?"):
            break

        # TODO: Should we ask for threshold *after* removing/adding keys?
        # Currently, if the users accidentally sets a wrong threshold, they
        # might have a hard time to add enough keys to meet it, which they have
        # to do before they can correct the mistake.
        if Confirm.ask("Do you want to change the root signature threshold?"):
            root_role.threshold = _PositiveIntPrompt.ask(
                "Please enter root signature threshold"
            )
            console.print(
                f"Changed root signature threshold to {root_role.threshold}"
            )

        # Allow removing keys, even if we drop below threshold.
        _remove_root_keys(root)

        # Require enough keys to meet the threshold
        _add_root_keys(root)


def _configure_online_key(root: Root) -> None:
    """Prompt loop to change online key.

    Loops until user exit.
    """
    console.print("Online Key Configuration")

    while True:
        # Get current key
        # TODO: Assert that all online roles have same/single keyid. Mandate
        # change otherwise.
        ts_role = root.get_delegated_role(Timestamp.type)
        current_key = root.get_key(ts_role.keyids[0])

        # Show key
        # TODO: Make pretty and useful
        console.print("Current Key:")
        uri = current_key.unrecognized_fields.get(KEY_URI_FIELD, "")
        if uri:
            uri = f"(uri: '{uri}')"
        console.print(f"keyid: {current_key.keyid}", uri)

        # Allow user to skip online key change (assumes valid metadata)
        if not Confirm.ask("Do you want to change the online key?"):
            break

        # Load new key
        try:
            new_key = _load_public_key_from_file()

        except (OSError, ValueError) as e:
            console.print(f"Cannot load: {e}")
            continue

        # For file-based keys we default to a "relative file path uri" using
        # keyid as filename. The online signing key must be made available to
        # the worker under that filename. Additionally, a base path to the file
        # can be specified via container configuration.
        # see repository-service-tuf/repository-service-tuf#580 for details
        uri = f"fn:{new_key.keyid}"

        new_key.unrecognized_fields[KEY_URI_FIELD] = uri

        # Remove current and add new key
        for role_name in ONLINE_ROLE_NAMES:
            root.revoke_key(current_key.keyid, role_name)

            # TODO: Handle case where key already exists as root key. Disallow?
            root.add_key(new_key, role_name)

        console.print(f"Configured online key: '{new_key.keyid}'")


def _configure_expiry(root: Root) -> None:
    """Prompt loop to configure root expiry.

    Loops until user exit and metadata is not expired.
    """
    console.print("Expiration Date Configuration")

    while True:
        if root.is_expired():
            console.print(
                f"Root has expired on {root.expires:{EXPIRY_FORMAT}}"
            )
        else:
            console.print(f"Root expires on {root.expires:{EXPIRY_FORMAT}}")
            if not Confirm.ask("Do you want to change the expiry date?"):
                break

        days = _PositiveIntPrompt.ask(
            "Please enter number of days from now, when root should expire"
        )

        root.expires = datetime.utcnow() + timedelta(days=days)
        console.print(f"Changed root to expire in {days} days")


def _load_signer(public_key: Key) -> Signer:
    """Ask for details to load signer, load and return."""
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

    TODO: Consider upstreaming features to `get_verification_result`:
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


def _get_verification_results(
    metadata: Metadata[Root], prev_root: Optional[Root]
) -> Tuple[Dict[str, Key], str]:
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
    return unused_keys, missing_sig_msg


def _sign_multiple(
    metadata: Metadata[Root],
    prev_root: Optional[Root],
) -> Optional[list[Signature]]:
    """Prompt loop to add signatures to root.

    Prints metadata for review once, and signature requirements.
    Loops until fully signed or user exit.
    """
    signatures = []
    showed_metadata = False
    while True:
        unused_keys, missing_sig_msg = _get_verification_results(
            metadata, prev_root
        )
        if not missing_sig_msg:
            console.print("Metadata fully signed.")
            return signatures

        # Show metadata for review once
        if not showed_metadata:
            _show(metadata.signed)
            showed_metadata = True

        # Show signature requirements
        console.print(missing_sig_msg)

        # Loop until signing success or user exit
        while True:
            if not Confirm.ask("Do you want to sign?"):
                return signatures

            signature = _sign(metadata, unused_keys)
            if signature:
                signatures.append(signature)
                break


def _sign_one(
    metadata: Metadata[Root], prev_root: Optional[Root]
) -> Optional[Signature]:
    """Prompt loop to add one signature.

    Prints metadata for review, and signature requirements.
    Returns None, if metadata is fully missing, or loops until success and
    returns signature.
    """
    unused_keys, missing_sig_msg = _get_verification_results(
        metadata, prev_root
    )
    if not missing_sig_msg:
        console.print("Metadata fully signed.")
        return

    _show(metadata.signed)
    console.print(missing_sig_msg)

    signature = None
    while not signature:
        signature = _sign(metadata, unused_keys)

    return signature


def _sign(metadata: Metadata, keys: Dict[str, Key]) -> Optional[Signature]:
    """Add signature to ``metadata`` using ``keys``.

    Return Signature or None, if signing fails.
    """
    signature = None
    keyid = Prompt.ask("Choose key", choices=sorted(keys))
    try:
        signer = _load_signer(keys[keyid])
        signature = metadata.sign(signer, append=True)
        console.print(f"Signed with key {keyid}")

    except (ValueError, OSError, UnsignedMetadataError) as e:
        console.print(f"Cannot sign: {e}")

    return signature


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
    """Update root metadata and bump version.

    Will ask for root metadata, public key paths, and signing key paths.
    """
    console.print("Root Metadata Update")
    # Load
    current_root_md = _load("Enter path to root to update")
    new_root = deepcopy(current_root_md.signed)

    # Update
    _configure_expiry(new_root)
    _configure_root_keys(new_root)
    _configure_online_key(new_root)

    # Sign and save (if changed)
    if new_root == current_root_md.signed:
        console.print("Not saving unchanged metadata.")
    else:
        new_root.version += 1
        new_root_md = Metadata(new_root)
        _sign_multiple(new_root_md, current_root_md.signed)
        _save(new_root_md)

    console.print("Bye.")


@admin2.command()  # type: ignore
def sign() -> None:
    """Add one signature to root metadata.

    Will ask for root metadata and signing key path.
    """
    # 1. Load
    root_md = _load("Enter path to root to sign")
    prev_root = None
    if root_md.signed.version > 1:
        prev_root_md = _load("Enter path to previous root")
        prev_root = prev_root_md.signed

    # 2. Add signature, if missing
    signature = _sign_one(root_md, prev_root)

    # 3. Save, if signature was added
    if signature:
        _save(root_md)

    console.print("Bye.")
