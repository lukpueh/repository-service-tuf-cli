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
- finalize update
  - beautify (see pr comments)
  - api integration
  - cli options to save payload, or send payload only
  - assert one valid signature before pushing / saving

- implement ceremony

"""

import time
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import click

# Magic import to unbreak `load_pem_private_key` - pyca/cryptography#10315
import cryptography.hazmat.backends.openssl.backend  # noqa: F401
from click import ClickException
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from requests import request
from requests.exceptions import RequestException
from rich.markdown import Markdown
from rich.prompt import Confirm, IntPrompt, InvalidResponse, Prompt
from rich.table import Table
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
    RootVerificationResult,
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
from repository_service_tuf.helpers.api_client import URL as ROUTE

ONLINE_ROLE_NAMES = {Timestamp.type, Snapshot.type, Targets.type}

KEY_URI_FIELD = "x-rstuf-online-key-uri"
KEY_NAME_FIELD = "x-rstuf-key-name"

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


def _load_signer_from_file(public_key: Key) -> Signer:
    """Ask for details to load signer, load and return."""
    path = Prompt.ask("Please enter path to encrypted local private key")

    with open(path, "rb") as f:
        private_pem = f.read()

    password = Prompt.ask("Please enter password", password=True)
    private_key = load_pem_private_key(private_pem, password.encode())
    return CryptoSigner(private_key, public_key)


def _show_missing_signatures(results: RootVerificationResult) -> None:
    results_to_show = [results.first]
    # Show only one result, if the same number of signatures from the same set
    # of keys is missing in both.
    if (
        results.second.unsigned != results.first.unsigned
        or results.second.missing != results.first.missing
    ):
        results_to_show.append(results.second)

    for result in results_to_show:
        title = f"Please add {result.missing} more signature(s) from any of "
        key_table = Table("ID", "Name", title=title)

        for keyid, key in result.unsigned.items():
            name = key.unrecognized_fields.get(KEY_NAME_FIELD)
            key_table.add_row(keyid, name)

        console.print(key_table)


def _get_missing_keys(results: RootVerificationResult) -> dict[str, Key]:
    missing_keys = {}
    # Use only those keys to sign, whose signatures are effectively missing.
    # This also means the cli can't be used to sign beyond the threshold.
    if not results.first.verified:
        missing_keys.update(results.first.unsigned)

    if not results.second.verified:
        missing_keys.update(results.second.unsigned)

    return missing_keys

def _sign_multiple(
    metadata: Metadata[Root],
    prev_root: Optional[Root],
) -> Optional[list[Signature]]:
    """Prompt loop to add signatures to root.

    Prints metadata for review once, and signature requirements.
    Loops until fully signed or user exit.
    """
    console.print(Markdown("## Signing"))

    signatures: List[Signature] = []
    show_metadata = True
    while True:
        results = metadata.signed.get_root_verification_result(
            prev_root,
            metadata.signed_bytes,
            metadata.signatures,
        )

        if results.verified:
            console.print("Metadata is fully signed.")
            return signatures

        # Show metadata for review once
        if show_metadata:
            _show(metadata.signed)
            show_metadata = False

        _show_missing_signatures(results)
        missing_keys = _get_missing_keys(results)
        # Loop until signing success or user exit
        while True:
            if not Confirm.ask("Do you want to sign?"):
                return signatures

            signature = _sign(metadata, missing_keys)
            if signature:
                signatures.append(signature)
                break


def _sign(metadata: Metadata, keys: Dict[str, Key]) -> Optional[Signature]:
    """Prompt for signing key and sign.

    Return Signature or None, if signing fails.
    """
    signature = None
    choice, key = _choose_key("sign", keys)
    try:
        signer = _load_signer(key)
        signature = metadata.sign(signer, append=True)
        console.print(f"Signed metadata with key '{choice}'")

    except (ValueError, OSError, UnsignedMetadataError) as e:
        console.print(f"Cannot sign metadata with key '{choice}': {e}")

    return signature

def _get_root_keys(root: Root) -> Dict[str, Key]:
    return {
        keyid: root.get_key(keyid) for keyid in root.roles[Root.type].keyids
    }

def _get_online_key(root: Root) -> Key:
    # TODO: assert all online roles have the same and only one keyid
    return root.get_key(root.roles[Timestamp.type].keyids[0])


def _show(root: Root):
    """Pretty print root metadata."""

    key_table = Table("Role", "ID", "Name", "Signing Scheme", "Public Value")
    for key in _get_root_keys(root).values():
        public_value = key.keyval["public"]  # SSlibKey-specific
        name = key.unrecognized_fields.get(KEY_NAME_FIELD)
        key_table.add_row("Root", key.keyid, name, key.scheme, public_value)

    key = _get_online_key(root)
    key_table.add_row(
        "Online", key.keyid, "", key.scheme, key.keyval["public"]
    )

    root_table = Table("Infos", "Keys", title="Root Metadata")
    root_table.add_row(
        (
            f"Expiration: {root.expires:%x}\n"
            f"Threshold: {root.roles[Root.type].threshold}"
        ),
        key_table,
    )

    console.print(root_table)


@rstuf.group()  # type: ignore
def admin2():
    """POC: alternative admin interface"""


@admin2.command()  # type: ignore
def ceremony() -> None:
    """Bootstrap Ceremony to create initial root metadata and RSTUF config.

    Will ask for public key paths and signing key paths.
    """
    console.print("\n", Markdown("# Metadata Bootstrap Tool"))

    root = Root()

    ############################################################################
    # Configure expiration and online settings
    console.print(Markdown("##  Metadata Expiration"))
    # Prompt for expiry dates
    expiry_dates = {}
    for role in ["root", "timestamp", "snapshot", "targets", "bins"]:
        days = _PositiveIntPrompt.ask(
            "Please enter number of days from now, "
            f"when {role} should expire",
            default=100,  # TODO: use per-role constants as default
        )
        expiry_date = datetime.utcnow() + timedelta(days=days)
        console.print(f"{role} expires on {expiry_date:{EXPIRY_FORMAT}}")
        expiry_dates[role] = expiry_date

    # Set root expiration
    root.expires = expiry_dates["root"]
    # TODO: include other dates in payload

    console.print(Markdown("## Artifacts"))

    # TODO: include in payload
    number_of_bins = IntPrompt.ask(
        "Choose the number of delegated hash bin roles",
        default=256,  # TODO: use constant as default
        choices=[str(2**i) for i in range(1, 15)],
        show_default=True,
        show_choices=True,
    )

    # TODO: include in payload
    # TODO: validate url
    targets_base_url = Prompt.ask(
        "Please enter the targets base URL "
        "(e.g. https://www.example.com/downloads/)"
    )
    if not targets_base_url.endswith("/"):
        targets_base_url += "/"

    ############################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)

    # TODO: validate default threshold policy?
    threshold = _PositiveIntPrompt.ask("Please enter root threshold")
    root_role.threshold = threshold

    while True:
        # Show current signing keys
        if root_role.keyids:
            console.print("Current signing keys are:")
            for idx, keyid in enumerate(root_role.keyids, start=1):
                key = root.get_key(keyid)
                name = key.unrecognized_fields.get(KEY_NAME_FIELD, keyid)
                console.print(f"{idx}. {name}")

        # Show missing key info
        missing = max(0, threshold - len(root_role.keyids))
        if missing:
            console.print(
                f"{missing} more key(s) needed to meet threshold {threshold}"
            )
        else:
            console.print(
                f"Threshold {threshold} met, more keys can be added."
            )

        # Show prompt, or skip if the user can only add keys
        if root_role.keyids:
            prompt = (
                "Please press '0' to add key, "
                "or enter '<number>' to remove key"
            )
            default = None
            if not missing:
                prompt += ". Press enter to continue"
                default = -1

            choice = IntPrompt.ask(
                prompt,
                choices=[str(i) for i in range(-1, len(root_role.keyids) + 1)],
                default=default,
                show_choices=False,
                show_default=False,
            )

        else:
            choice = 0

        if choice == -1:  # Continue
            break

        elif choice == 0:  # Add key
            try:
                key = _load_public_key_from_file()
            except (OSError, ValueError) as e:
                console.print(f"Cannot load: {e}")
                continue

            if key.keyid in root.keys:
                console.print("Key already in use.")
                continue

            while True:
                name = Prompt.ask("Please enter a key name")
                if not name:
                    console.print("Key name cannot be empty.")
                    continue
                if name in [
                    k.unrecognized_fields.get(KEY_NAME_FIELD)
                    for k in root.keys.values()
                ]:
                    console.print("Key name already in use.")
                    continue
                break

            key.unrecognized_fields[KEY_NAME_FIELD] = name
            root.add_key(key, Root.type)
            console.print(f"Added root key '{name}'")

        else:  # Remove key
            keyid = root_role.keyids[choice - 1]
            key = root.get_key(keyid)
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, keyid)
            root.revoke_key(keyid, Root.type)
            console.print(f"Removed '{name}'")


    ############################################################################
    # Configure Online Key
    console.print(Markdown("## Online Key"))

    while True:
        try:
            key = _load_public_key_from_file()

        except (OSError, ValueError) as e:
            console.print(f"Cannot load: {e}")
            continue

        # Disallow re-adding a key even if it is for a different role.
        if key.keyid in root.keys:
            console.print("Key already in use.")
            continue

        break

    uri = f"fn:{key.keyid}"
    key.unrecognized_fields[KEY_URI_FIELD] = uri
    for role_name in ONLINE_ROLE_NAMES:
        root.add_key(key, role_name)

    console.print(f"Added online key: '{key.keyid}'")

    # Sign
    console.print(Markdown("## Sign"))
    root_md = Metadata(root)
    _sign_multiple(root_md, None)
