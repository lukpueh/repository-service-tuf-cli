"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

Goals
-----
- use state-of-the-art securesystemslib Signer API only
- simplify (e.g. avoid custom/redundant abstractions over Metadata API)
- configure online signer location via uri attached to public key
  (for repository-service-tuf/repository-service-tuf-worker#427)

"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import click

# Magic import to unbreak `load_pem_private_key` - pyca/cryptography#10315
import cryptography.hazmat.backends.openssl.backend  # noqa: F401
from click import ClickException
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.prompt import Confirm, IntPrompt, InvalidResponse, Prompt
from rich.table import Table
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
    VerificationResult,
)

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console

ONLINE_ROLE_NAMES = {Timestamp.type, Snapshot.type, Targets.type}

KEY_URI_FIELD = "x-rstuf-online-key-uri"
KEY_NAME_FIELD = "x-rstuf-key-name"

# Use locale's appropriate date representation to display the expiry date.
EXPIRY_FORMAT = "%x"


@dataclass
class CeremonyPayload:
    settings: "Settings"
    metadata: "Metadatas"


@dataclass
class Metadatas:  # accept bad spelling to disambiguate with Metadata
    root: dict[str, Any]


@dataclass
class Settings:
    expiration: "ExpirationSettings"
    services: "ServiceSettings"


@dataclass
class ExpirationSettings:
    root: int = 365
    targets: int = 365
    snapshot: int = 1
    timestamp: int = 1
    bins: int = 1


@dataclass
class ServiceSettings:
    number_of_delegated_bins: int = 256
    targets_base_url: str = None
    targets_online_key: bool = True


@dataclass
class UpdatePayload:
    metadata: "Metadatas"


@dataclass
class SignPayload:
    role: str = "root"
    signature: dict[str, str] = None


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


def _get_root_keys(root: Root) -> Dict[str, Key]:
    return {
        keyid: root.get_key(keyid) for keyid in root.roles[Root.type].keyids
    }


def _get_online_key(root: Root) -> Optional[Key]:
    # TODO: assert all online roles have the same and only one keyid, or none
    key = None
    if root.roles[Timestamp.type].keyids:
        key = root.get_key(root.roles[Timestamp.type].keyids[0])

    return key


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


def _collect_expiry(role: str) -> Tuple[int, datetime]:
    """Prompt for expiry date (days from now)."""
    days = _PositiveIntPrompt.ask(
        f"Please enter expiry date for '{role}' role in days from now",
        default=getattr(ExpirationSettings, role),
    )
    date = datetime.utcnow() + timedelta(days=days)
    console.print(f"New expiry date is: {date:{EXPIRY_FORMAT}}")

    return days, date


def _configure_root_keys(root: Root) -> None:
    """Prompt dialog to add or remove root key in passed root, until user exit.

    - Print if and how many root keys are missing to meet the threshold
    - Print current root keys
    - Prompt for user choice to add or remove key, or to continue (exit)
        - "continue" choice is only available, if threshold is met
        - "remove" choice is only available, if keys exist
        - "add" choice is only shown, if "remove" or "exit" is also available,
          otherwise, we branch right into "add" dialog

    """

    root_role = root.get_delegated_role(Root.type)
    while True:
        # Show current signing keys
        if root_role.keyids:
            console.print("Current signing keys are:")
            for idx, keyid in enumerate(root_role.keyids, start=1):
                new_key = root.get_key(keyid)
                name = new_key.unrecognized_fields.get(KEY_NAME_FIELD, keyid)
                console.print(f"{idx}. {name}")

        # Show missing key info
        missing = max(0, root_role.threshold - len(root_role.keyids))
        if missing:
            console.print(
                f"{missing} more key(s) needed to meet threshold {root_role.threshold}"
            )
        else:
            console.print(
                f"Threshold {root_role.threshold} met, more keys can be added."
            )

        # Skip prompt, if user must add key
        if not root_role.keyids:
            choice = 0

        else:
            prompt = (
                "Please press '0' to add key, "
                "or enter '<number>' to remove key"
            )
            choices = [str(i) for i in range(len(root_role.keyids) + 1)]
            default = ...  # no default

            if not missing:
                prompt += ". Press enter to continue"
                default = -1

            choice = IntPrompt.ask(
                prompt,
                choices=choices,
                default=default,
                show_choices=False,
                show_default=False,
            )

        if choice == -1:  # Continue
            break

        elif choice == 0:  # Add key
            try:
                new_key = _load_public_key_from_file()
            except (OSError, ValueError) as e:
                console.print(f"Cannot load: {e}")
                continue

            if new_key.keyid in root.keys:
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

            new_key.unrecognized_fields[KEY_NAME_FIELD] = name
            root.add_key(new_key, Root.type)
            console.print(f"Added root key '{name}'")

        else:  # Remove key
            keyid = root_role.keyids[choice - 1]
            new_key = root.get_key(keyid)
            name = new_key.unrecognized_fields.get(KEY_NAME_FIELD, keyid)
            root.revoke_key(keyid, Root.type)
            console.print(f"Removed '{name}'")


def _configure_online_key(root: Root) -> None:
    """Prompt dialog to set or optionally update the online key."""
    current_key = _get_online_key(root)
    if current_key:
        console.print(f"Current online key is: '{current_key.keyid}'")
        if not Confirm.ask(
            "Do you want to change the online key?", default="y"
        ):
            return

    while True:
        try:
            new_key = _load_public_key_from_file()

        except (OSError, ValueError) as e:
            console.print(f"Cannot load: {e}")
            continue

        # Disallow re-adding a key even if it is for a different role.
        if new_key.keyid in root.keys:
            console.print("Key already in use.")
            continue

        break

    uri = f"fn:{new_key.keyid}"
    new_key.unrecognized_fields[KEY_URI_FIELD] = uri
    for role_name in ONLINE_ROLE_NAMES:
        if current_key:
            root.revoke_key(current_key.keyid, role_name)
        root.add_key(new_key, role_name)

    console.print(f"Added online key: '{new_key.keyid}'")


def _filter_root_verification_results(
    root_result: RootVerificationResult,
) -> list[VerificationResult]:
    """Filter unverified results with distinct 'missing' and 'unsigned' fields."""
    # NOTE: Tried a few different things to construct `results`,
    # including list/dict-comprehensions, map, reduce, lambda, etc.
    # This seems the least ugly solution...
    results: list[VerificationResult] = []
    if not root_result.first.verified:
        results.append(root_result.first)

    if not root_result.second.verified and (
        (root_result.first.unsigned, root_result.first.missing)
        != (root_result.second.unsigned, root_result.second.missing)
    ):
        results.append(root_result.second)

    return results


def _filter_and_print_keys_for_signing(
    results: list[VerificationResult],
) -> list[Key]:
    keys: list[Key] = []
    idx = 0
    for result in results:
        console.print(f"Missing {result.missing} signature(s) from any of:")
        for idx, key in enumerate(result.unsigned.values(), start=idx + 1):
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
            console.print(f"{idx}. {name}")
            keys.append(key)

    return keys


def _choose_key_for_signing(keys: list[Key], allow_skip) -> Optional[Key]:
    prompt = "Please enter '<number>' to choose a signing key"
    choices = [str(i) for i in range(1, len(keys) + 1)]
    default = ...  # no default

    # Require at least one signature to continue
    # TODO: do not configure this policy inline
    if allow_skip:
        prompt += ", or press enter to continue"
        default = -1

    choice = IntPrompt.ask(
        prompt,
        choices=choices,
        default=default,
        show_choices=False,
        show_default=False,
    )

    if choice == -1:  # Continue
        return None

    # Get signing key
    return keys[choice - 1]


def _add_signature(metadata: Metadata, key: Key) -> Signature:
    while True:
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
        try:
            signer = _load_signer_from_file(key)
            # TODO: Check if the signature is valid for the key?
            signature = metadata.sign(signer, append=True)
            break

        except (ValueError, OSError, UnsignedMetadataError) as e:
            console.print(f"Cannot sign metadata with key '{name}': {e}")

    console.print(f"Signed metadata with key '{name}'")
    return signature


def _add_root_signatures(
    root_md: Metadata[Root], prev_root: Optional[Root]
) -> None:

    while True:
        root_result = root_md.signed.get_root_verification_result(
            prev_root,
            root_md.signed_bytes,
            root_md.signatures,
        )
        if root_result.verified:
            console.print("Metadata is fully signed.")
            break

        results = _filter_root_verification_results(root_result)
        keys = _filter_and_print_keys_for_signing(results)

        allow_skip = bool(root_result.signed)
        key = _choose_key_for_signing(keys, allow_skip)

        if not key:
            break

        _add_signature(root_md, key)
