"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

Goals
-----
- use state-of-the-art securesystemslib Signer API only
- simplify (e.g. avoid custom/redundant abstractions over Metadata API)
- configure online signer location via uri attached to public key
  (for repository-service-tuf/repository-service-tuf-worker#427)

"""

import json
import time
from copy import deepcopy
from dataclasses import asdict, dataclass
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
    Snapshot,
    Targets,
    Timestamp,
    UnsignedMetadataError,
    VerificationResult,
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


def _collect_expiry(role: str) -> Tuple[int, datetime]:
    """Prompt for expiry date (days from now)."""
    days = _PositiveIntPrompt.ask(
        f"Please enter expiry date for '{role}' role in days from now",
        default=getattr(ExpirationSettings, role),
    )
    date = datetime.utcnow() + timedelta(days=days)
    console.print(f"New expiry date is: {date:{EXPIRY_FORMAT}}")

    return days, date


@rstuf.group()  # type: ignore
def admin2():
    """POC: alternative admin interface"""


@admin2.command()  # type: ignore
@click.option(
    "--output",
    "-o",
    is_flag=False,
    flag_value="ceremony-payload.json",
    help="Write json result to FILENAME (default: 'ceremony-payload.json')",
    type=click.File("w"),
)
def ceremony(output) -> None:
    """Bootstrap Ceremony to create initial root metadata and RSTUF config.

    Will ask for public key paths and signing key paths.
    """
    console.print("\n", Markdown("# Metadata Bootstrap Tool"))

    root = Root()

    ############################################################################
    # Configure expiration and online settings
    console.print(Markdown("##  Metadata Expiration"))
    # Prompt for expiry dates
    expiration_settings = ExpirationSettings()
    for role in ["root", "timestamp", "snapshot", "targets", "bins"]:
        days, date = _collect_expiry(role)
        setattr(expiration_settings, role, days)
        if role == "root":
            root.expires = date

    console.print(Markdown("## Artifacts"))

    service_settings = ServiceSettings()
    number_of_bins = IntPrompt.ask(
        "Choose the number of delegated hash bin roles",
        default=service_settings.number_of_delegated_bins,
        choices=[str(2**i) for i in range(1, 15)],
        show_default=True,
        show_choices=True,
    )

    service_settings.number_of_delegated_bins = number_of_bins

    # TODO: validate url
    targets_base_url = Prompt.ask(
        "Please enter the targets base URL "
        "(e.g. https://www.example.com/downloads/)"
    )
    if not targets_base_url.endswith("/"):
        targets_base_url += "/"

    service_settings.targets_base_url = targets_base_url

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

    ############################################################################
    # Review Metadata
    console.print(Markdown("## Review"))

    metadata = Metadata(root)
    _show(metadata.signed)

    # TODO: ask to continue? or abort? or start over?

    ############################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))

    while True:
        result = metadata.signed.get_verification_result(
            Root.type,
            metadata.signed_bytes,
            metadata.signatures,
        )
        if result.verified:
            console.print("Metadata is fully signed.")
            break

        console.print(f"Missing {result.missing} signature(s) from any of:")
        for idx, key in enumerate(result.unsigned.values(), start=1):
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
            console.print(f"{idx}. {name}")

        prompt = "Please enter '<number>' to choose a signing key"
        choices = [str(i) for i in range(1, len(result.unsigned) + 1)]
        default = ...  # no default

        # Require at least one signature to continue
        # TODO: do not configure this policy inline
        if result.signed:
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
            break

        else:  # Get signing key
            key = list(result.unsigned.values())[choice - 1]

        while True:
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
            try:
                signer = _load_signer_from_file(key)
                metadata.sign(signer, append=True)
                console.print(f"Signed metadata with key '{name}'")
                break

            except (ValueError, OSError, UnsignedMetadataError) as e:
                console.print(f"Cannot sign metadata with key '{name}': {e}")

    metadatas = Metadatas(metadata.to_dict())
    settings = Settings(expiration_settings, service_settings)
    payload = CeremonyPayload(settings, metadatas)
    if output:
        json.dump(asdict(payload), output, indent=2)


@admin2.command()  # type: ignore
@click.argument("root_in", type=click.File("rb"))
@click.option(
    "--output",
    "-o",
    is_flag=False,
    flag_value="update-payload.json",
    help="Write json result to FILENAME (default: 'update-payload.json')",
    type=click.File("w"),
)
def update(root_in, output) -> None:
    """Update root metadata and bump version.

    Will ask for root metadata, public key paths, and signing key paths.
    """
    console.print("\n", Markdown("# Metadata Update Tool"))

    ############################################################################
    # Load root
    # TODO: load from API
    prev_root_md = Metadata[Root].from_bytes(root_in.read())
    root = deepcopy(prev_root_md.signed)

    ############################################################################
    # Configure expiration
    console.print(Markdown("## Root Expiration"))

    expired = root.is_expired()
    console.print(
        f"Root expire{'d' if expired else 's'} "
        f"on {root.expires:{EXPIRY_FORMAT}}"
    )

    if expired or Confirm.ask(
        "Do you want to change the expiry date?", default="y"
    ):
        _, date = _collect_expiry("root")
        root.expires = date

    ############################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)
    # TODO: validate default threshold policy?
    console.print(f"Current root threshold is {root_role.threshold}")
    if Confirm.ask("Do you want to change the root threshold?", default="y"):
        threshold = _PositiveIntPrompt.ask("Please enter root threshold")
        console.print(f"New root threshold is {threshold}")
        root_role.threshold = threshold

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

    ############################################################################
    # Configure Online Key

    console.print(Markdown("## Online Key"))

    current_key = _get_online_key(root)
    console.print(f"Current online key is: '{current_key.keyid}'")
    if Confirm.ask("Do you want to change the online key?", default="y"):
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
            root.add_key(new_key, role_name)

        console.print(f"Added online key: '{new_key.keyid}'")

    ############################################################################
    # Bump version
    # TODO: check if metadata changed, or else abort? start over?
    root.version += 1

    ############################################################################
    # Review Metadata
    console.print(Markdown("## Review"))
    metadata = Metadata(root)
    _show(metadata.signed)

    # TODO: ask to continue? or abort? or start over?

    ############################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))

    while True:
        results = root.get_root_verification_result(
            prev_root_md.signed,
            metadata.signed_bytes,
            metadata.signatures,
        )
        if results.verified:
            console.print("Metadata is fully signed.")
            break

        # Only show distinct unverified results
        # NOTE: I tried a few different things to construct `results_to_show`,
        # including list/dict-comprehensions, map, reduce, lambda, etc.
        # This seems the least ugly solution...
        results_to_show: list[VerificationResult] = []
        if not results.first.verified:
            results_to_show.append(results.first)

        if not results.second.verified and (
            (results.first.unsigned, results.first.missing)
            != (results.second.unsigned, results.second.missing)
        ):
            results_to_show.append(results.second)

        idx = 0
        keys_to_use: list[Key] = []
        for result in results_to_show:
            console.print(
                f"Missing {result.missing} signature(s) from any of:"
            )
            for idx, key in enumerate(result.unsigned.values(), start=idx + 1):
                name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
                console.print(f"{idx}. {name}")
                keys_to_use.append(key)

        prompt = "Please enter '<number>' to choose a signing key"
        choices = [str(i) for i in range(1, len(keys_to_use) + 1)]
        default = ...  # no default

        # Require at least one signature to continue
        # TODO: do not configure this policy inline
        if result.signed:
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
            break

        else:  # Get signing key
            key = keys_to_use[choice - 1]

        # Sign until success
        while True:
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
            try:
                signer = _load_signer_from_file(key)
                metadata.sign(signer, append=True)
                console.print(f"Signed metadata with key '{name}'")
                break

            except (ValueError, OSError, UnsignedMetadataError) as e:
                console.print(f"Cannot sign metadata with key '{name}': {e}")

    payload = UpdatePayload(Metadatas(metadata.to_dict()))
    if output:
        json.dump(asdict(payload), output, indent=2)


@admin2.command()  # type: ignore
@click.argument("root", type=click.File("rb"))
@click.argument("prev_root", type=click.File("rb"), required=False)
@click.option(
    "--output",
    "-o",
    is_flag=False,
    flag_value="sign-payload.json",
    help="Write json result to FILENAME (default: 'sign-payload.json')",
    type=click.File("w"),
)
def sign(root, prev_root, output) -> None:
    """Add one signature to root metadata."""
    console.print("\n", Markdown("# Metadata Signing Tool"))

    ############################################################################
    # Load roots
    # TODO: load from API
    metadata = Metadata[Root].from_bytes(root.read())

    if prev_root:
        prev_root = Metadata[Root].from_bytes(prev_root.read()).signed

    results = metadata.signed.get_root_verification_result(
        prev_root,
        metadata.signed_bytes,
        metadata.signatures,
    )
    if results.verified:
        console.print("Metadata is fully signed.")
        return

    ############################################################################
    # Review Metadata
    console.print(Markdown("## Review"))
    _show(metadata.signed)

    ############################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))

    # Only show distinct unverified results
    # NOTE: I tried a few different things to construct `results_to_show`,
    # including list/dict-comprehensions, map, reduce, lambda, etc.
    # This seems the least ugly solution...
    results_to_show: list[VerificationResult] = []
    if not results.first.verified:
        results_to_show.append(results.first)

    if not results.second.verified and (
        (results.first.unsigned, results.first.missing)
        != (results.second.unsigned, results.second.missing)
    ):
        results_to_show.append(results.second)

    idx = 0
    keys_to_use: list[Key] = []
    for result in results_to_show:
        console.print(f"Missing {result.missing} signature(s) from any of:")
        for idx, key in enumerate(result.unsigned.values(), start=idx + 1):
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
            console.print(f"{idx}. {name}")
            keys_to_use.append(key)

    prompt = "Please enter '<number>' to choose a signing key"
    choices = [str(i) for i in range(1, len(keys_to_use) + 1)]
    choice = IntPrompt.ask(prompt, choices=choices, show_choices=False)

    key = keys_to_use[choice - 1]

    # Sign until success
    while True:
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
        try:
            signer = _load_signer_from_file(key)
            signature = metadata.sign(signer, append=True)
            # TODO: Check if the signature is valid for the key
            console.print(f"Signed metadata with key '{name}'")
            break

        except (ValueError, OSError, UnsignedMetadataError) as e:
            console.print(f"Cannot sign metadata with key '{name}': {e}")

    payload = SignPayload(signature=signature.to_dict())
    if output:
        json.dump(asdict(payload), output, indent=2)
