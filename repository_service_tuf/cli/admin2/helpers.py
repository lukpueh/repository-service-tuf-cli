"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

Advantages
----------
- use state-of-the-art securesystemslib Signer API only
- simplify (e.g. avoid custom/redundant abstractions over Metadata API)
- configure online signer location via uri attached to public key

"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

# Magic import to unbreak `load_pem_private_key` - pyca/cryptography#10315
import cryptography.hazmat.backends.openssl.backend  # noqa: F401
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.prompt import Confirm, IntPrompt, InvalidResponse, Prompt
from rich.table import Table
from securesystemslib.signer import CryptoSigner, Key, Signature, SSlibKey
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
    targets_base_url: Optional[str] = None
    targets_online_key: bool = True


@dataclass
class UpdatePayload:
    metadata: "Metadatas"


@dataclass
class SignPayload:
    signature: dict[str, str]
    role: str = "root"


##############################################################################
# Prompt and dialog helpers
class _PositiveIntPrompt(IntPrompt):
    validate_error_message = (
        "[prompt.invalid]Please enter a valid positive integer number"
    )

    def process_response(self, value: str) -> int:
        return_value: int = super().process_response(value)
        if return_value < 1:
            raise InvalidResponse(self.validate_error_message)
        return return_value


def _load_signer_from_file_prompt(public_key: SSlibKey) -> CryptoSigner:
    """Prompt for path to private key and password, return Signer."""
    path = Prompt.ask("Please enter path to encrypted private key")

    with open(path, "rb") as f:
        private_pem = f.read()

    password = Prompt.ask("Please enter password", password=True)
    private_key = load_pem_private_key(private_pem, password.encode())
    return CryptoSigner(private_key, public_key)


def _load_key_from_file_prompt() -> SSlibKey:
    """Prompt for path to public key, return Key."""
    path = Prompt.ask("Please enter path to public key")
    with open(path, "rb") as f:
        public_pem = f.read()

    crypto = load_pem_public_key(public_pem)

    key = SSlibKey.from_crypto(crypto)

    return key


def _load_key_prompt(root: Root) -> Optional[Key]:
    """Prompt and return Key, or None on error or if key is already loaded."""
    try:
        key = _load_key_from_file_prompt()

    except (OSError, ValueError) as e:
        console.print(f"Cannot load key: {e}")
        return None

    # Disallow re-adding a key even if it is for a different role.
    if key.keyid in root.keys:
        console.print("Key already in use.")
        return None

    return key


def _key_name_prompt(root) -> str:
    """Prompt for key name until success."""
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

    return name


def _expiry_prompt(role: str) -> Tuple[int, datetime]:
    """Prompt for days until expiry for role, returns days and expiry date.

    Use per-role defaults from ExpirationSettings.
    """
    days = _PositiveIntPrompt.ask(
        f"Please enter days until expiry for {role} role",
        default=getattr(ExpirationSettings, role),
    )
    date = datetime.utcnow() + timedelta(days=days)
    console.print(f"New expiry date is: {date:{EXPIRY_FORMAT}}")

    return days, date


def _expiration_settings_prompt() -> Tuple[ExpirationSettings, datetime]:
    """Prompt for expiry days for all roles, return as ExpirationSettings,
    and expiration date (for root only).

    """
    expiration_settings = ExpirationSettings()
    for role in ["root", "timestamp", "snapshot", "targets", "bins"]:
        days, date = _expiry_prompt(role)
        setattr(expiration_settings, role, days)
        if role == "root":
            root_expires = date

    return expiration_settings, root_expires


def _service_settings_prompt() -> ServiceSettings:
    """Prompt for number of bins and targets base URL,
    return as ServiceSettings."""
    number_of_bins = IntPrompt.ask(
        "Please enter number of delegated hash bins",
        default=ServiceSettings.number_of_delegated_bins,
        choices=[str(2**i) for i in range(1, 15)],
        show_default=True,
        show_choices=True,
    )
    # TODO: validate url
    targets_base_url = Prompt.ask("Please enter targets base URL")
    if not targets_base_url.endswith("/"):
        targets_base_url += "/"
    return ServiceSettings(number_of_bins, targets_base_url)


def _root_threshold_prompt() -> int:
    # TODO: validate default threshold policy?
    return _PositiveIntPrompt.ask("Please enter root threshold")


def _choose_add_remove_skip_key_prompt(
    key_count: int, allow_skip: bool
) -> int:
    """Prompt for key config user choice, return:

    -1: skip (only if `allow_skip` is true)
     0: add key
     i: remove key by index (starts at 1!)
    """

    prompt = "Please press 0 to add a key, or remove a key by its index"
    choices = [str(i) for i in range(key_count + 1)]
    default: Any = ...  # no default

    if allow_skip:
        prompt += ". Press enter to continue"
        default = -1

    return IntPrompt.ask(
        prompt,
        choices=choices,
        default=default,
        show_choices=False,
        show_default=False,
    )


def _configure_root_keys_prompt(root: Root) -> None:
    """Prompt dialog to add or remove root key in passed root, until user exit.

    - Print if and how many root keys are missing to meet the threshold
    - Print current root keys
    - Prompt for user choice to add or remove key, or to skip (exit)
        - "skip" choice is only available, if threshold is met
        - "remove" choice is only available, if keys exist
        - "add" choice is only shown, if "remove" or "skip" is available,
          otherwise, we branch right into "add" dialog

    """

    root_role = root.get_delegated_role(Root.type)
    while True:
        _print_current_root_keys(root)

        missing = max(0, root_role.threshold - len(root_role.keyids))
        _print_missing_key_info(root_role.threshold, missing)

        # Prompt for choice unless user must add keys
        if not root_role.keyids:
            choice = 0

        else:
            allow_skip = not missing
            choice = _choose_add_remove_skip_key_prompt(
                len(root_role.keyids), allow_skip
            )

        # Apply choice
        if choice == -1:  # skip
            break

        elif choice == 0:  # add
            new_key = _load_key_prompt(root)
            if not new_key:
                continue

            name = _key_name_prompt(root)
            new_key.unrecognized_fields[KEY_NAME_FIELD] = name
            root.add_key(new_key, Root.type)
            console.print(f"Added root key '{name}'")

        else:  # remove
            keyid = root_role.keyids[choice - 1]
            key = root.get_key(keyid)
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, keyid)
            root.revoke_key(keyid, Root.type)
            console.print(f"Removed root key '{name}'")


def _configure_online_key_prompt(root: Root) -> None:
    """Prompt dialog to set or optionally update the online key."""
    current_key = _get_online_key(root)
    if current_key:
        # TODO: Is the info even helpful?
        console.print(f"Current online key is: '{current_key.keyid}'")
        if not Confirm.ask(
            "Do you want to change the online key?", default=True
        ):
            return

    while True:
        if new_key := _load_key_prompt(root):
            break

    uri = f"fn:{new_key.keyid}"
    new_key.unrecognized_fields[KEY_URI_FIELD] = uri
    for role_name in ONLINE_ROLE_NAMES:
        if current_key:
            root.revoke_key(current_key.keyid, role_name)
        root.add_key(new_key, role_name)

    console.print(f"Configured file-based online key: '{new_key.keyid}'")
    console.print(f"Expected private key file name is: '{new_key.keyid}'")


def _choose_signing_key_prompt(key_count: int, allow_skip: bool) -> int:
    """Prompt for signing key user choice, return:

    -1: skip (only if `allow_skip` is true)
     i: signing key by index (starts at 1!)
    """

    prompt = "Please enter signing key index"
    choices = [str(i) for i in range(1, key_count + 1)]
    default: Any = ...  # no default

    if allow_skip:
        prompt += ", or press enter to continue"
        default = -1

    return IntPrompt.ask(
        prompt,
        choices=choices,
        default=default,
        show_choices=False,
        show_default=False,
    )


def _add_signature_prompt(metadata: Metadata, key: Key) -> Signature:
    """Prompt for signing key and add signature to metadata until success."""
    while True:
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
        try:
            signer = _load_signer_from_file_prompt(key)
            # TODO: Check if the signature is valid for the key?
            signature = metadata.sign(signer, append=True)
            break

        except (ValueError, OSError, UnsignedMetadataError) as e:
            console.print(f"Cannot sign metadata with key '{name}': {e}")

    console.print(f"Signed metadata with key '{name}'")
    return signature


def _add_root_signatures_prompt(
    root_md: Metadata[Root], prev_root: Optional[Root]
) -> None:
    # TODO: Add docstring
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

        choice = _choose_signing_key_prompt(
            len(keys), allow_skip=bool(root_result.signed)
        )
        if choice == -1:
            break

        else:
            key = keys[choice - 1]

        _add_signature_prompt(root_md, key)


##############################################################################
# Other helpers


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


def _print_root(root: Root):
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


def _filter_root_verification_results(
    root_result: RootVerificationResult,
) -> list[VerificationResult]:
    """Filter unverified distinct results."""
    # NOTE: Tried a few different things to construct `results`,
    # including list/dict-comprehensions, map, reduce, lambda, etc.
    # This seems the least ugly / most readable solution:
    results: list[VerificationResult] = []
    if not root_result.first.verified:
        results.append(root_result.first)

    if not root_result.second.verified and (
        root_result.first.verified
        or (
            (root_result.first.unsigned, root_result.first.missing)
            != (root_result.second.unsigned, root_result.second.missing)
        )
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


def _print_current_root_keys(root: Root) -> None:
    root_role = root.get_delegated_role(Root.type)
    console.print("Current signing keys are:")
    for idx, keyid in enumerate(root_role.keyids, start=1):
        key = root.get_key(keyid)
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, keyid)
        console.print(f"{idx}. {name}")


def _print_missing_key_info(threshold: int, missing: int) -> None:
    if missing:
        console.print(
            f"{missing} more key(s) needed for threshold {threshold}"
        )
    else:
        console.print(f"Threshold {threshold} met, more keys can be added.")
