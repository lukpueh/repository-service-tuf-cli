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
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse

import click
from click import ClickException
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from requests import request
from requests.exceptions import RequestException
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.table import Table
from securesystemslib.signer import CryptoSigner, Key, Signature, Signer
from tuf.api.metadata import Metadata, Root, Timestamp, UnsignedMetadataError

from repository_service_tuf.cli import console, rstuf
from repository_service_tuf.helpers.api_client import URL as ROUTE


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


@dataclass
class VerificationResult:
    """tuf.api.metadata.VerificationResult but with Keys objects

    Likely upstreamed (theupdateframework/python-tuf#2544)
    """

    verified: bool
    signed: Dict[str, Key]
    unsigned: Dict[str, Key]
    threshold: int


def _get_verification_result(
    delegator: Root, delegate: Metadata[Root]
) -> VerificationResult:
    """Return signature verification result for delegate."""
    result = delegator.get_verification_result(
        Root.type, delegate.signed_bytes, delegate.signatures
    )
    signed = {keyid: delegator.get_key(keyid) for keyid in result.signed}
    unsigned = {keyid: delegator.get_key(keyid) for keyid in result.unsigned}

    threshold = delegator.roles[Root.type].threshold

    return VerificationResult(result.verified, signed, unsigned, threshold)


@dataclass
class MissingSignatures:
    """Missing signature info.

    Attributes:
        keys: Keys that can be used to reach the threshold.
        num: Number of keys that must be used to reach the threshold.
    """

    keys: Dict[str, Key]
    num: int


def _get_missing_sig_infos(
    metadata: Metadata[Root], prev_root: Optional[Root]
) -> Tuple[List[MissingSignatures]]:
    """Verify signatures and return unique per-delegator missing sig infos."""

    infos = []
    result = _get_verification_result(metadata.signed, metadata)
    if not result.verified:
        missing = MissingSignatures(
            result.unsigned, result.threshold - len(result.signed)
        )
        infos.append(missing)

    if prev_root:
        prev_result = _get_verification_result(prev_root, metadata)
        if not prev_result.verified:
            prev_missing = MissingSignatures(
                prev_result.unsigned,
                prev_result.threshold - len(prev_result.signed),
            )
            if prev_missing not in infos:
                infos.append(prev_missing)

    return infos


def _show_missing_sig_infos(
    missing_sig_infos: List[MissingSignatures],
) -> None:
    for info in missing_sig_infos:
        title = f"Please add {info.num} more signature(s) from any of "

        key_table = Table("ID", "Name", title=title)
        for keyid, key in info.keys.items():
            name = key.unrecognized_fields.get("name", "-")
            key_table.add_row(keyid, name)

        console.print(key_table)


def _sign_one(
    metadata: Metadata[Root], prev_root: Optional[Root]
) -> Optional[Signature]:
    """Prompt loop to add one signature.

    Return None, if metadata is already fully missing.
    Otherwise, loop until success and returns the added signature.
    """
    missing_sig_infos = _get_missing_sig_infos(metadata, prev_root)
    if not missing_sig_infos:
        console.print("Metadata fully signed.")
        return None

    # Merge unused keys from 1 or 2 missing sigs infos
    unused_keys = {
        keyid: key
        for info in missing_sig_infos
        for keyid, key in info.keys.items()
    }

    _show(metadata.signed)
    _show_missing_sig_infos(missing_sig_infos)

    # Loop until success
    signature = None
    while not signature:
        signature = _sign(metadata, unused_keys)

    return signature


def _sign(metadata: Metadata, keys: Dict[str, Key]) -> Optional[Signature]:
    """Prompt for signing key and sign.

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


def _get_root_keys(root: Root) -> List[Key]:
    return [root.get_key(keyid) for keyid in root.roles[Root.type].keyids]


def _get_online_key(root: Root) -> Key:
    # TODO: assert all online roles have the same and only one keyid
    return root.get_key(root.roles[Timestamp.type].keyids[0])


def _show(root: Root):
    """Pretty print root metadata."""

    key_table = Table("Role", "ID", "Name", "Signing Scheme", "Public Value")
    for key in _get_root_keys(root):
        public_value = key.keyval["public"]  # SSlibKey-specific
        name = key.unrecognized_fields.get("name", "-")
        key_table.add_row("Root", key.keyid, name, key.scheme, public_value)
    key = _get_online_key(root)
    key_table.add_row(
        "Online", key.keyid, "-", key.scheme, key.keyval["public"]
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


def _request(method: str, url: str, **kwargs: Any) -> Dict[str, Any]:
    """HTTP requests helper.

    Returns deserialized contents, and raises on error.
    """
    response = request(method, url, **kwargs)
    response.raise_for_status()
    response_data = response.json()["data"]
    return response_data


def _wait_for_success(server: str, task_id: str) -> None:
    """Poll task API indefinitely until async task finishes.

    Raises RuntimeError, if task fails.
    """
    task_url = parse.urljoin(server, ROUTE.TASK.value + task_id)
    while True:
        response_data = _request("get", task_url)
        state = response_data["state"]

        if state in ["PENDING", "RECEIVED", "STARTED", "RUNNING"]:
            time.sleep(2)
            continue

        if state == "SUCCESS":
            if response_data["result"]["status"]:
                break

        raise RuntimeError(response_data)


def _fetch_metadata(
    api_server: str,
) -> Tuple[Optional[Metadata[Root]], Optional[Root]]:
    """Fetch from Metadata Sign API."""
    sign_url = parse.urljoin(api_server, ROUTE.METADATA_SIGN.value)
    response_data = _request("get", sign_url)
    metadata = response_data["metadata"]
    root_data = metadata.get("root")

    root_md = None
    prev_root = None
    if root_data:
        root_md = Metadata[Root].from_dict(root_data)
        if root_md.signed.version > 1:
            prev_root_data = metadata["trusted_root"]
            prev_root_md = Metadata[Root].from_dict(prev_root_data)
            prev_root = prev_root_md.signed

    return root_md, prev_root


def _push_signature(api_server: str, signature: Signature) -> None:
    """Post signature and wait for success of async task."""
    sign_url = parse.urljoin(api_server, ROUTE.METADATA_SIGN.value)
    request_data = {"role": "root", "signature": signature.to_dict()}
    response_data = _request("post", sign_url, json=request_data)
    task_id = response_data["task_id"]
    _wait_for_success(api_server, task_id)


@rstuf.group()  # type: ignore
def admin2():
    """POC: alternative admin interface"""


@admin2.command()  # type: ignore
@click.option(
    "--api-server",
    help="URL to the RSTUF API.",
    required=True,
)
def sign(api_server: str) -> None:
    """Add one signature to root metadata."""
    console.print("\n", Markdown("# Metadata Signing Tool"))

    try:
        root_md, prev_root = _fetch_metadata(api_server)

    except RequestException as e:
        raise ClickException(str(e))

    if not root_md:
        console.print(f"Nothing to sign on {api_server}.")

    else:
        signature = _sign_one(root_md, prev_root)
        if signature:
            try:
                _push_signature(api_server, signature)

            except (RequestException, RuntimeError) as e:
                raise ClickException(str(e))
