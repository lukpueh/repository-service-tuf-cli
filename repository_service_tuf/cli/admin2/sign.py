import json
from dataclasses import asdict

import click
from rich.markdown import Markdown
from tuf.api.metadata import Metadata, Root

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin2 import admin2
from repository_service_tuf.cli.admin2.helpers import (
    SignPayload,
    _add_signature,
    _choose_key_for_signing,
    _filter_and_print_keys_for_signing,
    _filter_root_verification_results,
    _show,
)


@admin2.command()  # type: ignore
@click.argument("root_in", type=click.File("rb"))
@click.argument("prev_root_in", type=click.File("rb"), required=False)
@click.option(
    "--payload-out",
    "-o",
    is_flag=False,
    flag_value="sign-payload.json",
    help="Write json result to FILENAME (default: 'sign-payload.json')",
    type=click.File("w"),
)
def sign(root_in, prev_root_in, payload_out) -> None:
    """Add one signature to root metadata."""
    console.print("\n", Markdown("# Metadata Signing Tool"))

    ###########################################################################
    # Load roots
    # TODO: load from API
    root_md = Metadata[Root].from_bytes(root_in.read())

    prev_root = None
    if prev_root_in:
        prev_root = Metadata[Root].from_bytes(prev_root_in.read()).signed

    ###########################################################################
    # Verify signatures
    root_result = root_md.signed.get_root_verification_result(
        prev_root,
        root_md.signed_bytes,
        root_md.signatures,
    )
    if root_result.verified:
        console.print("Metadata is fully signed.")
        return

    ###########################################################################
    # Review metadata
    console.print(Markdown("## Review"))
    _show(root_md.signed)

    ###########################################################################
    # Sign metadata
    console.print(Markdown("## Sign"))
    results = _filter_root_verification_results(root_result)
    keys = _filter_and_print_keys_for_signing(results)
    key = _choose_key_for_signing(keys, allow_skip=False)
    signature = _add_signature(root_md, key)

    ###########################################################################
    # Dump payload
    # TODO: post to API
    if payload_out:
        payload = SignPayload(signature=signature.to_dict())
        json.dump(asdict(payload), payload_out, indent=2)
