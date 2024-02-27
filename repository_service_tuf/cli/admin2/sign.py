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

    ###########################################################################
    # Load roots
    # TODO: load from API
    metadata = Metadata[Root].from_bytes(root.read())

    if prev_root:
        prev_root = Metadata[Root].from_bytes(prev_root.read()).signed

    root_result = metadata.signed.get_root_verification_result(
        prev_root,
        metadata.signed_bytes,
        metadata.signatures,
    )
    if root_result.verified:
        console.print("Metadata is fully signed.")
        return

    ###########################################################################
    # Review Metadata
    console.print(Markdown("## Review"))
    _show(metadata.signed)

    ###########################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))
    results = _filter_root_verification_results(root_result)
    keys = _filter_and_print_keys_for_signing(results)
    key = _choose_key_for_signing(keys, allow_skip=False)
    signature = _add_signature(metadata, key)

    payload = SignPayload(signature=signature.to_dict())
    if output:
        json.dump(asdict(payload), output, indent=2)
