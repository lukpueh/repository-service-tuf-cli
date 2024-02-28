import json
from copy import deepcopy
from dataclasses import asdict

import click
from rich.markdown import Markdown
from rich.prompt import Confirm
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
    EXPIRY_FORMAT,
    Metadatas,
    UpdatePayload,
    _add_root_signatures,
    _collect_expiry,
    _configure_online_key,
    _configure_root_keys,
    _PositiveIntPrompt,
    _show,
)


@admin2.command()  # type: ignore
@click.argument("root_in", type=click.File("rb"))
@click.option(
    "--payload-out",
    "-o",
    is_flag=False,
    flag_value="update-payload.json",
    help="Write json result to FILENAME (default: 'update-payload.json')",
    type=click.File("w"),
)
def update(root_in, payload_out) -> None:
    """Update root metadata and bump version.

    Will ask for root metadata, public key paths, and signing key paths.
    """
    console.print("\n", Markdown("# Metadata Update Tool"))

    ###########################################################################
    # Load root
    # TODO: load from API
    prev_root_md = Metadata[Root].from_bytes(root_in.read())
    root = deepcopy(prev_root_md.signed)

    ###########################################################################
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

    ###########################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)

    # TODO: validate default threshold policy?
    console.print(f"Current root threshold is {root_role.threshold}")
    if Confirm.ask("Do you want to change the root threshold?", default="y"):
        threshold = _PositiveIntPrompt.ask("Please enter root threshold")
        console.print(f"New root threshold is {threshold}")
        root_role.threshold = threshold

    _configure_root_keys(root)

    ###########################################################################
    # Configure Online Key

    console.print(Markdown("## Online Key"))
    _configure_online_key(root)

    ###########################################################################
    # Bump version
    # TODO: check if metadata changed, or else abort? start over?
    root.version += 1

    ###########################################################################
    # Review Metadata
    console.print(Markdown("## Review"))

    root_md = Metadata(root)
    _show(root_md.signed)

    # TODO: ask to continue? or abort? or start over?

    ###########################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))
    _add_root_signatures(root_md, prev_root_md.signed)

    payload = UpdatePayload(Metadatas(root_md.to_dict()))
    if payload_out:
        json.dump(asdict(payload), payload_out, indent=2)
