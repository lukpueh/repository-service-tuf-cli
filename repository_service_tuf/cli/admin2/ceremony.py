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
    CeremonyPayload,
    Metadatas,
    Settings,
    _add_root_signatures,
    _collect_expiration_settings_and_root_expires,
    _collect_root_threshold,
    _collect_service_settings,
    _configure_online_key,
    _configure_root_keys,
    _show,
)


@admin2.command()  # type: ignore
@click.option(
    "--payload-out",
    "-o",
    is_flag=False,
    flag_value="ceremony-payload.json",
    help="Write json result to FILENAME (default: 'ceremony-payload.json')",
    type=click.File("w"),
)
def ceremony(payload_out) -> None:
    """Bootstrap Ceremony to create initial root metadata and RSTUF config."""
    console.print("\n", Markdown("# Metadata Bootstrap Tool"))

    root = Root()

    ###########################################################################
    # Configure expiration and online service settings
    console.print(Markdown("##  Metadata Expiration"))
    expiration_settings, root_expires = (
        _collect_expiration_settings_and_root_expires()
    )
    root.expires = root_expires

    console.print(Markdown("## Artifacts"))
    service_settings = _collect_service_settings()

    ###########################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)
    root_role.threshold = _collect_root_threshold()
    _configure_root_keys(root)

    ###########################################################################
    # Configure Online Key
    console.print(Markdown("## Online Key"))
    _configure_online_key(root)

    ###########################################################################
    # Review Metadata
    console.print(Markdown("## Review"))
    _show(root)
    # TODO: ask to continue? or abort? or start over?

    ###########################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))
    root_md = Metadata(root)
    _add_root_signatures(root_md, None)

    ###########################################################################
    # Dump payload
    # TODO: post to API
    if payload_out:
        metadatas = Metadatas(root_md.to_dict())
        settings = Settings(expiration_settings, service_settings)
        payload = CeremonyPayload(settings, metadatas)
        json.dump(asdict(payload), payload_out, indent=2)
