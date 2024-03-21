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
    RoleSettings,
    Settings,
    _add_root_signatures_prompt,
    _configure_online_key_prompt,
    _configure_root_keys_prompt,
    _expiry_prompt,
    _online_settings_prompt,
    _print_root,
    _root_threshold_prompt,
    _warn_no_save,
)


@admin2.command()  # type: ignore
@click.option(
    "--save",
    "-s",
    is_flag=False,
    flag_value="ceremony-payload.json",
    help="Write json result to FILENAME (default: 'ceremony-payload.json')",
    type=click.File("w"),
)
def ceremony(save) -> None:
    """Bootstrap Ceremony to create initial root metadata and RSTUF config."""
    console.print("\n", Markdown("# Metadata Bootstrap Tool"))

    if not save:
        _warn_no_save()

    root = Root()

    ###########################################################################
    # Configure online role settings
    console.print(Markdown("##  Online role settings"))
    roles_settings = _online_settings_prompt()

    console.print(Markdown("##  Root expiry"))
    days, date = _expiry_prompt("root")
    root.expires = date

    # TODO: this is prone to get out of sync with root.expires
    roles_settings.root = RoleSettings(days)

    ###########################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)
    root_role.threshold = _root_threshold_prompt()
    _configure_root_keys_prompt(root)

    ###########################################################################
    # Configure Online Key
    console.print(Markdown("## Online Key"))
    _configure_online_key_prompt(root)

    ###########################################################################
    # Review Metadata
    console.print(Markdown("## Review"))
    _print_root(root)
    # TODO: ask to continue? or abort? or start over?

    ###########################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))
    root_md = Metadata(root)
    _add_root_signatures_prompt(root_md, None)

    ###########################################################################
    # Dump payload
    # TODO: post to API
    if save:
        metadatas = Metadatas(root_md.to_dict())
        settings = Settings(roles_settings)
        payload = CeremonyPayload(settings, metadatas)
        json.dump(asdict(payload), save, indent=2)
        console.print(f"Saved result to '{save.name}'")
