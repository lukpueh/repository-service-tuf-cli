import json
from dataclasses import asdict

import click
from rich.markdown import Markdown
from rich.prompt import IntPrompt, Prompt
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
    ExpirationSettings,
    Metadatas,
    ServiceSettings,
    Settings,
    _add_root_signatures,
    _collect_expiry,
    _configure_online_key,
    _configure_root_keys,
    _PositiveIntPrompt,
    _show,
)


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

    ###########################################################################
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

    ###########################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)

    # TODO: validate default threshold policy?
    threshold = _PositiveIntPrompt.ask("Please enter root threshold")
    root_role.threshold = threshold

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
    metadata = Metadata(root)
    _add_root_signatures(metadata, None)

    metadatas = Metadatas(metadata.to_dict())
    settings = Settings(expiration_settings, service_settings)
    payload = CeremonyPayload(settings, metadatas)
    if output:
        json.dump(asdict(payload), output, indent=2)
