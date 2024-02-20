from pathlib import Path

import pretend
import pytest
from click.testing import CliRunner
from tuf.api.metadata import Metadata, Root

import repository_service_tuf.cli.admin2 as admin2

_FILES = Path(__file__).parent.parent.parent / "files"
_ROOTS = _FILES / "root"
_PEMS = _FILES / "pem"


@pytest.fixture
def patch_getpass(monkeypatch):
    """Fixture to mock password prompt return value for encrypted test keys.

    NOTE: we need this, because getpass does not receive the inputs passed to
    click's invoke method (interestingly, click's own password prompt, which
    also uses getpass, does receive them)
    """

    def mock_getpass(prompt, stream=None):
        # no need to mock prompt output, rich prompts independently
        return "hunter2"

    import rich.console

    monkeypatch.setattr(rich.console, "getpass", mock_getpass)


# flake8: noqa
