from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console
from rich.pretty import pprint
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli import admin2
from repository_service_tuf.cli.admin2 import sign

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
class TestSign:
    @staticmethod
    def _pretty(arg):
        """Helper to format a string as pprint would do it."""
        console = Console()
        with console.capture() as capture:
            pprint(arg, console=console)
        return capture.get()

    @staticmethod
    def _split(dialog):
        """Helper to split (output, input) tuples of lines in a prompt dialog.
        Some lines may only have outputs."""

        outputs = inputs = ""
        for line in dialog:
            assert isinstance(line, tuple) and len(line) in [1, 2]
            outputs += line[0]
            if len(line) == 2:
                inputs += line[1] + "\n"

        return outputs, inputs

    def test_run(self, client: CliRunner, monkeypatch, patch_getpass):
        root = Metadata[Root].from_file(f"{_ROOTS / 'v1.json'}")

        inputs = [
            "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            f"{_PEMS / 'ec'}",
        ]

        monkeypatch.setattr(admin2, "_fetch_metadata", lambda x: (root, None))
        monkeypatch.setattr(admin2, "_push_signature", lambda x, y: None)

        result = client.invoke(
            sign, "--api-server bla", input="\n".join(inputs)
        )
        if result.exception:
            raise result.exception

        print(result.output)

    def test_run2(self, client: CliRunner, monkeypatch, patch_getpass):
        root1 = Metadata[Root].from_file(f"{_ROOTS / 'v1.json'}")
        root2 = Metadata[Root].from_file(f"{_ROOTS / 'v2.json'}")

        inputs = [
            "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            f"{_PEMS / 'ec'}",
        ]

        monkeypatch.setattr(
            admin2, "_fetch_metadata", lambda x: (root2, root1.signed)
        )
        monkeypatch.setattr(admin2, "_push_signature", lambda x, y: None)

        result = client.invoke(
            sign, "--api-server bla", input="\n".join(inputs)
        )
        if result.exception:
            raise result.exception

        print(result.output)

    # def test_sign_v1(self, client: CliRunner, patch_getpass):
    #     """Sign root v1, with 2/2 keys."""

    #     root = Metadata[Root].from_file(f"{_ROOTS / 'v1.json'}")
    #     root_pretty = self._pretty(root.signed.to_dict())

    #     dialog = [
    #         (
    #             "Enter path to root to sign: ",
    #             f"{_ROOTS / 'v1.json'}",
    #         ),
    #         (root_pretty,),
    #         (
    #             "need 2 signature(s) from any of ['50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3', 'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc']",
    #         ),
    #         (
    #             "Choose key [50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
    #             "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
    #         ),
    #         (
    #             "Enter path to encrypted local private key: ",
    #             f"{_PEMS / 'ec'}",
    #         ),
    #         ("Enter password: ",),  # provided via patch_getpass
    #         (
    #             "Signed with key 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
    #         ),
    #         (
    #             "Save? [y/n]: ",
    #             "n",
    #         ),
    #         ("Bye.",),
    #     ]

    #     outputs, inputs = self._split(dialog)
    #     result = client.invoke(sign, input=inputs)
    #     # ignore newlines to make life easier (rich inserts plenty)
    #     assert outputs.replace("\n", "") == result.output.replace("\n", "")

    # def test_sign_v2(self, client, patch_getpass):
    #     """Sign root v2, with 2/2 keys from old root and 2/2 from new, where
    #     1 key is in both old and new (needs 3 signatures in total)."""

    #     root = Metadata[Root].from_file(f"{_ROOTS / 'v2.json'}")
    #     root_pretty = self._pretty(root.signed.to_dict())

    #     dialog = [
    #         (
    #             "Enter path to root to sign: ",
    #             f"{_ROOTS / 'v2.json'}",
    #         ),
    #         (
    #             "Enter path to previous root: ",
    #             f"{_ROOTS / 'v1.json'}",
    #         ),
    #         (root_pretty,),
    #         (
    #             "need 2 signature(s) from any of ['2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241', '50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3']",
    #         ),
    #         (
    #             "need 2 signature(s) from any of ['50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3', 'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc']",
    #         ),
    #         (
    #             "Choose key [2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241/50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
    #             "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
    #         ),
    #         (
    #             "Enter path to encrypted local private key: ",
    #             f"{_PEMS / 'ec'}",
    #         ),
    #         ("Enter password: ",),  # provided via patch_getpass
    #         (
    #             "Signed with key 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
    #         ),
    #         (
    #             "Save? [y/n]: ",
    #             "n",
    #         ),
    #         ("Bye.",),
    #     ]

    #     outputs, inputs = self._split(dialog)
    #     result = client.invoke(sign, input=inputs)
    #     # ignore newlines to make life easier (rich inserts plenty)
    #     assert outputs.replace("\n", "") == result.output.replace("\n", "")
