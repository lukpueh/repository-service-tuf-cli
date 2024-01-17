from pathlib import Path

import pytest
from click.testing import CliRunner

from repository_service_tuf.cli.admin2 import sign, update

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

    def test_sign_v1(self, client: CliRunner, patch_getpass):
        """Sign root v1, with 2/2 keys."""

        dialog = [
            (
                "Enter path to root to sign: ",
                f"{_ROOTS / 'v1.json'}",
            ),
            (
                "need 2 signature(s) from any of ['50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3', 'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc']",
            ),
            (
                "Review? [y/n]: ",
                "n",
            ),
            (
                "Sign? [y/n]: ",
                "y",
            ),
            (
                "Choose key [50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
                "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            ),
            (
                "Enter path to encrypted local private key: ",
                f"{_PEMS / 'ec'}",
            ),
            ("Enter password: ",),  # provided via patch_getpass
            (
                "Signed with key 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            ),
            (
                "need 1 signature(s) from any of ['c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc']",
            ),
            (
                "Sign? [y/n]: ",
                "y",
            ),
            (
                "Choose key [c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
                "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
            ),
            (
                "Enter path to encrypted local private key: ",
                f"{_PEMS / 'ed'}",
            ),
            ("Enter password: ",),  # provided via patch_getpass
            (
                "Signed with key c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
            ),
            ("Metadata fully signed.",),
            (
                "Save? [y/n]: ",
                "n",
            ),
            ("Bye.",),
        ]

        outputs, inputs = self._split(dialog)
        result = client.invoke(sign, input=inputs)
        # ignore newlines to make life easier (rich inserts plenty)
        assert outputs.replace("\n", "") == result.output.replace("\n", "")

    def test_sign_v2(self, client, patch_getpass):
        """Sign root v2, with 2/2 keys from old root and 2/2 from new, where
        1 key is in both old and new (needs 3 signatures in total)."""

        dialog = [
            (
                "Enter path to root to sign: ",
                f"{_ROOTS / 'v2.json'}",
            ),
            (
                "Enter path to previous root: ",
                f"{_ROOTS / 'v1.json'}",
            ),
            (
                "need 2 signature(s) from any of ['2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241', '50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3']",
            ),
            (
                "need 2 signature(s) from any of ['50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3', 'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc']",
            ),
            (
                "Review? [y/n]: ",
                "n",
            ),
            (
                "Sign? [y/n]: ",
                "y",
            ),
            (
                "Choose key [2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241/50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
                "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            ),
            (
                "Enter path to encrypted local private key: ",
                f"{_PEMS / 'ec'}",
            ),
            ("Enter password: ",),  # provided via patch_getpass
            (
                "Signed with key 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            ),
            (
                "need 1 signature(s) from any of ['2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241']",
            ),
            (
                "need 1 signature(s) from any of ['c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc']",
            ),
            (
                "Sign? [y/n]: ",
                "y",
            ),
            (
                "Choose key [2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
                "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
            ),
            (
                "Enter path to encrypted local private key: ",
                f"{_PEMS / 'ed'}",
            ),
            ("Enter password: ",),  # provided via patch_getpass
            (
                "Signed with key c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
            ),
            (
                "need 1 signature(s) from any of ['2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241']",
            ),
            (
                "Sign? [y/n]: ",
                "y",
            ),
            (
                "Choose key [2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241]: ",
                "2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241",
            ),
            (
                "Enter path to encrypted local private key: ",
                f"{_PEMS / 'rsa'}",
            ),
            ("Enter password: ",),  # provided via patch_getpass
            (
                "Signed with key 2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241",
            ),
            ("Metadata fully signed.",),
            (
                "Save? [y/n]: ",
                "n",
            ),
            ("Bye.",),
        ]

        outputs, inputs = self._split(dialog)
        result = client.invoke(sign, input=inputs)
        # ignore newlines to make life easier (rich inserts plenty)
        assert outputs.replace("\n", "") == result.output.replace("\n", "")

    def test_update(self, client, patch_getpass):
        dialog = [
            ("Root Metadata Update",),
            (
                "Enter path to root to update: ",
                f"{_ROOTS / 'v1.json'}",
            ),
            ("Expiration Date Configuration",),
            ("Root has expired on 12/21/23",),
            (
                "Please enter number of days from now, when root should expire: ",
                "10",
            ),
            ("Changed root to expire in 10 days",),
            ("Root expires on 01/27/24",),
            (
                "Do you want to change the expiry date? [y/n]: ",
                "n",
            ),
            ("Root Key Configuration",),
            ("Current Threshold: 2",),
            ("Current Keys:",),
            (
                "keyid: c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc ",
            ),
            (
                "keyid: 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3 ",
            ),
            (
                "Do you want to change root keys? [y/n]: ",
                "y",
            ),
            (
                "Do you want to change the root signature threshold? [y/n]: ",
                "y",
            ),
            (
                "Please enter root signature threshold: ",
                "1",
            ),
            ("Changed root signature threshold to 1",),
            (
                "Do you want to remove a root key? [y/n]: ",
                "y",
            ),
            (
                "Choose key to remove [50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
                "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3",
            ),
            (
                "Removed root key '50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3'",
            ),
            ("Current Threshold: 1",),
            ("Current Keys:",),
            (
                "keyid: c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc ",
            ),
            (
                "Do you want to remove a root key? [y/n]: ",
                "y",
            ),
            (
                "Choose key to remove [c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: ",
                "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",
            ),
            (
                "Removed root key 'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc'",
            ),
            ("Current Threshold: 1",),
            ("Current Keys:",),
            ("Please add 1 key(s) to meet threshold (1).",),
            (
                "Please enter a public key path: ",
                f"{_PEMS / 'rsa.pub'}",
            ),
            (
                "Please enter a key name, or press enter to continue without name: ",
                "my rsa root key",
            ),
            (
                "Added root key '2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241'",
            ),
            ("Current Threshold: 1",),
            ("Current Keys:",),
            (
                "keyid: 2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241 (name: my rsa root key)",
            ),
            (
                "Do you want to add a root key? [y/n]: ",
                "n",
            ),
            ("Current Threshold: 1",),
            ("Current Keys:",),
            (
                "keyid: 2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241 (name: my rsa root key)",
            ),
            (
                "Do you want to change root keys? [y/n]: ",
                "n",
            ),
            ("Online Key Configuration",),
            ("Current Key:",),
            (
                "keyid: c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc ",
            ),
            (
                "Do you want to change the online key? [y/n]: ",
                "y",
            ),
            (
                "Please enter a public key path: ",
                f"{_PEMS / 'ec.pub'}",
            ),
            (
                "Configured online key: '50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3'",
            ),
            ("Current Key:",),
            (
                "keyid: 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3 (uri: fn:ec.pub)",
            ),
            (
                "Do you want to change the online key? [y/n]: ",
                "n",
            ),
            (
                "need 1 signature(s) from any of ['2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241']",
            ),
            (
                "need 2 signature(s) from any of ['50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3', 'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc']",
            ),
            (
                "Review? [y/n]: ",
                "n",
            ),
            (
                "Sign? [y/n]: ",
                "n",
            ),
            (
                "Save? [y/n]: ",
                "n",
            ),
            ("Bye.",),
        ]

        outputs, inputs = self._split(dialog)
        result = client.invoke(update, input=inputs)
        # ignore newlines to make life easier (rich inserts plenty)
        assert outputs.replace("\n", "") == result.output.replace("\n", "")
