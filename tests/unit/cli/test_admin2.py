import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from securesystemslib.signer import CryptoSigner, Key

from repository_service_tuf.cli.admin2 import helpers
from repository_service_tuf.cli.admin2.ceremony import ceremony
from repository_service_tuf.cli.admin2.sign import sign
from repository_service_tuf.cli.admin2.update import update

_FILES = Path(__file__).parent.parent.parent / "files"
_ROOTS = _FILES / "root"
_PEMS = _FILES / "pem"
_PAYLOADS = _FILES / "payload"

_INPUT_METH = "rich.console.Console.input"


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

    monkeypatch.setattr("rich.console.getpass", mock_getpass)


# flake8: noqa


class TestAdmin2:
    def test_ceremony(self, client, patch_getpass):
        inputs = [
            "100",  # Please enter number of days from now, when root should expire
            "100",  # Please enter number of days from now, when timestamp should expire
            "100",  # Please enter number of days from now, when snapshot should expire
            "100",  # Please enter number of days from now, when targets should expire
            "100",  # Please enter number of days from now, when bins should expire
            "256",  # Choose the number of delegated hash bin roles [2/4/8/16/32/64/128/256/512/1024/2048/4096/8192/16384] (256)
            "https://yolo.wtf",  # Please enter the targets base URL (e.g. https://www.example.com/downloads/)
            "2",  # Please enter root threshold
            f"{_PEMS / 'rsa.pub'}",  # Please enter a public key path:
            "my rsa key",  # Please enter a key name:
            "0",  # Please press '0' to add key, or enter '<number>' to remove key:
            f"{_PEMS / 'ec.pub'}",  # Please enter a public key path:
            "my ec key",  # Please enter a key name:
            "0",  # Please press '0' to add key, or enter '<number>' to remove key: Press enter to contiue:
            f"{_PEMS / 'ed.pub'}",  # Please enter a public key path:
            "my ed key",  # Please enter a key name:
            "1",  # Please press '0' to add key, or enter '<number>' to remove key. Press enter to contiue:
            "",  # Please press '0' to add key, or enter '<number>' to remove key. Press enter to contiue:
            f"{_PEMS / 'rsa.pub'}",  # Please enter a public key path:
            "2",  # Please enter '<number>' to choose a signing key
            f"{_PEMS / 'ed'}",  # Please enter path to encrypted local private key
            "1",  # Please enter '<number>' to choose a signing key, or press enter to continue:
            f"{_PEMS / 'ec'}",  # Please enter path to encrypted local private key
        ]

        with client.isolated_filesystem():
            result = client.invoke(
                ceremony,
                args=["-o", "payload.json"],
                input="\n".join(inputs),
                catch_exceptions=False,
            )
            print(result.output)

            with open("payload.json") as f:
                payload = json.load(f)

        with open(_PAYLOADS / "ceremony-payload.json") as f:
            expected_payload = json.load(f)

        payload["metadata"]["root"]["signed"].pop("expires")
        expected_payload["metadata"]["root"]["signed"].pop("expires")

        sigs = payload["metadata"]["root"].pop("signatures")
        expected_sigs = expected_payload["metadata"]["root"].pop("signatures")

        assert [sig["keyid"] for sig in sigs] == [
            sig["keyid"] for sig in expected_sigs
        ]
        assert payload == expected_payload

    def test_update(self, client, patch_getpass):
        inputs = [
            "365",  # Please enter number of days from now, when root should expire (100)
            "y",  # Do you want to change the root threshold? [y/n] (y)
            "1",  # Please enter root threshold
            "2",  # Please press '0' to add key, or enter '<number>' to remove key. Press enter to continue
            "1",  # Please press '0' to add key, or enter '<number>' to remove key. Press enter to continue
            f"{_PEMS / 'rsa.pub'}",  # Please enter a public key path
            "rsa root key",  # Please enter a key name
            "",  # Please press '0' to add key, or enter '<number>' to remove key. Press enter to continue:
            "y",  # Do you want to change the online key? [y/n] (y)
            f"{_PEMS / 'ec.pub'}",  # Please enter a public key path
            "1",  # Please enter '<number>' to choose a signing key
            f"{_PEMS / 'ed'}",  # Please enter path to encrypted local private key
            "1",  # Please enter '<number>' to choose a signing key
            f"{_PEMS / 'ec'}",  # Please enter path to encrypted local private key
            "1",  # Please enter '<number>' to choose a signing key
            f"{_PEMS / 'rsa'}",  # Please enter path to encrypted local private key
        ]

        with client.isolated_filesystem():
            result = client.invoke(
                update,
                args=[f"{_ROOTS / 'v1.json'}", "-o", "payload.json"],
                input="\n".join(inputs),
                catch_exceptions=False,
            )
            print(result.output)

            with open("payload.json") as f:
                payload = json.load(f)

        with open(_PAYLOADS / "update-payload.json") as f:
            expected_payload = json.load(f)

        payload["metadata"]["root"]["signed"].pop("expires")
        expected_payload["metadata"]["root"]["signed"].pop("expires")

        sigs = payload["metadata"]["root"].pop("signatures")
        expected_sigs = expected_payload["metadata"]["root"].pop("signatures")

        assert [sig["keyid"] for sig in sigs] == [
            sig["keyid"] for sig in expected_sigs
        ]
        assert payload == expected_payload

    def test_sign(self, client, patch_getpass):
        inputs = [
            "4",  # Please enter '<number>' to choose a signing key:
            f"{_PEMS / 'rsa'}",  # Please enter path to encrypted local private key:
        ]

        with client.isolated_filesystem():
            result = client.invoke(
                sign,
                args=[
                    f"{_ROOTS / 'v2.json'}",
                    f"{_ROOTS / 'v1.json'}",
                    "-o",
                    "payload.json",
                ],
                input="\n".join(inputs),
                catch_exceptions=False,
            )
            print(result.output)

            with open("payload.json") as f:
                payload = json.load(f)

        with open(_PAYLOADS / "sign-payload.json") as f:
            expected_payload = json.load(f)

        assert payload["role"] == "root"
        assert (
            payload["signature"]["keyid"]
            == expected_payload["signature"]["keyid"]
        )


@pytest.fixture
def ed25519_key():
    return Key.from_dict(
        "fake_keyid",
        {
            "keytype": "ed25519",
            "keyval": {
                "public": "4f66dabebcf30628963786001984c0b75c175cdcf3bc4855933a2628f0cd0a0f"
            },
            "scheme": "ed25519",
        },
    )


class TestHelpers:
    def test_load_signer_from_file_prompt(self, ed25519_key):
        inputs = [f"{_PEMS / 'ed'}", "hunter2"]

        # success
        with patch(_INPUT_METH, side_effect=inputs):
            signer = helpers._load_signer_from_file_prompt(ed25519_key)

        assert isinstance(signer, CryptoSigner)

        # fail with wrong file for key
        inputs = [f"{_PEMS / 'rsa'}", "hunter2"]
        with patch(_INPUT_METH, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)

        # fail with bad password
        inputs = [f"{_PEMS / 'ed'}", "hunter1"]
        with patch(_INPUT_METH, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)
