from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.pretty import pprint
from rich.prompt import Confirm, Prompt
from securesystemslib.signer import CryptoSigner, Key, Signer, SSlibKey
from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp

from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin import admin

ONLINE_ROLE_NAMES = {Timestamp.type, Snapshot.type, Targets.type}

# see repository-service-tuf/repository-service-tuf-worker#427
ONLINE_KEY_URI_FIELD = "x-rstuf-online-key-uri"
KEY_LABEL_FIELD = "x-rstuf-key-label"


def load_public() -> Key:
    """Ask for details to load public key, load and return."""
    # TODO: Give choice -- data (copy paste), hsm, aws, sigstore, ... -- and
    # consider configuring signer based on that choice. Note that for online and
    # offline signing, different choices might be interesting.

    # TODO: clarify supported key types, format
    path = Prompt.ask("Enter public key path")
    with open(path, "rb") as f:
        public_pem = f.read()

    crypto = load_pem_public_key(public_pem)
    key = SSlibKey.from_crypto(crypto)

    # TODO: keyids can be anything. we could just ask for a custom keyid
    # instead of a label.
    label = Prompt.ask("Enter key label (optional)")
    if label:
        key.unrecognized_fields[KEY_LABEL_FIELD] = label

    return key


def configure_online_signer() -> str:
    """Ask for details to load online signer and return as URI."""
    # TODO: Give choice -- relative path, envvar, aws, gcp, azure, sigstore, ...

    # TODO: clarify supported key types, format, "unencryptedness" and where
    # the key will be used
    path = Prompt.ask("Enter full path to unencrypted online private key")
    uri = f"{CryptoSigner.FILE_URI_SCHEME}:{path}?encrypted=false"

    return uri


def load_signer(public_key) -> Signer:
    """Ask for details to load signer, load and return."""
    # TODO: Give choice -> hsm, sigstore, ...

    # TODO: clarify supported key types, format
    path = Prompt.ask("Enter path to encrypted local private key")
    with open(path, "rb") as f:
        private_pem = f.read()

    password = Prompt.ask("Enter password", password=True)
    private_key = load_pem_private_key(private_pem, password.encode())
    signer = CryptoSigner(private_key, public_key)

    return signer


@admin.command()  # type: ignore
def ceremony2() -> None:
    """POC: Key-only Metadata Ceremony.

    This implements the key loading and signing parts of the ceremony command
    as proof of concept.

    TODO:
    - Make re-usable for `metadata update` and `metadata sign`.
    - polish enough so that reviewers can try it out:
      - handle errors from inputs
      - clarify and beautify outputs
    - Integrate with existing cli
    """

    root = Root()

    console.print("Online key")
    while True:
        key = load_public()
        uri = configure_online_signer()
        key.unrecognized_fields[ONLINE_KEY_URI_FIELD] = uri
        root.keys[key.keyid] = key
        for name in ONLINE_ROLE_NAMES:
            root.roles[name].keyids = [key.keyid]

        pprint(root.to_dict())
        if Confirm.ask("Done?"):
            break

    console.print("Offline keys")
    while True:
        # TODO: add, remove, done, show stat
        console.print("Add")
        key = load_public()
        root.add_key(key, Root.type)

        pprint(root.to_dict())
        if Confirm.ask("Done?"):
            break

    metadata = Metadata(root)
    console.print("Sign metadata")
    for keyid in root.roles[Root.type].keyids:
        console.print(f"Sign with key {keyid}")
        # TODO: yes, no, done, show stat
        key = root.get_key(keyid)
        signer = load_signer(key)
        metadata.sign(signer, append=True)

        pprint(metadata.to_dict())
        if Confirm.ask("Done?"):
            break
