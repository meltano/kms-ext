"""Meltano KMS extension."""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import boto3
import dotenv
import os
import structlog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import dotenv_values
from meltano.edk import models
from meltano.edk.extension import ExtensionBase

from .secrets import EnvVar, Secret, SecretsFile

log = structlog.get_logger()

class KMSCrypto:
    """Encrypt plaintext using KMS-compliant RSA algorithm."""

    def __init__(self, pem_filepath: Path):
        self.pem_filepath = pem_filepath
        self._public_key = None

    @property
    def public_key(self):
        if self._public_key is None:
            with open(self.pem_filepath, "rb") as pk_file:
                self._public_key = serialization.load_pem_public_key(
                    data=pk_file.read()
                )
        return self._public_key

    def encrypt(self, plaintext: str):
        ciphertext = self.public_key.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(ciphertext)


class KMS(ExtensionBase):
    """Extension implementing the ExtensionBase interface."""

    def __init__(self) -> None:
        """Initialize the extension."""

    def invoke(self, *args: Any | None, **kwargs: Any) -> None:
        """Invoke the underlying cli, that is being wrapped by this extension.

        Args:
            args: Ignored positional arguments.
            kwargs: Ignored keyword arguments.

        Raises:
            NotImplementedError: There is no underlying CLI for this extension.
        """
        raise NotImplementedError

    def encrypt(
        self,
        public_key_path: Path,
        dotenv_path: Path = Path(".env"),
        output_path: Path = Path("secrets.yml"),
    ) -> Path:
        """Encrypt a given dotenv file with a given RSA public key (PEM file).

        Args:
            public_key_path: Path to RSA public key (PEM file).
            dotenv_path: Path to dotenv file (defaults to '.env')
            output_path: Path to output file (defaults to 'secrets.yml')

        Returns:
            A path to the outputted ciphertext file.
        """
        kms = KMSCrypto(pem_filepath=public_key_path)
        config = dotenv_values(dotenv_path)

        env_vars = []
        for key, plaintext in config.items():
            secret = Secret(
                ciphertext=kms.encrypt(plaintext).decode("utf-8"),
                scheme="RSAES_OAEP_SHA_256",
            )
            env_vars.append(EnvVar(name=key, value=secret))

        secrets = SecretsFile(env=env_vars)

        with open(output_path, "w") as secrets_file:
            secrets_file.write(secrets.yaml())

        return Path(output_path)

    def decrypt(
        self,
        input_path: Path = Path("secrets.yml"),
        output_path: Path = Path(".env"),
    ) -> Path:
        client = boto3.client("kms")

        try:
            kms_key_id = os.environ["KMS_KEY_ID"]
        except KeyError as ex:
            raise Exception("The environment variable $KMS_KEY_ID must be set to decrypt") from ex

        with open(input_path) as ciphertext_file:
            secrets = SecretsFile.parse_raw(ciphertext_file.read())

        for env_var in secrets.env:
            ciphertext = base64.b64decode(env_var.value.ciphertext)
            response = client.decrypt(
                CiphertextBlob=ciphertext,
                KeyId=kms_key_id,
                EncryptionAlgorithm=env_var.value.scheme,  # "RSAES_OAEP_SHA_256" | "SYMMETRIC_DEFAULT" | "RSAES_OAEP_SHA_1" | "SM2PKE"
            )
            plaintext = response["Plaintext"].decode("utf-8")
            dotenv.set_key(output_path, env_var.name, plaintext)

    def describe(self) -> models.Describe:
        """Describe the extension.

        Returns:
            The extension description
        """
        return models.Describe(
            commands=[
                models.ExtensionCommand(
                    name="kms", description="Encrypt/decrypt commands"
                )
            ]
        )
