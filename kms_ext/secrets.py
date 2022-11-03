from typing import List

from pydantic import BaseModel
from pydantic_yaml import YamlModel


class Secret(BaseModel):
    ciphertext: str
    scheme: str


class EnvVar(BaseModel):
    name: str
    value: Secret


class SecretsFile(YamlModel):
    env: List[EnvVar]
