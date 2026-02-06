from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field


class RemoteLlmConfig(BaseModel):
    base_url: str = ""
    api_key_env_var: str = ""
    model_name: str = ""


class RedactionConfig(BaseModel):
    enabled: bool = True


class Config(BaseModel):
    include_globs: List[str] = Field(default_factory=list)
    exclude_globs: List[str] = Field(default_factory=list)
    severity_threshold: str = "medium"
    enable_external_scanners: bool = False
    enable_llm: bool = False
    llm_mode: str = "off"
    remote_llm: RemoteLlmConfig = Field(default_factory=RemoteLlmConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    sarif: bool = False


def load_config(path: Optional[Path]) -> Config:
    if path is None:
        default_path = Path(".saicr.yaml")
        if default_path.exists():
            path = default_path
    if path is None or not path.exists():
        return Config()
    data = yaml.safe_load(path.read_text()) or {}
    return Config(**data)
