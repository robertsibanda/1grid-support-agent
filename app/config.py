import os
import sys
from pathlib import Path
from pydantic_settings import BaseSettings

IS_WINDOWS = sys.platform == "win32"
PROJECT_ROOT = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    confidence_threshold: float = 0.85
    zonewalk_bin: str = "/usr/bin/zonewalk"
    log_level: str = "INFO"
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db_name: str = "1grid"

    @property
    def warehouse_db(self) -> str:
        return str(PROJECT_ROOT / "data" / "support_warehouse.db")

    @property
    def nosql_db_path(self) -> str:
        return str(PROJECT_ROOT / "data" / "nosql_warehouse.json")

    @property
    def conversations_jsonl(self) -> str:
        return str(PROJECT_ROOT / "data" / "conversations.jsonl")

    @property
    def chroma_db_path(self) -> str:
        return str(PROJECT_ROOT / "data" / "chroma")

    @property
    def zonewalk_available(self) -> bool:
        return not IS_WINDOWS and os.path.exists(self.zonewalk_bin)

    class Config:
        env_file = str(PROJECT_ROOT / ".env")
        env_file_encoding = "utf-8"

settings = Settings()
