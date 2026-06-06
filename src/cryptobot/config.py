"""Bot configuration via pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    bot_token: str
    admin_ids: list[int] = []

    @property
    def database_configured(self) -> bool:
        return False  # No DB for now


settings = Settings()
