"""全局配置：通过 .env 覆盖，默认指向本地 Ollama。"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


class Settings:
    # ---- LLM（OpenAI 接口，Ollama 默认地址）----
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "ollama")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "qwen3:8b")
    LLM_TIMEOUT: int = int(os.getenv("LLM_TIMEOUT", "60"))

    # 演示模式：强验证时把验证码直接回给前端，方便答辩
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "false").lower() == "true"

    # ---- 业务规则 ----
    DAILY_YELLOW_LIMIT: float = float(os.getenv("DAILY_YELLOW_LIMIT", "1000"))
    DAILY_TRANSFER_LIMIT: float = float(os.getenv("DAILY_TRANSFER_LIMIT", "50000"))
    MAX_CONSECUTIVE_FAIL: int = int(os.getenv("MAX_CONSECUTIVE_FAIL", "3"))

    # ---- DUPLEX (configuration is server-owned) ----
    DUPLEX_MODE = os.getenv("DUPLEX_MODE", "local")
    DUPLEX_DETECTOR_URL = os.getenv("DUPLEX_DETECTOR_URL", "")
    DUPLEX_COMPONENT_URL = os.getenv("DUPLEX_COMPONENT_URL", "")
    DUPLEX_MEMORY_URL = os.getenv("DUPLEX_MEMORY_URL", "")
    CONFIRM_TTL_SECONDS = int(os.getenv("CONFIRM_TTL_SECONDS", "300"))
    MFA_PROVIDER = os.getenv("MFA_PROVIDER", "local_outbox")
    MFA_TOTP_SECRETS = os.getenv("MFA_TOTP_SECRETS", "{}")
    MFA_DELIVERY_URL = os.getenv("MFA_DELIVERY_URL", "")
    LOCK_SECONDS = int(os.getenv("LOCK_SECONDS", "300"))
    # ---- 存储 ----
    DB_PATH: str = os.getenv("DB_PATH", str(Path(__file__).resolve().parents[1] / "data" / "bank.db"))

    # ---- 鉴权（演示用 token）----
    VALID_TOKENS: list = ["guest001", "admin001"]


settings = Settings()
if settings.DUPLEX_MODE not in ('local','external_required'):
    raise ValueError('DUPLEX_MODE must be local or external_required')
if settings.MFA_PROVIDER not in ('local_outbox','totp'):
    raise ValueError('MFA_PROVIDER must be local_outbox or totp')
