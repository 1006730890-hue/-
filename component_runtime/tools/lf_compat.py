"""Compatibility shim for the Hugging Face token interface."""
from __future__ import annotations

import os

__all__ = ["install", "HF_FOLDER_PATCHED"]


def install() -> bool:
    """把 `HfFolder` 补回 `huggingface_hub`。已存在则不覆盖，返回是否做了改动。"""
    import huggingface_hub

    if hasattr(huggingface_hub, "HfFolder"):
        return False

    class HfFolder:                                              # noqa: D401
        """`huggingface_hub` 0.x 的 token 存取接口，按原语义最小实现。

        只覆盖 LlamaFirewall 用到的那两个类方法。路径优先用 hub 自己
        暴露的常量，取不到再退回约定的 `~/.cache/huggingface/token`。
        """

        @staticmethod
        def _token_path() -> str:
            constants = getattr(huggingface_hub, "constants", None)
            path = getattr(constants, "HF_TOKEN_PATH", None) if constants else None
            if path:
                return str(path)
            return os.path.join(
                os.environ.get("HF_HOME", os.path.expanduser("~/.cache/huggingface")), "token"
            )

        @classmethod
        def save_token(cls, token: str) -> None:
            path = cls._token_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(str(token))

        @classmethod
        def get_token(cls) -> str | None:
            path = cls._token_path()
            if not os.path.exists(path):
                return None
            try:
                with open(path, encoding="utf-8") as handle:
                    return handle.read().strip() or None
            except OSError:
                return None

        @classmethod
        def delete_token(cls) -> None:
            path = cls._token_path()
            try:
                os.remove(path)
            except OSError:
                pass

    huggingface_hub.HfFolder = HfFolder
    return True


HF_FOLDER_PATCHED = install()
