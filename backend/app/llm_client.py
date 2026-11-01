"""LLM 客户端：对接 Ollama（OpenAI 兼容），失败时标记不可用以便降级。"""
from openai import OpenAI
import httpx
import time
from .config import settings

_client = None
_available = None
_checked_at = 0.0


def get_client():
    global _client
    if _client is None:
        _client = OpenAI(base_url=settings.LLM_BASE_URL, api_key=settings.LLM_API_KEY,
                         timeout=settings.LLM_TIMEOUT, max_retries=0,
                         http_client=httpx.Client(trust_env=False))
    return _client


def is_available():
    global _available, _checked_at
    if _available is not None and time.monotonic() - _checked_at < 5:
        return _available
    try:
        models = get_client().with_options(timeout=3, max_retries=0).models.list()
        _available = any(model.id == settings.LLM_MODEL for model in models.data)
    except Exception:
        _available = False
    _checked_at = time.monotonic()
    return _available


def chat(messages, tools=None):
    kwargs = dict(model=settings.LLM_MODEL, messages=messages, temperature=0.1, max_tokens=2048, extra_body={"think":False})
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    return get_client().chat.completions.create(**kwargs).choices[0].message


def json_chat(messages):
    response = get_client().chat.completions.create(
        model=settings.LLM_MODEL,messages=messages,temperature=0,max_tokens=2048,
        response_format={'type':'json_object'},extra_body={'think':False})
    content = response.choices[0].message.content
    if not isinstance(content,str) or not content.strip():
        raise ValueError('empty structured model verdict')
    return content
