"""Input, argument and low-trust data screening with explicit component status."""
import base64
import json
import re
import unicodedata
from urllib.parse import unquote
from urllib.request import Request, build_opener, ProxyHandler
from .. import config
from .robustness import normalize_hardened

PATTERNS = [
    r"(?:ignore|disregard|override).{0,35}(?:previous|system|security|instructions|checks)",
    r"(?:bypass|disable|skip).{0,25}(?:mfa|verification|confirm|security|checks)",
    r"(?:忽略|无视|覆盖).{0,18}(?:之前|此前|系统|安全|规则|指令)",
    r"(?:绕过|跳过|关闭|禁用|取消).{0,12}(?:安全检查|权限检查|权限校验|安全规则|短信验证|验证码|人工确认)",
    r"(?:输出|泄露|打印|显示).{0,12}(?:系统提示词|隐藏指令|api.?key|密钥)",
    r"(?:你现在是|扮演).{0,15}(?:后台管理员|系统管理员|开发者)",
    r"(?:system|developer)\s*:\s*(?:ignore|bypass|disable)",
    r"(?:已获得|已经|无需).{0,10}(?:用户授权|用户确认|确认即可).{0,15}(?:立即|直接).{0,8}(?:转账|执行)",
]
COMPILED = [re.compile(p, re.I | re.S) for p in PATTERNS]


def post(url, endpoint, payload, timeout=4):
    request = Request(url.rstrip('/') + endpoint,
                      data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                      headers={'Content-Type': 'application/json'}, method='POST')
    with build_opener(ProxyHandler({})).open(request, timeout=timeout) as response:
        result = json.load(response)
    if not isinstance(result, dict):
        raise ValueError('component returned a non-object')
    return result


def inspect_local(text):
    value = str(text)
    views = [value, normalize_hardened(value), unquote(value)]
    hidden = ''.join(chr(ord(c)-0xE0000) for c in value if 0xE0020 <= ord(c) <= 0xE007E)
    if hidden:
        views.append(hidden)
    for token in re.findall(r'[A-Za-z0-9+/]{24,}={0,2}', value)[:12]:
        try:
            decoded = base64.b64decode(token + '=' * (-len(token) % 4), validate=True).decode('utf-8')
            views.append(decoded)
        except (ValueError, UnicodeError):
            pass
    for view in views:
        normalized = unicodedata.normalize('NFKC', view)
        for pattern in COMPILED:
            if pattern.search(normalized):
                return {'detected': True, 'decision': 'deny', 'source': 'local_rules',
                        'reason': '检测到覆盖安全约束或冒充系统权限的指令'}
    return {'detected': False, 'decision': 'allow', 'source': 'local_rules'}


def inspect_input(text):
    local = inspect_local(text)
    if local['detected']:
        return local
    url = config.settings.DUPLEX_DETECTOR_URL
    if not url:
        if config.settings.DUPLEX_MODE == 'external_required':
            return {'detected': False, 'decision': 'deny', 'source': 'promptguard',
                    'code': 'security_component_unavailable', 'reason': '未配置必需的入口检测服务'}
        return local
    try:
        result = post(url, '/review', {'text': str(text)})
        verdict = result.get('decision')
        if result.get('available') is not True or verdict not in ('allow', 'ask', 'deny'):
            raise ValueError('missing detector decision')
        return {**result, 'detected': verdict != 'allow', 'source': 'promptguard'}
    except Exception as exc:
        return {'detected': False, 'decision': 'deny', 'source': 'promptguard',
                'code': 'security_component_unavailable', 'reason': type(exc).__name__}


def scan_arguments(name, args, description):
    if inspect_local(json.dumps(args, ensure_ascii=False))['detected']:
        return {'decision': 'deny', 'reason': '工具参数中含越权指令', 'source': 'local_rules'}
    url = config.settings.DUPLEX_COMPONENT_URL
    if not url:
        if config.settings.DUPLEX_MODE == 'external_required':
            return {'decision': 'deny', 'reason': '参数扫描服务未配置', 'code': 'security_component_unavailable'}
        return {'decision': 'allow', 'source': 'local_rules'}
    try:
        result = post(url, '/arg-scan', {'tool': name, 'args': args, 'tool_description': description})
        if result.get('decision') != 'allow' or result.get('available') is not True:
            return {'decision': 'deny', 'reason': result.get('reason', '参数扫描拒绝或不可用')}
        return result
    except Exception as exc:
        return {'decision': 'deny', 'reason': type(exc).__name__, 'code': 'security_component_unavailable'}


def detector(text):
    result = inspect_input(text)
    return {'detected': result['decision'] != 'allow', 'spans': []}
