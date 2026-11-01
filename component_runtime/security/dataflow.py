"""Session-local sensitive value tracking; records never confer authorization."""
from __future__ import annotations
import base64
import hashlib
import json
import re
from urllib.parse import quote, quote_plus, unquote


class DataFlowLedger:
    def __init__(self):
        self.records = []

    def observe(self, source_id, path, result):
        raw = result.get("content", result) if isinstance(result, dict) else str(result)
        text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
        values = [m.group(1).strip("\"' ") for m in re.finditer(r"(?i)[\w-]*(?:key|secret|password|token|credential)\s*[:=]\s*([^\s,;]+)", text)]
        values += re.findall(r"\b(?:sk-[\w-]{16,}|AKIA[0-9A-Z]{16}|ghp_\w{20,}|[A-Z]{2}\d{20,})\b", text)
        def leaves(item):
            if isinstance(item, dict):
                for child in item.values(): yield from leaves(child)
            elif isinstance(item, list):
                for child in item: yield from leaves(child)
            elif isinstance(item, str) and 8 <= len(item) <= 256:
                yield item
        values += list(leaves(raw))
        # Sensitive prose is also tracked in bounded distinctive fragments.
        values += [line.strip() for line in text.splitlines() if 20 <= len(line.strip()) <= 256]
        values = sorted({v for v in values if len(v) >= 8})
        self.records.append({"source_id": source_id, "path": path, "values": values,
                             "content_sha256": hashlib.sha256(text.encode()).hexdigest()})

    def match(self, arguments):
        encoded = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
        decoded = unquote(unquote(encoded))
        hits = []
        for record in self.records:
            for value in record["values"]:
                forms = {value, quote(value, safe=""), quote_plus(value), base64.b64encode(value.encode()).decode(), value.encode().hex()}
                if any(form in encoded or form in decoded for form in forms):
                    hits.append({"source_id": record["source_id"], "path": record["path"],
                                 "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
                                 "reason": "参数携带本会话真实读取的敏感值或等价编码"})
                    break
        return hits
