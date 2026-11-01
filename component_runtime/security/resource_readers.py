"""Actual resource adapters, including document metadata and mail MIME bodies."""
from __future__ import annotations
import email.policy
from email.parser import BytesParser
from html.parser import HTMLParser
import json
from pathlib import Path
import urllib.request
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 262144


class WebText(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []
    def handle_data(self, data):
        self.parts.append(data)
    def handle_comment(self, data):
        self.parts.append("HTML注释：" + data)
    def handle_starttag(self, tag, attrs):
        self.parts.extend(str(v) for k, v in attrs if k in {"alt", "title", "content", "aria-label"} and v)


def read_resource(kind: str, locator: str):
    if kind in {"web", "url"}:
        parsed = urlparse(locator)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("网页资源必须是 http/https URL")
        request = urllib.request.Request(locator, headers={"User-Agent": "AgentDojo-Resource-Gateway/2.0"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=15) as response:
            raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError("网页超过完整检查上限，拒绝截断后放行")
            text = raw.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            content_type = response.headers.get("Content-Type", "")
            if "html" in content_type:
                parser = WebText(); parser.feed(text); text = "\n".join(parser.parts)
            return text, {"url": response.url, "bytes": len(raw), "content_type": content_type,
                          "reader": "urllib+HTMLParser"}, "external_web_content"
    path = (ROOT / locator).resolve() if not Path(locator).is_absolute() else Path(locator).resolve()
    path.relative_to(ROOT)
    if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("资源文件不存在或超过 8MB 上限")
    metadata = {"path": str(path), "bytes": path.stat().st_size}
    if kind == "document" and path.suffix.lower() == ".pdf":
        from pypdf import PdfReader
        document = PdfReader(path)
        text = "\n".join(page.extract_text() or "" for page in document.pages)
        text += "\nPDF元数据：" + json.dumps(dict(document.metadata or {}), ensure_ascii=False, default=str)
        metadata.update(reader="pypdf", pages=len(document.pages))
    elif kind == "document" and path.suffix.lower() == ".docx":
        from docx import Document
        document = Document(path)
        text = "\n".join([p.text for p in document.paragraphs] +
                         [" | ".join(c.text for c in row.cells) for t in document.tables for row in t.rows])
        text += "\nWord元数据：" + " | ".join(str(getattr(document.core_properties, field) or "")
                                           for field in ("title", "subject", "comments", "keywords", "author"))
        metadata.update(reader="python-docx")
    elif kind == "email":
        message = BytesParser(policy=email.policy.default).parsebytes(path.read_bytes())
        parts = [f"{key}: {value}" for key, value in message.items()]
        for part in message.walk():
            if part.get_content_maintype() == "text":
                body = part.get_content()
                if part.get_content_subtype() == "html":
                    parser = WebText(); parser.feed(body); body = "\n".join(parser.parts)
                parts.append(body)
        text = "\n".join(parts); metadata.update(reader="email.mime", message_id=str(message.get("Message-ID", "")))
    elif kind in {"ticket", "issue"}:
        record = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record, (dict, list)):
            raise ValueError("工单/Issue 导出必须是 JSON 对象或数组")
        text = json.dumps(record, ensure_ascii=False, indent=2)
        metadata.update(reader="json-export", connector="local_export", record_id=record.get("id") if isinstance(record, dict) else None)
    elif kind in {"document", "source_code", "ide"}:
        text = path.read_text(encoding="utf-8", errors="strict")
        metadata.update(reader="filesystem", lines=len(text.splitlines()))
    else:
        raise ValueError("不支持的资源类型")
    if len(text) > LIMIT:
        raise ValueError("解析内容超过完整检查上限，拒绝截断后放行")
    return text, metadata, {"document": "external_document", "source_code": "external_source_code",
                            "ide": "external_source_code", "email": "external_email",
                            "ticket": "external_ticket", "issue": "external_issue"}[kind]
