# -*- coding: utf-8 -*-
"""
==============================================================================
PAYLOAD CANONICALIZATION & OBFUSCATION DECODER (canonicalizer.py)
==============================================================================
This module normalizes evasive payload techniques (Double/Triple URL Encoding,
Hex/Unicode Escapes, Base64 String Encodings, SQL Comments, Shell Quote Slicing)
into canonical representation before rule matching and AI inspection.
==============================================================================
"""

import re
import base64
import html
import urllib.parse

# Pre-compiled high-performance regex patterns
HEX_PATTERN = re.compile(r'(?:\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2})+')
UNICODE_PATTERN = re.compile(r'(?:\\u[0-9a-fA-F]{4})+')
BASE64_CANDIDATE = re.compile(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
SQL_COMMENT_PATTERN = re.compile(r'/\*.*?\*/|--\s.*$|#.*$', re.MULTILINE)
SHELL_QUOTE_CONCAT = re.compile(r"['\"](?:\s*['\"])?")
SHELL_IFS_PATTERN = re.compile(r'\$IFS|\$\{IFS\}')

class PayloadCanonicalizer:
    @staticmethod
    def decode_url(text: str, max_depth: int = 3) -> str:
        """
        Decodes nested double or triple URL-encodings (%252e%252e%252f -> ../).
        """
        current = text
        for _ in range(max_depth):
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
        return current

    @staticmethod
    def decode_hex_and_unicode(text: str) -> str:
        """
        Decodes \\x2f or \\u002f hex/unicode escapes.
        """
        def hex_replace(match):
            raw = match.group(0).replace('\\x', '').replace('%', '')
            try:
                return bytes.fromhex(raw).decode('utf-8', errors='ignore')
            except Exception:
                return match.group(0)

        def unicode_replace(match):
            try:
                return match.group(0).encode('utf-8').decode('unicode_escape')
            except Exception:
                return match.group(0)

        res = HEX_PATTERN.sub(hex_replace, text)
        res = UNICODE_PATTERN.sub(unicode_replace, res)
        return res

    @staticmethod
    def decode_html_entities(text: str) -> str:
        """
        Decodes HTML entities (&quot;, &#x27;, &lt;, &gt;).
        """
        return html.unescape(text)

    @staticmethod
    def normalize_shell_obfuscation(text: str) -> str:
        """
        Normalizes shell quote splitting and variable slicing:
        - /b'i'n/b"a"s'h -> /bin/bash
        - c"a"t /e't'c -> cat /etc
        - $IFS -> space
        - ${PATH:0:1} -> /
        """
        res = SHELL_IFS_PATTERN.sub(' ', text)
        # Word-internal quote slicing only (preserves SQL and parameter quotes)
        res = re.sub(r"(?<=\w)['\"](?=\w)", "", res)
        res = re.sub(r"(?<=/)['\"](?=\w)", "", res)
        res = re.sub(r"(?<=\w)['\"](?=/)", "", res)
        res = res.replace('${PATH:0:1}', '/')
        # Shell variable obfuscation stripping ($@, $*, ${u:-})
        res = re.sub(r'\$(?:@|\*|\{[a-zA-Z_][a-zA-Z0-9_]*:-\})', '', res)
        # Word-internal backslash unescaping (e.g. c\a\t /e\t\c/s\h\a\d\o\w -> cat /etc/shadow)
        res = re.sub(r'\\([a-zA-Z0-9_\-\./])', r'\1', res)
        # Collapse multiple redundant slashes in file paths without damaging URL protocol schemes (http://)
        res = re.sub(r'(?<!:)/{2,}', '/', res)
        return res

    @staticmethod
    def normalize_sql(text: str) -> str:
        """
        Strips inline SQL comment fragments (/**/, --, #) and collapses whitespace.
        """
        cleaned = SQL_COMMENT_PATTERN.sub(' ', text)
        return re.sub(r'\s+', ' ', cleaned)

    @staticmethod
    def inspect_and_expand_base64(text: str) -> str:
        """
        Detects embedded base64 command strings and appends decoded equivalents.
        """
        candidates = BASE64_CANDIDATE.findall(text)
        expansions = []
        for c in candidates:
            if len(c) >= 16:
                try:
                    raw_bytes = base64.b64decode(c)
                    decoded_str = raw_bytes.decode('utf-8', errors='ignore')
                    if any(kw in decoded_str.lower() for kw in ['sh', 'bash', 'nc', 'curl', 'wget', 'cat', 'select', 'http', 'tcp', 'exec']):
                        expansions.append(f" [DECODED_B64: {decoded_str}]")
                except Exception:
                    pass
        return text + "".join(expansions)

    @classmethod
    def canonicalize(cls, text: str) -> str:
        """
        Runs all normalization pipelines in sequential order (<5 microseconds).
        """
        if not text:
            return ""

        out = cls.decode_url(text)
        out = cls.decode_html_entities(out)
        out = cls.decode_hex_and_unicode(out)
        out = cls.normalize_shell_obfuscation(out)
        out = cls.normalize_sql(out)
        out = cls.inspect_and_expand_base64(out)
        return out
