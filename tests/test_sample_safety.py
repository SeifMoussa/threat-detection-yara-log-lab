"""Safety checks for synthetic sample data and documentation."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ROOT = ROOT / "samples"
DOC_ROOT = ROOT / "docs"

TEXT_SAMPLE_PATTERNS = ("*.txt", "*.csv", "*.jsonl", "*.json")
TOKEN_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|token|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{8,}"),
]
FINANCIAL_PATTERNS = [
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
]
URL_PATTERN = re.compile(r"\bhttps?://([A-Za-z0-9.-]+)")
DOMAIN_PATTERN = re.compile(r"\b([A-Za-z0-9-]+\.(?:com|org|net|test))\b")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RESERVED_DOMAINS = ("example.com", "example.org", "example.net")
PROHIBITED_INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)\bexploit\s+instructions?\b"),
    re.compile(r"(?i)\bweaponized\b"),
    re.compile(r"(?i)\breverse\s+shell\b"),
    re.compile(r"(?i)\bcredential\s+dump(?:ing)?\b"),
]


def test_text_samples_exist_in_each_category() -> None:
    for category in ("benign", "suspicious", "false_positive"):
        files = list((SAMPLE_ROOT / "files" / category).glob("*.txt"))
        assert files, f"Expected at least one text sample in {category}"


def test_samples_do_not_contain_obvious_secret_or_financial_patterns() -> None:
    for sample_file in _sample_files():
        text = sample_file.read_text(encoding="utf-8")
        for pattern in TOKEN_PATTERNS + FINANCIAL_PATTERNS:
            assert not pattern.search(text), f"Unsafe-looking pattern in {sample_file}"


def test_samples_do_not_use_public_ips() -> None:
    for sample_file in _sample_files():
        text = sample_file.read_text(encoding="utf-8")
        for match in IPV4_PATTERN.finditer(text):
            ip_address = ipaddress.ip_address(match.group(0))
            assert _is_allowed_documentation_ip(ip_address), f"Public IP in {sample_file}"


def test_sample_urls_use_reserved_domains_only() -> None:
    for sample_file in _sample_files():
        text = sample_file.read_text(encoding="utf-8")
        for match in URL_PATTERN.finditer(text):
            domain = match.group(1).lower()
            assert domain.endswith(".test") or domain in RESERVED_DOMAINS


def test_samples_do_not_use_unreserved_domains() -> None:
    for sample_file in _sample_files():
        text = sample_file.read_text(encoding="utf-8")
        for match in DOMAIN_PATTERN.finditer(text):
            domain = match.group(1).lower()
            assert domain.endswith(".test") or domain in RESERVED_DOMAINS


def test_suspicious_samples_are_clearly_synthetic() -> None:
    suspicious_files = [
        *list((SAMPLE_ROOT / "logs/suspicious").glob("*")),
        *list((SAMPLE_ROOT / "files/suspicious").glob("*")),
    ]

    for sample_file in suspicious_files:
        if sample_file.name == ".gitkeep":
            continue
        text = sample_file.read_text(encoding="utf-8")
        assert "SYNTHETIC" in text.upper() or '"synthetic":true' in text


def test_samples_are_text_only() -> None:
    for sample_file in _sample_files():
        data = sample_file.read_bytes()
        assert b"\x00" not in data, f"Binary-looking sample file: {sample_file}"


def test_docs_and_samples_do_not_contain_exploit_instructions() -> None:
    for text_file in [*_sample_files(), *DOC_ROOT.rglob("*.md")]:
        text = text_file.read_text(encoding="utf-8")
        for pattern in PROHIBITED_INSTRUCTION_PATTERNS:
            assert not pattern.search(text), f"Unsafe instruction wording in {text_file}"


def _sample_files() -> list[Path]:
    files: list[Path] = []
    for pattern in TEXT_SAMPLE_PATTERNS:
        files.extend(SAMPLE_ROOT.rglob(pattern))
    return [path for path in files if path.is_file()]


def _is_allowed_documentation_ip(ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    documentation_networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )
    return any(ip_address in network for network in documentation_networks)
