# Security Policy

OpenScholarGuard is a defensive project for detecting and sanitizing document-borne prompt
injection and AI-review manipulation attempts.

## Reporting Vulnerabilities

Please report security issues privately through the repository security advisory workflow
when available. If that is not available yet, open a minimal issue that does not disclose
an exploit payload and ask for a private contact channel.

## Scope

Security-relevant reports include:

- Scanner bypasses for documented detector classes.
- Sanitizer failures that keep high-risk hidden instructions.
- Crashes caused by malformed PDFs or documents.
- Report rendering issues such as unsafe HTML escaping.

## Non-Goals

OpenScholarGuard does not guarantee that a document is safe. It provides audit signals and
sanitized text for downstream systems. Use it as one layer in a broader safety architecture.
