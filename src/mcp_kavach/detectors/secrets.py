"""Credential detectors. MVP ships only high-precision prefixed formats —
AWS access key IDs, GitHub tokens, JWTs. Unprefixed secrets (e.g. AWS
*secret* keys, generic API keys) are deliberately excluded: 40 chars of
base64 with no anchor is a false-positive machine. See threat-model.md.
"""

from __future__ import annotations

import re

from mcp_kavach.detectors.regex import RegexDetector


class AwsAccessKeyDetector(RegexDetector):
    name = "aws_access_key"
    entity_type = "AWS_ACCESS_KEY"
    confidence = 0.95
    pattern = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")


class GithubTokenDetector(RegexDetector):
    name = "github_token"
    entity_type = "GITHUB_TOKEN"
    confidence = 0.95
    pattern = re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"
    )


class JwtDetector(RegexDetector):
    name = "jwt"
    entity_type = "JWT"
    confidence = 0.9
    pattern = re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    )
