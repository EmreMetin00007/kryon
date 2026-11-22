"""Encrypted local credential vault and bounded IMAP OTP reader."""
from __future__ import annotations

from . import otp_core
from .credential_vault import CredentialVault
from .otp_core import OtpError, fetch_latest_otp

__all__ = [
    "CredentialVault",
    "OtpError",
    "fetch_latest_otp",
    "otp_core",
]
