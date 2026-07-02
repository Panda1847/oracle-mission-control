"""mTLS context helpers for worker communication."""

from __future__ import annotations

import ssl
from dataclasses import dataclass


@dataclass
class TLSConfig:
    certfile: str = ""
    keyfile: str = ""
    cafile: str = ""
    require_client_cert: bool = False


def build_server_context(config: TLSConfig) -> ssl.SSLContext | None:
    if not (config.certfile and config.keyfile):
        return None
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)
    if config.cafile:
        context.load_verify_locations(cafile=config.cafile)
    if config.require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def build_client_context(config: TLSConfig) -> ssl.SSLContext | None:
    if not config.cafile and not (config.certfile and config.keyfile):
        return None
    context = ssl.create_default_context(cafile=config.cafile or None)
    if config.certfile and config.keyfile:
        context.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)
    return context

