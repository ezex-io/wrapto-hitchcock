"""Data models for Hitchcock."""

from dataclasses import dataclass


@dataclass
class Credentials:
    """Credentials data model."""
    network: str
    variant: str
    private_key: str
    public_key: str
    address: str
    environment: str | None = None

