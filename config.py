#!/usr/bin/env python3
"""
Configuration module for Hitchcock.
Stores contract addresses and RPC endpoints for various networks.
Supports environment variables with fallback to defaults.
"""

import os
from typing import Dict, Optional
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


def get_env(key: str, default: str) -> str:
    """Get environment variable with fallback to default."""
    return os.getenv(key, default)


# Contract addresses organized by contract name, network, and environment
# Structure: CONTRACTS[contract_name][network][environment]
CONTRACTS: Dict[str, Dict[str, Dict[str, str]]] = {
    "wpac": {
        "polygon": {
            "testnet": "0x1F9EcDf71DDb39022728B53f5584621762e466be",  # Polygon Amoy
            "mainnet": "0x2f77E0afAEE06970Bf860B8267b5aFECFFF6F216",
        },
        "bsc": {
            "testnet": "0xA9A2511Bb9cE4aCF4F02D679Af836a0fcC8c8AF7",  # BSC Testnet
            "mainnet": "0x10004a9A742ec135c686C9aCed00FA3C93D66866",
        },
        "base": {
            "testnet": "0x1F9EcDf71DDb39022728B53f5584621762e466be",  # Base Sepolia
            "mainnet": "0x10004a9A742ec135c686C9aCed00FA3C93D66866",
        },
    },
}


# RPC endpoints with environment variable support and defaults
# Structure: RPC_ENDPOINTS[network][environment]
RPC_ENDPOINTS: Dict[str, Dict[str, str]] = {
    "polygon": {
        "testnet": get_env(
            "POLYGON_AMOY_RPC",
            "https://polygon-amoy.drpc.org"
        ),
        "mainnet": get_env(
            "POLYGON_MAINNET_RPC",
            "https://polygon.drpc.org"
        ),
    },
    "bsc": {
        "testnet": get_env(
            "BSC_TESTNET_RPC",
            "wss://bsc-testnet.drpc.org"
        ),
        "mainnet": get_env(
            "BSC_MAINNET_RPC",
            "https://bsc.drpc.org"
        ),
    },
    "base": {
        "testnet": get_env(
            "BASE_SEPOLIA_RPC",
            "https://base-sepolia.drpc.org"
        ),
        "mainnet": get_env(
            "BASE_MAINNET_RPC",
            "https://base.drpc.org"
        ),
    },
}


def get_contract_address(
    contract_name: str,
    network: str,
    environment: str = "mainnet"
) -> Optional[str]:
    """
    Get contract address for a given contract, network, and environment.

    Args:
        contract_name: Name of the contract (e.g., "hitchcock")
        network: Network name (e.g., "polygon", "bsc", "base")
        environment: Environment type ("testnet" or "mainnet")

    Returns:
        Contract address as string, or None if not found
    """
    return CONTRACTS.get(contract_name, {}).get(network, {}).get(environment)


def get_rpc_endpoint(
    network: str,
    environment: str = "mainnet"
) -> Optional[str]:
    """
    Get RPC endpoint for a given network and environment.

    Args:
        network: Network name (e.g., "polygon", "bsc", "base")
        environment: Environment type ("testnet" or "mainnet")

    Returns:
        RPC endpoint URL as string, or None if not found
    """
    return RPC_ENDPOINTS.get(network, {}).get(environment)


def list_contracts() -> list[str]:
    """List all available contract names."""
    return list(CONTRACTS.keys())


def list_networks() -> list[str]:
    """List all available network names."""
    return list(RPC_ENDPOINTS.keys())


def list_environments() -> list[str]:
    """List all available environment types."""
    return ["testnet", "mainnet"]


# Pactus Wrapto addresses (deposit and withdraw)
# Deposit: locked/cold address for wrapping PAC
# Withdraw: unlocked/warm address for unwrapping wPAC
WRAPTO_ADDRESSES: Dict[str, Dict[str, str]] = {
    "mainnet": {
        "deposit": "pc1zgp0x33hehvczq6dggs04gywfqpzl9fea5039gh",
        "withdraw": "pc1zqyxjatqfhaj3arc727alwl4sa3z8lv2m730eh2",
    },
    "testnet": {
        "deposit": "tpc1rlqj68h3hm4nw9js3jpnl75kr8sfh79xkxt2lck",
        "withdraw": "tpc1rlqj68h3hm4nw9js3jpnl75kr8sfh79xkxt2lck",
    },
}


def get_wrapto_address(environment: str = "mainnet", address_type: str = "deposit") -> Optional[str]:
    """
    Get Wrapto address for a given environment and type.

    Args:
        environment: Environment type ("testnet" or "mainnet")
        address_type: Type of address ("deposit" or "withdraw")

    Returns:
        Wrapto address as string, or None if not found
    """
    return WRAPTO_ADDRESSES.get(environment, {}).get(address_type)

