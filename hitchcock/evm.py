"""EVM blockchain operations."""

from typing import Any, Dict
from eth_account import Account
from eth_keys import keys
from web3 import Web3

from hitchcock.models import Credentials


def generate_credentials(network: str) -> Credentials:
    """Generate EVM credentials (secp256k1)."""
    account = Account.create()
    key_hex = account.key.hex()
    public_key_hex = account._key_obj.public_key.to_hex()

    return Credentials(
        network=network,
        variant="secp256k1",
        private_key=key_hex,
        public_key=public_key_hex,
        address=account.address,
    )


def derive_address_from_private_key(privkey_str: str) -> Dict[str, str]:
    """Derive address from EVM private key."""
    # Remove 0x prefix if present
    if privkey_str.startswith("0x"):
        privkey_str = privkey_str[2:]

    try:
        private_key_bytes = bytes.fromhex(privkey_str)
    except ValueError:
        raise ValueError("Invalid hex format for private key.")

    if len(private_key_bytes) != 32:
        raise ValueError("Private key must be 32 bytes (64 hex characters).")

    private_key_obj = keys.PrivateKey(private_key_bytes)
    public_key_obj = private_key_obj.public_key
    account = Account.from_key(private_key_bytes)

    return {
        "private_key": privkey_str,
        "public_key": public_key_obj.to_hex(),
        "address": account.address,
    }


def get_wpac_info(contract_address: str, rpc_endpoint: str) -> Dict[str, Any]:
    """Get wPAC contract information."""
    # Handle WebSocket URLs
    if rpc_endpoint.startswith("wss://"):
        http_endpoint = rpc_endpoint.replace("wss://", "https://")
        w3 = Web3(Web3.HTTPProvider(http_endpoint))
    else:
        w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    info = {}

    # Get contract native balance
    try:
        balance_wei = w3.eth.get_balance(Web3.to_checksum_address(contract_address))
        balance_eth = w3.from_wei(balance_wei, "ether")
        info["native_balance"] = balance_eth
    except Exception as e:
        info["native_balance"] = None
        info["native_balance_error"] = str(e)

    # Get ERC-20 total supply and admin addresses
    try:
        wpac_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"name": "", "type": "uint256"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "owner",
                "outputs": [{"name": "", "type": "address"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "MINTER",
                "outputs": [{"name": "", "type": "address"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "FEE_COLLECTOR",
                "outputs": [{"name": "", "type": "address"}],
                "type": "function",
            },
        ]

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=wpac_abi,
        )

        try:
            total_supply = contract.functions.totalSupply().call()
            decimals = contract.functions.decimals().call()
            info["total_supply"] = total_supply / (10 ** decimals)
            info["decimals"] = decimals
        except Exception:
            info["total_supply"] = None

        # Get admin addresses
        try:
            owner = contract.functions.owner().call()
            info["owner"] = owner
        except Exception:
            info["owner"] = None

        try:
            minter = contract.functions.MINTER().call()
            info["minter"] = minter
        except Exception:
            info["minter"] = None

        try:
            fee_collector = contract.functions.FEE_COLLECTOR().call()
            info["fee_collector"] = fee_collector
        except Exception:
            info["fee_collector"] = None

    except Exception as e:
        info["total_supply"] = None
        info["error"] = str(e)

    return info


def create_set_minter_transaction(
    contract_address: str,
    new_minter: str,
    owner_privkey: str,
    rpc_endpoint: str,
) -> Dict[str, Any]:
    """Create and sign a transaction to set the minter address."""
    # Handle WebSocket URLs
    if rpc_endpoint.startswith("wss://"):
        http_endpoint = rpc_endpoint.replace("wss://", "https://")
        w3 = Web3(Web3.HTTPProvider(http_endpoint))
    else:
        w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Remove 0x prefix from private key if present
    if owner_privkey.startswith("0x"):
        owner_privkey = owner_privkey[2:]

    try:
        private_key_bytes = bytes.fromhex(owner_privkey)
    except ValueError:
        raise ValueError("Invalid hex format for private key.")

    if len(private_key_bytes) != 32:
        raise ValueError("Private key must be 32 bytes (64 hex characters).")

    account = Account.from_key(private_key_bytes)
    owner_address = account.address

    # wPAC contract ABI for setMinter function
    wpac_abi = [
        {
            "constant": False,
            "inputs": [{"name": "_minterAddress", "type": "address"}],
            "name": "setMinter",
            "outputs": [],
            "type": "function",
        },
    ]

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=wpac_abi,
    )

    # Build transaction
    try:
        # Estimate gas first
        gas_estimate = contract.functions.setMinter(Web3.to_checksum_address(new_minter)).estimate_gas(
            {"from": owner_address}
        )
        transaction = contract.functions.setMinter(Web3.to_checksum_address(new_minter)).build_transaction(
            {
                "from": owner_address,
                "nonce": w3.eth.get_transaction_count(owner_address),
                "gas": int(gas_estimate * 1.2),  # Add 20% buffer
                "gasPrice": w3.eth.gas_price,
            }
        )
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")

    # Sign transaction
    try:
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")

    return {
        "contract_address": contract_address,
        "raw_transaction": signed_txn.rawTransaction.hex(),
        "transaction_hash": signed_txn.hash.hex(),
    }


def create_set_fee_collector_transaction(
    contract_address: str,
    new_fee_collector: str,
    owner_privkey: str,
    rpc_endpoint: str,
) -> Dict[str, Any]:
    """Create and sign a transaction to set the fee collector address."""
    # Handle WebSocket URLs
    if rpc_endpoint.startswith("wss://"):
        http_endpoint = rpc_endpoint.replace("wss://", "https://")
        w3 = Web3(Web3.HTTPProvider(http_endpoint))
    else:
        w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Remove 0x prefix from private key if present
    if owner_privkey.startswith("0x"):
        owner_privkey = owner_privkey[2:]

    try:
        private_key_bytes = bytes.fromhex(owner_privkey)
    except ValueError:
        raise ValueError("Invalid hex format for private key.")

    if len(private_key_bytes) != 32:
        raise ValueError("Private key must be 32 bytes (64 hex characters).")

    account = Account.from_key(private_key_bytes)
    owner_address = account.address

    # wPAC contract ABI for setFeeCollector function
    wpac_abi = [
        {
            "constant": False,
            "inputs": [{"name": "_feeCollectorAddress", "type": "address"}],
            "name": "setFeeCollector",
            "outputs": [],
            "type": "function",
        },
    ]

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=wpac_abi,
    )

    # Build transaction
    try:
        # Estimate gas first
        gas_estimate = contract.functions.setFeeCollector(Web3.to_checksum_address(new_fee_collector)).estimate_gas(
            {"from": owner_address}
        )
        transaction = contract.functions.setFeeCollector(Web3.to_checksum_address(new_fee_collector)).build_transaction(
            {
                "from": owner_address,
                "nonce": w3.eth.get_transaction_count(owner_address),
                "gas": int(gas_estimate * 1.2),  # Add 20% buffer
                "gasPrice": w3.eth.gas_price,
            }
        )
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")

    # Sign transaction
    try:
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")

    return {
        "contract_address": contract_address,
        "raw_transaction": signed_txn.rawTransaction.hex(),
        "transaction_hash": signed_txn.hash.hex(),
    }

