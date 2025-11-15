"""EVM blockchain operations."""

from typing import Any, Dict
from eth_account import Account
from eth_keys import keys
from web3 import Web3

from hitchcock import config
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
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    info = {}

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

        # Get chain ID from RPC (always fetch from the connected node)
        chain_id = w3.eth.chain_id

        # Debug information for developers
        from hitchcock import utils
        utils.info(f"Chain ID: {chain_id}")

        # Build transaction parameters - use EIP-1559 for modern chains
        tx_params = {
            "from": owner_address,
            "nonce": w3.eth.get_transaction_count(owner_address),
            "gas": int(gas_estimate * 1.2),  # Add 20% buffer
            "chainId": chain_id,
        }

        # Try to use EIP-1559 (type 2) for modern chains
        # Most modern chains support EIP-1559, so we'll try it and fallback to legacy if needed
        try:
            max_priority_fee = w3.eth.max_priority_fee
            # Estimate max fee as 2x current gas price (safe fallback)
            current_gas_price = w3.eth.gas_price
            max_fee_per_gas = current_gas_price * 2
            tx_params["maxFeePerGas"] = max_fee_per_gas
            tx_params["maxPriorityFeePerGas"] = max_priority_fee
            tx_params["type"] = 2  # EIP-1559
            utils.info(f"Using EIP-1559 transaction (Type 2)")
            utils.info(f"  Max Fee Per Gas: {max_fee_per_gas}")
            utils.info(f"  Max Priority Fee Per Gas: {max_priority_fee}")
        except Exception as e:
            # Fallback to legacy transaction if EIP-1559 fee estimation fails
            utils.warn(f"EIP-1559 not available, using legacy transaction: {e}")
            tx_params["gasPrice"] = w3.eth.gas_price
            utils.info(f"  Gas Price: {tx_params['gasPrice']}")

        transaction = contract.functions.setMinter(Web3.to_checksum_address(new_minter)).build_transaction(tx_params)
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")

    # Sign transaction
    try:
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")

    return {
        "contract_address": contract_address,
        "raw_transaction": signed_txn.raw_transaction.hex(),
        "transaction_hash": signed_txn.hash.hex(),
    }


def send_transaction(raw_transaction_hex: str, rpc_endpoint: str) -> Dict[str, Any]:
    """Send a signed transaction to the blockchain."""
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    try:
        # Remove 0x prefix if present
        if raw_transaction_hex.startswith("0x"):
            raw_transaction_hex = raw_transaction_hex[2:]

        # Send the transaction
        tx_hash = w3.eth.send_raw_transaction(bytes.fromhex(raw_transaction_hex))

        # Wait for transaction receipt (optional, can be removed if not needed)
        try:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            return {
                "transaction_hash": tx_hash.hex(),
                "status": receipt.status,
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
            }
        except Exception:
            # If we can't wait for receipt, just return the hash
            return {
                "transaction_hash": tx_hash.hex(),
                "status": "pending",
            }
    except Exception as e:
        raise ValueError(f"Failed to send transaction: {e}")


def create_set_fee_collector_transaction(
    contract_address: str,
    new_fee_collector: str,
    owner_privkey: str,
    rpc_endpoint: str,
) -> Dict[str, Any]:
    """Create and sign a transaction to set the fee collector address."""
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

        # Get chain ID from RPC (always fetch from the connected node)
        chain_id = w3.eth.chain_id

        # Debug information for developers
        from hitchcock import utils
        utils.info(f"Chain ID: {chain_id}")

        # Build transaction parameters - use EIP-1559 for modern chains
        tx_params = {
            "from": owner_address,
            "nonce": w3.eth.get_transaction_count(owner_address),
            "gas": int(gas_estimate * 1.2),  # Add 20% buffer
            "chainId": chain_id,
        }

        # Try to use EIP-1559 (type 2) for modern chains
        # Most modern chains support EIP-1559, so we'll try it and fallback to legacy if needed
        try:
            max_priority_fee = w3.eth.max_priority_fee
            # Estimate max fee as 2x current gas price (safe fallback)
            current_gas_price = w3.eth.gas_price
            max_fee_per_gas = current_gas_price * 2
            tx_params["maxFeePerGas"] = max_fee_per_gas
            tx_params["maxPriorityFeePerGas"] = max_priority_fee
            tx_params["type"] = 2  # EIP-1559
            utils.info(f"Using EIP-1559 transaction (Type 2)")
            utils.info(f"  Max Fee Per Gas: {max_fee_per_gas}")
            utils.info(f"  Max Priority Fee Per Gas: {max_priority_fee}")
        except Exception as e:
            # Fallback to legacy transaction if EIP-1559 fee estimation fails
            utils.warn(f"EIP-1559 not available, using legacy transaction: {e}")
            tx_params["gasPrice"] = w3.eth.gas_price
            utils.info(f"  Gas Price: {tx_params['gasPrice']}")

        transaction = contract.functions.setFeeCollector(Web3.to_checksum_address(new_fee_collector)).build_transaction(tx_params)
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")

    # Sign transaction
    try:
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")

    return {
        "contract_address": contract_address,
        "raw_transaction": signed_txn.raw_transaction.hex(),
        "transaction_hash": signed_txn.hash.hex(),
    }

