"""EVM blockchain operations."""

import traceback
from typing import Any, Dict, Optional
from eth_account import Account
from eth_keys import keys
from web3 import Web3

from hitchcock import config
from hitchcock.models import Credentials
from trezorlib import ethereum, tools
from trezorlib.transport import get_transport
from trezorlib.client import TrezorClient
from trezorlib.ui import ClickUI


class TrezorPINUI(ClickUI):
    """UI handler for Trezor PIN entry."""

    def __init__(self):
        super().__init__()

    def button_request(self, br):
        """Handle button requests from Trezor."""
        # br is a ButtonRequest message object
        # Check the code attribute for the button request type
        if hasattr(br, 'code'):
            if br.code == 26:  # ButtonRequestType_Other
                print("\nPlease confirm on your Trezor device...")
            else:
                print("\nPlease check your Trezor device for confirmation...")
        else:
            print("\nPlease check your Trezor device for confirmation...")
        return super().button_request(br)

    def get_pin(self, code=None):
        """Prompt user for PIN."""
        print("\nTrezor is requesting PIN entry.")
        print("Look at your Trezor device and enter the positions shown on the screen.")
        print("\nPIN Matrix Layout:")
        print("  7    8    9")
        print("  4    5    6")
        print("  1    2    3")
        print("\nFor example, if your device shows positions 7, 3, 9, enter: 739")
        pin = input("\nEnter PIN positions (numbers only, press Enter when done): ").strip()
        return pin

    def get_passphrase(self):
        """Prompt user for passphrase if needed."""
        print("\nTrezor is requesting passphrase.")
        passphrase = input("Enter passphrase (press Enter for no passphrase): ").strip()
        return passphrase if passphrase else None


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


def _get_native_token_symbol(chain_id: int) -> str:
    """Get native token symbol based on chain ID."""
    chain_symbol_map = {
        1: "ETH",      # Ethereum Mainnet
        5: "ETH",      # Goerli
        11155111: "ETH",  # Sepolia
        56: "BNB",     # BSC Mainnet
        97: "BNB",     # BSC Testnet
        137: "MATIC",  # Polygon Mainnet
        80002: "MATIC",  # Polygon Amoy
        8453: "ETH",   # Base Mainnet
        84532: "ETH",  # Base Sepolia
    }
    return chain_symbol_map.get(chain_id, "ETH")


def get_wpac_total_supply(contract_address: str, rpc_endpoint: str) -> float | None:
    """
    Get only the total supply of wPAC contract (lightweight function for faster queries).

    Args:
        contract_address: Address of the wPAC contract
        rpc_endpoint: RPC endpoint URL

    Returns:
        Total supply as float (already divided by decimals), or None if failed
    """
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    try:
        # Minimal ABI - only totalSupply function
        wpac_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"name": "", "type": "uint256"}],
                "type": "function",
            },
        ]

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=wpac_abi,
        )

        total_supply = contract.functions.totalSupply().call()
        # Use fixed decimals from config
        return total_supply / (10 ** config.WPAC_DECIMALS)
    except Exception:
        return None


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
                "name": "name",
                "outputs": [{"name": "", "type": "string"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "symbol",
                "outputs": [{"name": "", "type": "string"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"name": "", "type": "uint256"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
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

        # Get ERC-20 standard properties
        try:
            name = contract.functions.name().call()
            info["name"] = name
        except Exception:
            info["name"] = None

        try:
            symbol = contract.functions.symbol().call()
            info["symbol"] = symbol
        except Exception:
            info["symbol"] = None

        # Decimals is fixed, use config value
        info["decimals"] = config.WPAC_DECIMALS

        try:
            total_supply = contract.functions.totalSupply().call()
            # Use fixed decimals from config instead of fetching from contract
            info["total_supply"] = total_supply / (10 ** config.WPAC_DECIMALS)
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

        # Get native token balances for admin addresses
        chain_id = w3.eth.chain_id
        native_symbol = _get_native_token_symbol(chain_id)

        # Get owner balance
        if info.get("owner"):
            try:
                owner_balance = w3.eth.get_balance(Web3.to_checksum_address(info["owner"]))
                info["owner_balance"] = Web3.from_wei(owner_balance, "ether")
                info["owner_balance_symbol"] = native_symbol
            except Exception:
                info["owner_balance"] = None
                info["owner_balance_symbol"] = native_symbol

        # Get minter balance
        if info.get("minter"):
            try:
                minter_balance = w3.eth.get_balance(Web3.to_checksum_address(info["minter"]))
                info["minter_balance"] = Web3.from_wei(minter_balance, "ether")
                info["minter_balance_symbol"] = native_symbol
            except Exception:
                info["minter_balance"] = None
                info["minter_balance_symbol"] = native_symbol

        # Get fee collector balance
        if info.get("fee_collector"):
            try:
                fee_collector_balance = w3.eth.get_balance(Web3.to_checksum_address(info["fee_collector"]))
                info["fee_collector_balance"] = Web3.from_wei(fee_collector_balance, "ether")
                info["fee_collector_balance_symbol"] = native_symbol
            except Exception:
                info["fee_collector_balance"] = None
                info["fee_collector_balance_symbol"] = native_symbol

        # Get collected fees (contract's own balance)
        # According to the contract, fees are accumulated in the contract balance
        # and can be withdrawn via withdrawFee() which transfers balanceOf(address(this))
        try:
            contract_balance = contract.functions.balanceOf(
                Web3.to_checksum_address(contract_address)
            ).call()
            # Convert to human-readable format using fixed decimals
            info["collected_fee"] = contract_balance / (10 ** config.WPAC_DECIMALS)
        except Exception:
            info["collected_fee"] = None

    except Exception as e:
        info["total_supply"] = None
        info["error"] = str(e)

    return info


def sign_transaction_with_trezor(
    transaction: Dict[str, Any],
    derivation_path: str = "m/44'/60'/0'/0/5",
) -> bytes:
    """
    Sign a transaction using Trezor hardware wallet.

    Args:
        transaction: Unsigned transaction dictionary
        derivation_path: BIP44 derivation path (default: m/44'/60'/0'/0/5)

    Returns:
        Signed transaction bytes
    """
    try:
        # Connect to Trezor device
        transport = get_transport()
    except Exception as e:
        raise ValueError(
            f"Failed to connect to Trezor device: {e}\n"
            "Please ensure your Trezor device is:\n"
            "  - Connected via USB\n"
            "  - Unlocked\n"
            "  - Has the Ethereum app open (if using Trezor Model T)"
        )

    try:
        from trezorlib.client import TrezorClient
        ui = TrezorPINUI()
        client = TrezorClient(transport, ui=ui)

        # Parse derivation path
        address_n = tools.parse_path(derivation_path)

        # Prepare transaction data
        tx_data = transaction.get("data", b"")
        if isinstance(tx_data, str):
            tx_data = bytes.fromhex(tx_data.replace("0x", ""))
        elif not isinstance(tx_data, bytes):
            tx_data = b""

        # Prepare transaction parameters - Legacy transactions
        # Use gasPrice for legacy transactions
        gas_price = transaction.get("gasPrice", 0)
        if gas_price == 0:
            # Fallback to maxFeePerGas if gasPrice not available
            gas_price = transaction.get("maxFeePerGas", 0)

        # Sign the transaction
        # Note: 'to' parameter must be a hex string, not bytes
        to_address = transaction["to"]
        if to_address.startswith("0x"):
            to_address = to_address[2:]

        # Sign the transaction - returns (v, r, s) tuple
        v, r, s = ethereum.sign_tx(
            client,
            address_n,
            nonce=transaction["nonce"],
            gas_price=gas_price,
            gas_limit=transaction["gas"],
            to=to_address,  # Must be hex string, not bytes
            value=transaction.get("value", 0),
            data=tx_data,
            chain_id=transaction["chainId"],
            tx_type=None,  # Legacy transaction (type 0)
        )

        # Reconstruct the signed transaction from v, r, s
        # For legacy transactions, encode using RLP: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        import rlp

        # Prepare transaction fields
        nonce = transaction["nonce"]
        gas_limit = transaction["gas"]
        to_addr = transaction["to"]
        if to_addr and to_addr.startswith("0x"):
            to_addr = bytes.fromhex(to_addr[2:])
        elif to_addr:
            to_addr = bytes.fromhex(to_addr)
        else:
            to_addr = b""
        value = transaction.get("value", 0)
        data = tx_data

        # RLP encode the transaction: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        # All numeric fields should be integers, not bytes
        transaction_list = [
            nonce,
            gas_price,
            gas_limit,
            to_addr,
            value,
            data,
            v,  # v, r, s are already integers from Trezor
            r,
            s,
        ]

        signed_tx = rlp.encode(transaction_list)

        return signed_tx
    except Exception as e:
        # Capture detailed error information
        error_type = type(e).__name__
        error_msg = str(e) if str(e) else repr(e)

        # Get full traceback
        tb_lines = traceback.format_exception(type(e), e, e.__traceback__)
        tb_str = ''.join(tb_lines)

        # Include more context if available
        if hasattr(e, '__cause__') and e.__cause__:
            error_msg += f" (caused by: {e.__cause__})"

        # Build detailed error message
        detailed_error = (
            f"Failed to sign transaction with Trezor\n"
            f"Error Type: {error_type}\n"
            f"Error Message: {error_msg}\n"
            f"\nTransaction Details:\n"
            f"  - Nonce: {transaction.get('nonce')}\n"
            f"  - Gas: {transaction.get('gas')}\n"
            f"  - Chain ID: {transaction.get('chainId')}\n"
            f"  - To: {transaction.get('to')}\n"
            f"  - Value: {transaction.get('value', 0)}\n"
            f"  - Gas Price: {transaction.get('gasPrice', transaction.get('maxFeePerGas', 'N/A'))}\n"
            f"  - Transaction Type: {transaction.get('type', 0)}\n"
            f"\nFull Traceback:\n{tb_str}\n"
            f"Please ensure:\n"
            f"  - Your Trezor device is connected and unlocked\n"
            f"  - The Ethereum app is open (if using Trezor Model T)\n"
            f"  - You approve the transaction on the device"
        )

        raise ValueError(detailed_error)


def create_set_minter_transaction(
    contract_address: str,
    new_minter: str,
    owner_privkey: Optional[str] = None,
    rpc_endpoint: str = "",
    use_trezor: bool = False,
    trezor_path: str = "m/44'/60'/0'/0/5",
) -> Dict[str, Any]:
    """Create and sign a transaction to set the minter address."""
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Get owner address - either from Trezor or private key
    if use_trezor:
        try:
            transport = get_transport()
        except Exception as e:
            raise ValueError(
                f"Failed to connect to Trezor device: {e}\n"
                "Please ensure your Trezor device is:\n"
                "  - Connected via USB\n"
                "  - Unlocked\n"
                "  - Has the Ethereum app open (if using Trezor Model T)"
            )
        try:
            ui = TrezorPINUI()
            client = TrezorClient(transport, ui=ui)
            address_n = tools.parse_path(trezor_path)
            owner_address = ethereum.get_address(client, address_n, show_display=False)
            owner_address = Web3.to_checksum_address(owner_address)
        except Exception as e:
            raise ValueError(
                f"Failed to get address from Trezor: {e}\n"
                "Please ensure your Trezor device is unlocked and ready."
            )
    else:
        if not owner_privkey:
            raise ValueError("Private key is required when not using Trezor")
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

        # Build transaction parameters - Legacy transactions
        tx_params = {
            "from": owner_address,
            "nonce": w3.eth.get_transaction_count(owner_address),
            "gas": int(gas_estimate * 1.2),  # Add 20% buffer
            "chainId": chain_id,
        }

        # Use legacy transactions (gasPrice)
        current_gas_price = w3.eth.gas_price
        tx_params["gasPrice"] = current_gas_price
        utils.info(f"Using legacy transaction")
        utils.info(f"  Gas Price: {current_gas_price}")

        transaction = contract.functions.setMinter(Web3.to_checksum_address(new_minter)).build_transaction(tx_params)
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")

    # Sign transaction
    try:
        if use_trezor:
            signed_bytes = sign_transaction_with_trezor(transaction, trezor_path)
            tx_hash = Web3.keccak(signed_bytes).hex()
            return {
                "contract_address": contract_address,
                "raw_transaction": signed_bytes.hex(),
                "transaction_hash": tx_hash,
            }
        else:
            signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
            return {
                "contract_address": contract_address,
                "raw_transaction": signed_txn.raw_transaction.hex(),
                "transaction_hash": signed_txn.hash.hex(),
            }
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")


def send_transaction(raw_transaction_hex: str, rpc_endpoint: str) -> Dict[str, Any]:
    """Send a signed transaction to the blockchain."""
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    try:
        # Remove 0x prefix if present
        if raw_transaction_hex.startswith("0x"):
            raw_transaction_hex = raw_transaction_hex[2:]

        # Validate transaction format
        try:
            raw_tx_bytes = bytes.fromhex(raw_transaction_hex)
            if len(raw_tx_bytes) == 0:
                raise ValueError("Empty transaction data")
        except ValueError as e:
            raise ValueError(f"Invalid transaction hex format: {e}")

        # Try to decode and validate the transaction before sending (if supported)
        try:
            if hasattr(w3.eth, 'decode_transaction'):
                decoded_tx = w3.eth.decode_transaction(raw_tx_bytes)
                from hitchcock import utils
                utils.info(f"Transaction decoded successfully:")
                utils.info(f"  From: {decoded_tx.get('from')}")
                utils.info(f"  To: {decoded_tx.get('to')}")
                utils.info(f"  Nonce: {decoded_tx.get('nonce')}")
                utils.info(f"  Gas: {decoded_tx.get('gas')}")
        except (AttributeError, Exception):
            # decode_transaction not available in this web3.py version, skip validation
            pass

        # Send the transaction
        try:
            tx_hash = w3.eth.send_raw_transaction(raw_tx_bytes)
        except Exception as send_error:
            # Provide more detailed error information
            error_msg = str(send_error)
            if "500" in error_msg or "Internal Server Error" in error_msg:
                raise ValueError(
                    f"RPC endpoint returned 500 Internal Server Error: {error_msg}\n"
                    "This is usually a temporary issue with the RPC provider.\n"
                    "Suggestions:\n"
                    "  - Try again in a few moments\n"
                    "  - Check if the RPC endpoint is operational\n"
                    "  - Try using a different RPC endpoint\n"
                    f"  - Transaction hash (if available): {Web3.keccak(raw_tx_bytes).hex()}"
                )
            else:
                raise ValueError(f"Failed to send transaction to RPC: {error_msg}")

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
    except ValueError:
        # Re-raise ValueError as-is (already formatted)
        raise
    except Exception as e:
        raise ValueError(f"Failed to send transaction: {e}")


def create_set_fee_collector_transaction(
    contract_address: str,
    new_fee_collector: str,
    owner_privkey: Optional[str] = None,
    rpc_endpoint: str = "",
    use_trezor: bool = False,
    trezor_path: str = "m/44'/60'/0'/0/5",
) -> Dict[str, Any]:
    """Create and sign a transaction to set the fee collector address."""
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Get owner address - either from Trezor or private key
    if use_trezor:
        try:
            transport = get_transport()
        except Exception as e:
            raise ValueError(
                f"Failed to connect to Trezor device: {e}\n"
                "Please ensure your Trezor device is:\n"
                "  - Connected via USB\n"
                "  - Unlocked\n"
                "  - Has the Ethereum app open (if using Trezor Model T)"
            )
        try:
            ui = TrezorPINUI()
            client = TrezorClient(transport, ui=ui)
            address_n = tools.parse_path(trezor_path)
            owner_address = ethereum.get_address(client, address_n, show_display=False)
            owner_address = Web3.to_checksum_address(owner_address)
        except Exception as e:
            raise ValueError(
                f"Failed to get address from Trezor: {e}\n"
                "Please ensure your Trezor device is unlocked and ready."
            )
    else:
        if not owner_privkey:
            raise ValueError("Private key is required when not using Trezor")
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

        # Build transaction parameters - Legacy transactions
        tx_params = {
            "from": owner_address,
            "nonce": w3.eth.get_transaction_count(owner_address),
            "gas": int(gas_estimate * 1.2),  # Add 20% buffer
            "chainId": chain_id,
        }

        # Use legacy transactions (gasPrice)
        current_gas_price = w3.eth.gas_price
        tx_params["gasPrice"] = current_gas_price
        utils.info(f"Using legacy transaction")
        utils.info(f"  Gas Price: {current_gas_price}")

        transaction = contract.functions.setFeeCollector(Web3.to_checksum_address(new_fee_collector)).build_transaction(tx_params)
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")

    # Sign transaction
    try:
        if use_trezor:
            signed_bytes = sign_transaction_with_trezor(transaction, trezor_path)
            tx_hash = Web3.keccak(signed_bytes).hex()
            return {
                "contract_address": contract_address,
                "raw_transaction": signed_bytes.hex(),
                "transaction_hash": tx_hash,
            }
        else:
            signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
            return {
                "contract_address": contract_address,
                "raw_transaction": signed_txn.raw_transaction.hex(),
                "transaction_hash": signed_txn.hash.hex(),
            }
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")


def create_transfer_ownership_transaction(
    contract_address: str,
    new_owner: str,
    owner_privkey: Optional[str] = None,
    rpc_endpoint: str = "",
    use_trezor: bool = False,
    trezor_path: str = "m/44'/60'/0'/0/5",
) -> Dict[str, Any]:
    """Create and sign a transaction to transfer ownership."""
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Get owner address - either from Trezor or private key
    if use_trezor:
        try:
            transport = get_transport()
        except Exception as e:
            raise ValueError(
                f"Failed to connect to Trezor device: {e}\n"
                "Please ensure your Trezor device is:\n"
                "  - Connected via USB\n"
                "  - Unlocked\n"
                "  - Has the Ethereum app open (if using Trezor Model T)"
            )
        try:
            ui = TrezorPINUI()
            client = TrezorClient(transport, ui=ui)
            address_n = tools.parse_path(trezor_path)
            owner_address = ethereum.get_address(client, address_n, show_display=False)
            owner_address = Web3.to_checksum_address(owner_address)
        except Exception as e:
            raise ValueError(
                f"Failed to get address from Trezor: {e}\n"
                "Please ensure your Trezor device is unlocked and ready."
            )
    else:
        if not owner_privkey:
            raise ValueError("Private key is required when not using Trezor")
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

    # wPAC contract ABI for transferOwnership function
    wpac_abi = [
        {
            "constant": False,
            "inputs": [{"name": "newOwner", "type": "address"}],
            "name": "transferOwnership",
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
        gas_estimate = contract.functions.transferOwnership(Web3.to_checksum_address(new_owner)).estimate_gas(
            {"from": owner_address}
        )

        # Get chain ID from RPC (always fetch from the connected node)
        chain_id = w3.eth.chain_id

        # Debug information for developers
        from hitchcock import utils
        utils.info(f"Chain ID: {chain_id}")

        # Build transaction parameters - Legacy transactions
        tx_params = {
            "from": owner_address,
            "nonce": w3.eth.get_transaction_count(owner_address),
            "gas": int(gas_estimate * 1.2),  # Add 20% buffer
            "chainId": chain_id,
        }

        # Use legacy transactions (gasPrice)
        current_gas_price = w3.eth.gas_price
        tx_params["gasPrice"] = current_gas_price
        utils.info(f"Using legacy transaction")
        utils.info(f"  Gas Price: {current_gas_price}")

        transaction = contract.functions.transferOwnership(Web3.to_checksum_address(new_owner)).build_transaction(tx_params)
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")

    # Sign transaction
    try:
        if use_trezor:
            signed_bytes = sign_transaction_with_trezor(transaction, trezor_path)
            tx_hash = Web3.keccak(signed_bytes).hex()
            return {
                "contract_address": contract_address,
                "raw_transaction": signed_bytes.hex(),
                "transaction_hash": tx_hash,
            }
        else:
            signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
            return {
                "contract_address": contract_address,
                "raw_transaction": signed_txn.raw_transaction.hex(),
                "transaction_hash": signed_txn.hash.hex(),
            }
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")

