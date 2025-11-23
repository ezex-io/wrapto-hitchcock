"""EVM blockchain operations."""

import traceback
from typing import Any, Callable, Dict, List, Optional
from eth_account import Account
from eth_keys import keys
from web3 import Web3

from hitchcock import config, utils
from hitchcock.models import Credentials
from pactus.types import Amount
from trezorlib import ethereum, tools
from trezorlib.transport import get_transport
from trezorlib.client import TrezorClient
from trezorlib.ui import ClickUI

EIP1967_IMPLEMENTATION_SLOT = int(
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16
)


class EVMClient:
    """EVM blockchain client that manages RPC connections."""

    def __init__(self, network: str, environment: str = "testnet"):
        """
        Initialize EVM client with network and environment.

        Args:
            network: Network name (e.g., "ethereum", "polygon", "bnb", "base")
            environment: "testnet" or "mainnet"
        """
        self.network = network.lower()
        self.environment = environment.lower()

        # Get RPC endpoint from config
        rpc_endpoint = config.get_rpc_endpoint(self.network, self.environment)
        if not rpc_endpoint:
            raise ValueError(f"RPC endpoint not found for {self.network} {self.environment}")

        self.rpc_endpoint = rpc_endpoint
        self.w3 = self._connect_web3()

    def _connect_web3(self) -> Web3:
        """Return a connected Web3 instance or raise if unreachable."""
        w3 = Web3(Web3.HTTPProvider(self.rpc_endpoint))

        if not w3.is_connected():
            raise ConnectionError(f"Failed to connect to RPC endpoint: {self.rpc_endpoint}")

        return w3

    def generate_credentials(self) -> Credentials:
        """Generate EVM credentials (secp256k1)."""
        account = Account.create()
        key_hex = account.key.hex()
        public_key_hex = account._key_obj.public_key.to_hex()

        return Credentials(
            network=self.network,
            variant="secp256k1",
            private_key=key_hex,
            public_key=public_key_hex,
            address=account.address,
        )

    def derive_address_from_private_key(self, privkey_str: str) -> Dict[str, str]:
        """Derive address from EVM private key."""
        # Remove 0x prefix if present
        if privkey_str.startswith("0x"):
            privkey_str = privkey_str[2:]

        private_key_bytes = bytes.fromhex(privkey_str)

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

    def get_wpac_total_supply(self, contract_address: str) -> Amount:
        """
        Get only the total supply of WPAC contract (lightweight function for faster queries).

        Args:
            contract_address: Address of the WPAC contract

        Returns:
            Total supply as Amount

        Raises:
            ConnectionError: If unable to connect to RPC endpoint
            Exception: If contract call fails
        """
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

        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=wpac_abi,
        )

        total_supply_raw = contract.functions.totalSupply().call()
        # Convert raw value (in nano units) to Amount
        return Amount.from_nano_pac(int(total_supply_raw))

    def get_wpac_balance(self, contract_address: str, address: str) -> Amount:
        """
        Get WPAC ERC-20 token balance for a specific address.

        Args:
            contract_address: Address of the WPAC contract
            address: Address to query balance for

        Returns:
            Balance as Amount

        Raises:
            ConnectionError: If unable to connect to RPC endpoint
            Exception: If contract call fails
        """
        # Minimal ABI - only balanceOf function
        wpac_abi = [
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function",
            },
        ]

        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=wpac_abi,
        )

        balance_raw = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
        # Convert raw value (in nano units) to Amount
        return Amount.from_nano_pac(int(balance_raw))

    def get_wpac_info(self, contract_address: str) -> Dict[str, Any]:
        """Get WPAC contract information."""
        # This is a complex function, we'll keep it as a method but use self.w3
        # For now, let's create a wrapper that calls the existing function
        return get_wpac_info(contract_address, self.rpc_endpoint)

    def send_transaction(self, raw_transaction_hex: str) -> Dict[str, Any]:
        """Send a signed transaction to the blockchain."""
        return send_transaction(raw_transaction_hex, self.rpc_endpoint)

    def dump_all_bridges(self, contract_address: str) -> List[Dict[str, Any]]:
        """Dump all bridges from index 0 to counter-1."""
        return dump_all_bridges(contract_address, self.rpc_endpoint)


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


# Backward compatibility functions that use EVMClient
def generate_credentials(network: str) -> Credentials:
    """Generate EVM credentials (secp256k1)."""
    # Network doesn't affect credential generation, but we need it for the Credentials object
    # Use testnet as default environment since it doesn't matter for key generation
    client = EVMClient(network, "testnet")
    return client.generate_credentials()


def derive_address_from_private_key(privkey_str: str) -> Dict[str, str]:
    """Derive address from EVM private key."""
    # Network doesn't affect address derivation, use ethereum as default
    client = EVMClient("ethereum", "testnet")
    return client.derive_address_from_private_key(privkey_str)


def _get_native_token_symbol(chain_id: int) -> str:
    """Get native token symbol based on chain ID."""
    chain_symbol_map = {
        1: "ETH",      # Ethereum Mainnet
        11155111: "ETH",  # Sepolia
        56: "BNB",     # BNB Smart Chain (BSC) Mainnet
        97: "BNB",     # BNB Smart Chain (BSC) Testnet
        137: "MATIC",  # Polygon Mainnet
        80002: "MATIC",  # Polygon Amoy
        8453: "ETH",   # Base Mainnet
        84532: "ETH",  # Base Sepolia
    }
    return chain_symbol_map.get(chain_id, "ETH")


def get_wpac_total_supply(contract_address: str, rpc_endpoint: str) -> Amount:
    """
    Get only the total supply of WPAC contract (lightweight function for faster queries).

    Args:
        contract_address: Address of the WPAC contract
        rpc_endpoint: RPC endpoint URL

    Returns:
        Total supply as Amount

    Raises:
        ConnectionError: If unable to connect to RPC endpoint
        Exception: If contract call fails
    """
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

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

    total_supply_raw = contract.functions.totalSupply().call()
    # Convert raw value (in nano units) to Amount
    return Amount.from_nano_pac(int(total_supply_raw))


def get_wpac_balance(contract_address: str, address: str, rpc_endpoint: str) -> Amount:
    """
    Get WPAC ERC-20 token balance for a specific address.

    Args:
        contract_address: Address of the WPAC contract
        address: Address to query balance for
        rpc_endpoint: RPC endpoint URL

    Returns:
        Balance as Amount

    Raises:
        ConnectionError: If unable to connect to RPC endpoint
        Exception: If contract call fails
    """
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Minimal ABI - only balanceOf function
    wpac_abi = [
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function",
        },
    ]

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=wpac_abi,
    )

    balance_raw = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
    # Convert raw value (in nano units) to Amount
    return Amount.from_nano_pac(int(balance_raw))


def get_wpac_info(contract_address: str, rpc_endpoint: str) -> Dict[str, Any]:
    """Get WPAC contract information."""
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

        # Resolve the implementation (logic) contract behind the proxy
        try:
            slot_value = w3.eth.get_storage_at(
                Web3.to_checksum_address(contract_address),
                EIP1967_IMPLEMENTATION_SLOT,
            )

            if slot_value and any(slot_value[-20:]):
                implementation_hex = "0x" + slot_value[-20:].hex()
                info["implementation_address"] = Web3.to_checksum_address(implementation_hex)
            else:
                info["implementation_address"] = None
        except Exception:
            info["implementation_address"] = None

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
    derivation_path: str,
) -> bytes:
    """
    Sign a transaction using Trezor hardware wallet.

    Args:
        transaction: Unsigned transaction dictionary
        derivation_path: BIP44 derivation path

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


def _connect_web3(rpc_endpoint: str) -> Web3:
    """Return a connected Web3 instance or raise if unreachable."""
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    return w3


def _get_owner_context(
    owner_privkey: Optional[str],
    use_trezor: bool,
    trezor_path: str,
) -> tuple[str, Optional[bytes]]:
    """
    Resolve the signing address and optional private key bytes.

    Returns:
        Tuple of (owner_address, private_key_bytes or None when using Trezor)
    """
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
        return owner_address, None

    if not owner_privkey:
        raise ValueError("Private key is required when not using Trezor")

    clean_privkey = owner_privkey[2:] if owner_privkey.startswith("0x") else owner_privkey

    private_key_bytes = bytes.fromhex(clean_privkey)

    if len(private_key_bytes) != 32:
        raise ValueError("Private key must be 32 bytes (64 hex characters).")

    account = Account.from_key(private_key_bytes)
    return account.address, private_key_bytes


def _build_contract_transaction(
    w3: Web3,
    contract_address: str,
    owner_address: str,
    contract_abi: List[Dict[str, Any]],
    function_builder: Callable[[Any], Any],
) -> Dict[str, Any]:
    """Build a contract transaction after estimating gas."""
    try:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=contract_abi,
        )

        contract_function = function_builder(contract)

        gas_estimate = contract_function.estimate_gas({"from": owner_address})

        chain_id = w3.eth.chain_id
        utils.info(f"Chain ID: {chain_id}")

        tx_params = {
            "from": owner_address,
            "nonce": w3.eth.get_transaction_count(owner_address),
            "gas": int(gas_estimate * 1.2),
            "chainId": chain_id,
        }

        current_gas_price = w3.eth.gas_price
        tx_params["gasPrice"] = current_gas_price
        utils.info("Using legacy transaction")
        utils.info(f"  Gas Price: {current_gas_price}")

        transaction = contract_function.build_transaction(tx_params)
        return transaction
    except Exception as e:
        raise ValueError(f"Failed to build transaction: {e}")


def _sign_transaction_payload(
    transaction: Dict[str, Any],
    w3: Web3,
    contract_address: str,
    use_trezor: bool,
    trezor_path: str,
    private_key_bytes: Optional[bytes],
) -> Dict[str, str]:
    """Sign a transaction dictionary and return a unified response payload."""
    try:
        if use_trezor:
            signed_bytes = sign_transaction_with_trezor(transaction, trezor_path)
            tx_hash = Web3.keccak(signed_bytes).hex()
            raw_transaction = signed_bytes.hex()
        else:
            if private_key_bytes is None:
                raise ValueError("Private key bytes are required when not using Trezor")
            signed_txn = w3.eth.account.sign_transaction(transaction, private_key_bytes)
            raw_transaction = signed_txn.raw_transaction.hex()
            tx_hash = signed_txn.hash.hex()

        return {
            "contract_address": contract_address,
            "raw_transaction": raw_transaction,
            "transaction_hash": tx_hash,
        }
    except Exception as e:
        raise ValueError(f"Failed to sign transaction: {e}")


def _create_admin_transaction(
    contract_address: str,
    rpc_endpoint: str,
    owner_privkey: Optional[str],
    use_trezor: bool,
    trezor_path: str,
    contract_abi: List[Dict[str, Any]],
    function_builder: Callable[[Any], Any],
) -> Dict[str, Any]:
    """Shared flow for admin transactions that mutate WPAC contract roles."""
    w3 = _connect_web3(rpc_endpoint)
    owner_address, private_key_bytes = _get_owner_context(owner_privkey, use_trezor, trezor_path)
    transaction = _build_contract_transaction(
        w3,
        contract_address,
        owner_address,
        contract_abi,
        function_builder,
    )
    return _sign_transaction_payload(transaction, w3, contract_address, use_trezor, trezor_path, private_key_bytes)


def create_set_minter_transaction(
    contract_address: str,
    new_minter: str,
    owner_privkey: Optional[str] = None,
    rpc_endpoint: str = "",
    use_trezor: bool = False,
    trezor_path: str = "",
) -> Dict[str, Any]:
    """Create and sign a transaction to set the minter address."""
    wpac_abi = [
        {
            "constant": False,
            "inputs": [{"name": "_minterAddress", "type": "address"}],
            "name": "setMinter",
            "outputs": [],
            "type": "function",
        },
    ]

    minter_address = Web3.to_checksum_address(new_minter)

    return _create_admin_transaction(
        contract_address=contract_address,
        rpc_endpoint=rpc_endpoint,
        owner_privkey=owner_privkey,
        use_trezor=use_trezor,
        trezor_path=trezor_path,
        contract_abi=wpac_abi,
        function_builder=lambda contract: contract.functions.setMinter(minter_address),
    )


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
        raw_tx_bytes = bytes.fromhex(raw_transaction_hex)
        if len(raw_tx_bytes) == 0:
            raise ValueError("Empty transaction data")

        # Try to decode and validate the transaction before sending (if supported)
        try:
            if hasattr(w3.eth, 'decode_transaction'):
                decoded_tx = w3.eth.decode_transaction(raw_tx_bytes)
                utils.info("Transaction decoded successfully:")
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
    trezor_path: str = "",
) -> Dict[str, Any]:
    """Create and sign a transaction to set the fee collector address."""
    wpac_abi = [
        {
            "constant": False,
            "inputs": [{"name": "_feeCollectorAddress", "type": "address"}],
            "name": "setFeeCollector",
            "outputs": [],
            "type": "function",
        },
    ]

    collector_address = Web3.to_checksum_address(new_fee_collector)

    return _create_admin_transaction(
        contract_address=contract_address,
        rpc_endpoint=rpc_endpoint,
        owner_privkey=owner_privkey,
        use_trezor=use_trezor,
        trezor_path=trezor_path,
        contract_abi=wpac_abi,
        function_builder=lambda contract: contract.functions.setFeeCollector(collector_address),
    )


def create_transfer_ownership_transaction(
    contract_address: str,
    new_owner: str,
    owner_privkey: Optional[str] = None,
    rpc_endpoint: str = "",
    use_trezor: bool = False,
    trezor_path: str = "",
) -> Dict[str, Any]:
    """Create and sign a transaction to transfer ownership."""
    wpac_abi = [
        {
            "constant": False,
            "inputs": [{"name": "newOwner", "type": "address"}],
            "name": "transferOwnership",
            "outputs": [],
            "type": "function",
        },
    ]

    new_owner_address = Web3.to_checksum_address(new_owner)

    return _create_admin_transaction(
        contract_address=contract_address,
        rpc_endpoint=rpc_endpoint,
        owner_privkey=owner_privkey,
        use_trezor=use_trezor,
        trezor_path=trezor_path,
        contract_abi=wpac_abi,
        function_builder=lambda contract: contract.functions.transferOwnership(new_owner_address),
    )


def create_upgrade_to_transaction(
    contract_address: str,
    new_implementation: str,
    owner_privkey: Optional[str] = None,
    rpc_endpoint: str = "",
    use_trezor: bool = False,
    trezor_path: str = "",
) -> Dict[str, Any]:
    """Create and sign a transaction to upgrade the proxy implementation."""
    proxy_abi = [
        {
            "constant": False,
            "inputs": [{"name": "newImplementation", "type": "address"}],
            "name": "upgradeTo",
            "outputs": [],
            "type": "function",
        },
    ]

    implementation_address = Web3.to_checksum_address(new_implementation)

    return _create_admin_transaction(
        contract_address=contract_address,
        rpc_endpoint=rpc_endpoint,
        owner_privkey=owner_privkey,
        use_trezor=use_trezor,
        trezor_path=trezor_path,
        contract_abi=proxy_abi,
        function_builder=lambda contract: contract.functions.upgradeTo(implementation_address),
    )


def get_bridge_counter(contract_address: str, rpc_endpoint: str) -> int:
    """
    Get the counter value from the bridge contract.

    Args:
        contract_address: Address of the bridge contract
        rpc_endpoint: RPC endpoint URL

    Returns:
        Counter value as integer
    """
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Bridge contract ABI for counter property/function
    bridge_abi = [
        {
            "constant": True,
            "inputs": [],
            "name": "counter",
            "outputs": [{"name": "", "type": "uint256"}],
            "type": "function",
        },
    ]

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=bridge_abi,
    )

    try:
        counter = contract.functions.counter().call()
        return counter
    except Exception as e:
        raise ValueError(f"Failed to get counter: {e}")


def get_bridge_data(contract_address: str, rpc_endpoint: str, index: int) -> Dict[str, Any]:
    """
    Get bridge data for a specific index.

    Args:
        contract_address: Address of the bridge contract
        rpc_endpoint: RPC endpoint URL
        index: Bridge index (0-based)

    Returns:
        Dictionary with bridge data: sender, amount, destinationAddress, fee
    """
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint))

    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    # Bridge contract ABI for bridged function
    bridge_abi = [
        {
            "constant": True,
            "inputs": [{"name": "", "type": "uint256"}],
            "name": "bridged",
            "outputs": [
                {"name": "sender", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "destinationAddress", "type": "string"},
                {"name": "fee", "type": "uint256"},
            ],
            "type": "function",
        },
    ]

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=bridge_abi,
    )

    try:
        result = contract.functions.bridged(index).call()
        return {
            "sender": result[0],
            "amount": result[1],
            "destinationAddress": result[2],
            "fee": result[3],
        }
    except Exception as e:
        raise ValueError(f"Failed to get bridge data for index {index}: {e}")


def dump_all_bridges(contract_address: str, rpc_endpoint: str) -> List[Dict[str, Any]]:
    """
    Dump all bridges from index 0 to counter-1.

    Args:
        contract_address: Address of the bridge contract
        rpc_endpoint: RPC endpoint URL

    Returns:
        List of bridge data dictionaries
    """
    counter = get_bridge_counter(contract_address, rpc_endpoint)
    bridges = []

    for i in range(counter):
        try:
            bridge_data = get_bridge_data(contract_address, rpc_endpoint, i)
            bridge_data["index"] = i
            bridges.append(bridge_data)
        except Exception as e:
            # Continue even if one bridge fails
            bridges.append({"index": i, "error": str(e)})

    return bridges

