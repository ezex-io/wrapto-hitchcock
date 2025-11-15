"""Pactus blockchain operations using Pactus-SDK."""

from typing import Dict, Tuple
import grpc
from pactus.crypto.crypto import CryptoConfig
from pactus.crypto.ed25519.private_key import PrivateKey as EdPrivateKey
from pactus.transaction.transaction import Transaction
from pactus.amount import Amount
from pactus.crypto.address import Address
from pactus_grpc.blockchain_pb2_grpc import BlockchainStub
from pactus_grpc.blockchain_pb2 import GetAccountRequest

from hitchcock.models import Credentials


def setup_hrp(is_testnet: bool) -> None:
    """Set up HRP for Pactus network using Pactus SDK."""
    if is_testnet:
        CryptoConfig.use_testnet()
    else:
        # Set mainnet HRP values
        CryptoConfig.ADDRESS_HRP = "pc"
        CryptoConfig.PUBLIC_KEY_HRP = "public"
        CryptoConfig.PRIVATE_KEY_HRP = "secret"


def generate_credentials(environment: str) -> Credentials:
    """Generate Pactus credentials (Ed25519)."""
    is_testnet = environment.lower().startswith("test")
    setup_hrp(is_testnet)

    private_key = EdPrivateKey.random()
    public_key = private_key.public_key()
    address = public_key.account_address()

    return Credentials(
        network="Pactus",
        environment=environment,
        variant="Ed25519",
        private_key=private_key.string(),
        public_key=public_key.string(),
        address=address.string(),
    )


def derive_address_from_private_key(privkey_str: str, is_testnet: bool) -> Dict[str, str]:
    """Derive address from Pactus private key."""
    setup_hrp(is_testnet)

    private_key = EdPrivateKey.from_string(privkey_str)
    public_key = private_key.public_key()
    address = public_key.account_address()

    return {
        "private_key": private_key.string(),
        "public_key": public_key.string(),
        "address": address.string(),
    }


def create_and_sign_wrap_tx(
    sender_privkey_str: str,
    wrapto_addr_str: str,
    dest_addr: str,
    dest_network: str,
    amount_pac: float,
    fee_pac: float,
    is_testnet: bool,
) -> Tuple[bytes, str]:
    """Create and sign a wrap transaction (PAC->wPAC)."""
    setup_hrp(is_testnet)

    # Parse private key
    try:
        private_key = EdPrivateKey.from_string(sender_privkey_str)
    except ValueError:
        raise ValueError("Invalid Pactus private key format. Must be Ed25519.")

    # Derive sender address
    public_key = private_key.public_key()
    sender_addr = public_key.account_address()
    sender_addr_str = sender_addr.string()

    # Parse Wrapto address
    wrapto_addr = Address.from_string(wrapto_addr_str)

    # Create amounts
    amount = Amount.from_pac(amount_pac)
    fee = Amount.from_pac(fee_pac)

    # Create memo: <DEST_ADDR>@<NETWORK>
    memo = f"{dest_addr}@{dest_network}"

    # Create transaction
    tx = Transaction.create_transfer_tx(
        lock_time=0,
        sender=sender_addr,
        receiver=wrapto_addr,
        amount=amount,
        fee=fee,
        memo=memo,
    )

    # Sign transaction
    signed_bytes = tx.sign(private_key)

    return signed_bytes, sender_addr_str


def get_account_balance(address: str, is_testnet: bool) -> Amount:
    """Get account balance for a Pactus address using Pactus SDK gRPC.

    Returns:
        Amount: The account balance as an Amount object
    """
    if is_testnet:
        rpc_endpoint = "testnet1.pactus.org:50052"
    else:
        rpc_endpoint = "bootstrap1.pactus.org:50051"

    # Create gRPC channel (insecure channel for these ports)
    channel = grpc.insecure_channel(rpc_endpoint)

    try:
        # Create blockchain stub
        blockchain_stub = BlockchainStub(channel)

        # Get account info
        response = blockchain_stub.GetAccount(GetAccountRequest(address=address))

        # Extract account data (response has an 'account' field)
        account = response.account if hasattr(response, 'account') else None

        if account:
            balance_nano = account.balance if hasattr(account, 'balance') else 0
            return Amount.from_nano_pac(int(balance_nano))
        else:
            return Amount(0)
    except grpc.RpcError as e:
        # Handle gRPC errors - print error and return zero balance
        from hitchcock import utils
        utils.error(f"gRPC error fetching balance for {address}: {e.code()} - {e.details()}")
        return Amount(0)
    except Exception as e:
        # Handle other errors - print error and return zero balance
        from hitchcock import utils
        utils.error(f"Error fetching account balance for {address}: {str(e)}")
        return Amount(0)
    finally:
        channel.close()

