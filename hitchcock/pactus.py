"""Pactus blockchain operations using Pactus-SDK."""

from typing import Dict, Tuple
import grpc
from pactus.crypto import HRP, Address
from pactus.crypto.ed25519 import PrivateKey as EdPrivateKey
from pactus.transaction import Transaction
from pactus.types import Amount
from pactus_grpc.blockchain_pb2_grpc import BlockchainStub
from pactus_grpc.blockchain_pb2 import GetAccountRequest, GetBlockchainInfoRequest
from pactus_grpc.transaction_pb2_grpc import TransactionStub
from pactus_grpc.transaction_pb2 import BroadcastTransactionRequest

from hitchcock.models import Credentials


class PactusClient:
    """Pactus blockchain client that manages RPC connections."""

    def __init__(self, environment: str = "testnet"):
        """
        Initialize Pactus client with environment.

        Args:
            environment: "testnet" or "mainnet"
        """
        self.environment = environment.lower()
        self.is_testnet = self.environment == "testnet"

        # Set RPC endpoint based on environment
        if self.is_testnet:
            self.rpc_endpoint = "testnet1.pactus.org:50052"
        else:
            self.rpc_endpoint = "bootstrap1.pactus.org:50051"

        # Setup HRP for the network
        self._setup_hrp()

    def _setup_hrp(self) -> None:
        """Set up HRP for Pactus network using Pactus SDK."""
        if self.is_testnet:
            HRP.use_testnet()
        else:
            HRP.use_mainnet()

    def generate_credentials(self) -> Credentials:
        """Generate Pactus credentials (Ed25519)."""
        self._setup_hrp()

        private_key = EdPrivateKey.random()
        public_key = private_key.public_key()
        address = public_key.account_address()

        return Credentials(
            network="Pactus",
            environment=self.environment,
            variant="Ed25519",
            private_key=private_key.string(),
            public_key=public_key.string(),
            address=address.string(),
        )

    def derive_address_from_private_key(self, privkey_str: str) -> Dict[str, str]:
        """Derive address from Pactus private key."""
        self._setup_hrp()

        private_key = EdPrivateKey.from_string(privkey_str)
        public_key = private_key.public_key()
        address = public_key.account_address()

        return {
            "private_key": private_key.string(),
            "public_key": public_key.string(),
            "address": address.string(),
        }

    def create_and_sign_wrap_tx(
        self,
        sender_privkey_str: str,
        wrapto_addr_str: str,
        dest_addr: str,
        dest_network: str,
        amount: Amount,
        fee: Amount,
        memo: str | None = None,
    ) -> Tuple[bytes, str]:
        """Create and sign a wrap transaction (PAC->WPAC)."""
        self._setup_hrp()

        # Parse private key
        try:
            private_key = EdPrivateKey.from_string(sender_privkey_str)
        except Exception as e:
            raise ValueError(f"Invalid Pactus private key format: {e}")

        # Derive sender address
        public_key = private_key.public_key()
        sender_addr = public_key.account_address()
        sender_addr_str = sender_addr.string()

        # Parse Wrapto address
        wrapto_addr = Address.from_string(wrapto_addr_str)

        # Create memo: <DEST_ADDR>@<NETWORK> (default if not provided)
        if memo is None:
            memo = f"{dest_addr}@{dest_network}"

        # Get current block height for lock_time
        lock_time = self.get_blockchain_height()

        # Create transaction
        tx = Transaction.create_transfer_tx(
            lock_time=lock_time,
            sender=sender_addr,
            receiver=wrapto_addr,
            amount=amount,
            fee=fee,
            memo=memo,
        )

        # Sign transaction
        signed_bytes = tx.sign(private_key)

        return signed_bytes, sender_addr_str

    def get_account_balance(self, address: str) -> Amount:
        """
        Get account balance for a Pactus address using Pactus SDK gRPC.

        Args:
            address: Pactus address string

        Returns:
            Amount: The account balance as an Amount object
        """
        # Create gRPC channel (insecure channel for these ports)
        channel = grpc.insecure_channel(self.rpc_endpoint)

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

    def get_blockchain_height(self) -> int:
        """
        Get the current blockchain height (last block height).

        Returns:
            int: The current block height
        """
        # Create gRPC channel (insecure channel for these ports)
        channel = grpc.insecure_channel(self.rpc_endpoint)

        try:
            # Create blockchain stub
            blockchain_stub = BlockchainStub(channel)

            # Get blockchain info
            response = blockchain_stub.GetBlockchainInfo(GetBlockchainInfoRequest())
            return int(response.last_block_height)

        except grpc.RpcError as e:
            raise ValueError(f"gRPC error fetching blockchain height: {e.code()} - {e.details()}")
        except Exception as e:
            raise ValueError(f"Error fetching blockchain height: {str(e)}")
        finally:
            channel.close()

    def broadcast_transaction(self, signed_tx_bytes: bytes) -> str:
        """
        Broadcast a signed Pactus transaction to the network.

        Args:
            signed_tx_bytes: Signed transaction bytes

        Returns:
            Transaction ID as string
        """
        # Create gRPC channel (insecure channel for these ports)
        channel = grpc.insecure_channel(self.rpc_endpoint)

        try:
            # Create transaction stub
            transaction_stub = TransactionStub(channel)

            # Convert bytes to hex string for protobuf
            signed_tx_hex = signed_tx_bytes.hex()

            # Broadcast transaction - protobuf expects hex string
            request = BroadcastTransactionRequest(signed_raw_transaction=signed_tx_hex)
            response = transaction_stub.BroadcastTransaction(request)

            return str(response.id)

        except grpc.RpcError as e:
            error_msg = f"gRPC error broadcasting transaction: {e.code()} - {e.details()}"
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Error broadcasting transaction: {str(e)}"
            raise ValueError(error_msg)
        finally:
            channel.close()


# Backward compatibility functions that use PactusClient
def setup_hrp(is_testnet: bool) -> None:
    """Set up HRP for Pactus network using Pactus SDK."""
    environment = "testnet" if is_testnet else "mainnet"
    PactusClient(environment)
    # HRP is set up in __init__, just need to create client


def generate_credentials(environment: str) -> Credentials:
    """Generate Pactus credentials (Ed25519)."""
    client = PactusClient(environment)
    return client.generate_credentials()


def derive_address_from_private_key(privkey_str: str, is_testnet: bool) -> Dict[str, str]:
    """Derive address from Pactus private key."""
    environment = "testnet" if is_testnet else "mainnet"
    client = PactusClient(environment)
    return client.derive_address_from_private_key(privkey_str)


def create_and_sign_wrap_tx(
    sender_privkey_str: str,
    wrapto_addr_str: str,
    dest_addr: str,
    dest_network: str,
    amount: Amount,
    fee: Amount,
    is_testnet: bool,
    memo: str | None = None,
) -> Tuple[bytes, str]:
    """Create and sign a wrap transaction (PAC->WPAC)."""
    environment = "testnet" if is_testnet else "mainnet"
    client = PactusClient(environment)
    return client.create_and_sign_wrap_tx(
        sender_privkey_str,
        wrapto_addr_str,
        dest_addr,
        dest_network,
        amount,
        fee,
        memo,
    )


def get_account_balance(address: str, is_testnet: bool) -> Amount:
    """Get account balance for a Pactus address using Pactus SDK gRPC.

    Args:
        address: Pactus address string
        is_testnet: Whether to use testnet

    Returns:
        Amount: The account balance as an Amount object
    """
    environment = "testnet" if is_testnet else "mainnet"
    client = PactusClient(environment)
    return client.get_account_balance(address)


def broadcast_transaction(signed_tx_bytes: bytes, is_testnet: bool) -> str:
    """
    Broadcast a signed Pactus transaction to the network.

    Args:
        signed_tx_bytes: Signed transaction bytes
        is_testnet: Whether to use testnet

    Returns:
        Transaction ID as string
    """
    environment = "testnet" if is_testnet else "mainnet"
    client = PactusClient(environment)
    return client.broadcast_transaction(signed_tx_bytes)

