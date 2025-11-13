#!/usr/bin/env python3

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple


class HitchcockCLI:
    def __init__(self) -> None:
        self.actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Generate private key", self.generate_private_key),
            "2": ("Get Address from Private key", self.get_address_from_private_key),
            "3": ("Create and Sign Wrap Transaction (PAC->WAPC)", self.create_wrap_transaction),
            "0": ("Exit", self.exit_program),
        }
        self.should_exit = False

    def run(self) -> None:
        self.clear_screen()
        self.print_banner()

        while not self.should_exit:
            try:
                choice = self.prompt_main_menu()
                action = self.actions.get(choice)
                if action:
                    label, callback = action
                    self.section_header(label)
                    try:
                        callback()
                    except KeyboardInterrupt:
                        self.section_footer("Cancelled. Returning to main menu.")
                    except EOFError:
                        self.section_footer("Received EOF. Exiting Hitchcock.")
                        self.should_exit = True
                else:
                    self.warn(f"Unknown choice: {choice!r}")
            except KeyboardInterrupt:
                self.section_footer("Interrupted. Returning to main menu.")
            except EOFError:
                print("\nGoodbye!")
                break

    def prompt_main_menu(self) -> str:
        print()
        print("=== Hitchcock Main Menu ===")
        for key, (label, _) in self.actions.items():
            print(f"{key}. {label}")
        print()
        return input("Choose an option: ").strip()

    def generate_private_key(self) -> None:
        network = self.prompt_choice(
            "Select a target network",
            [
                "Pactus",
                "Ethereum",
                "Polygon",
                "Binance Smart Chain",
                "Base",
            ],
        )

        if network == "Pactus":
            # First question: Testnet or Mainnet
            environment = self.prompt_choice(
                "Select network environment",
                ["Mainnet", "Testnet"],
            )
            # Pactus always uses Ed25519
            credentials = self._generate_pactus_credentials(environment)
        else:
            credentials = self._generate_evm_credentials(network)

        self.print_credentials(credentials)
        input("\nPress Enter to return to the main menu...")

    def get_address_from_private_key(self) -> None:
        network = self.prompt_choice(
            "Select network",
            [
                "Pactus",
                "Ethereum",
                "Polygon",
                "Binance Smart Chain",
                "Base",
            ],
        )

        if network == "Pactus":
            # First question: Testnet or Mainnet
            environment = self.prompt_choice(
                "Select network environment",
                ["Mainnet", "Testnet"],
            )
            is_testnet = environment.lower().startswith("test")
        else:
            environment = None
            is_testnet = False

        # Get private key
        print()
        if network == "Pactus":
            privkey_prompt = "Enter Pactus private key: "
        else:
            privkey_prompt = f"Enter {network} private key (hex format, with or without 0x): "

        privkey_str = input(privkey_prompt).strip()
        if not privkey_str:
            self.warn("Private key is required.")
            return

        try:
            address_info = self._derive_address_from_private_key(
                network, privkey_str, is_testnet
            )
            self.print_address_info(address_info, network, environment)
        except Exception as e:
            self.warn(f"Failed to derive address: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def create_wrap_transaction(self) -> None:
        # Wrapto addresses
        WRAPTO_MAINNET = "pc1zl5uyhw5xw9rud43yp0kuhdewxy5vgdmx854mta"
        WRAPTO_TESTNET = "tpc1zr3yxv4a9asewmrr77a4jxmkeqedaggdvgytt77"

        # First question: Testnet or Mainnet
        environment = self.prompt_choice(
            "Select network environment",
            ["Mainnet", "Testnet"],
        )
        is_testnet = environment.lower().startswith("test")
        wrapto_address = WRAPTO_TESTNET if is_testnet else WRAPTO_MAINNET

        # Get sender private key
        print()
        sender_privkey_str = input("Enter Pactus sender private key: ").strip()
        if not sender_privkey_str:
            self.warn("Sender private key is required.")
            return

        # Get destination network
        dest_network = self.prompt_choice(
            "Select destination network",
            [
                "Ethereum",
                "Polygon",
                "Binance Smart Chain",
                "Base",
            ],
        )

        # Get destination address
        print()
        dest_address = input("Enter destination address: ").strip()
        if not dest_address:
            self.warn("Destination address is required.")
            return

        # Get amount (optional, default to 1 PAC)
        print()
        amount_str = input("Enter amount in PAC (default: 1.0): ").strip()
        if not amount_str:
            amount_pac = 1.0
        else:
            try:
                amount_pac = float(amount_str)
            except ValueError:
                self.warn(f"Invalid amount: {amount_str}. Using default 1.0 PAC.")
                amount_pac = 1.0

        # Get fee (optional, default to 0.001 PAC)
        print()
        fee_str = input("Enter fee in PAC (default: 0.001): ").strip()
        if not fee_str:
            fee_pac = 0.001
        else:
            try:
                fee_pac = float(fee_str)
            except ValueError:
                self.warn(f"Invalid fee: {fee_str}. Using default 0.001 PAC.")
                fee_pac = 0.001

        # Create and sign transaction
        try:
            signed_tx, sender_addr = self._create_and_sign_wrap_tx(
                sender_privkey_str,
                wrapto_address,
                dest_address,
                dest_network,
                amount_pac,
                fee_pac,
                is_testnet,
            )
            self.print_signed_transaction(signed_tx, environment, dest_network, sender_addr)
        except Exception as e:
            self.warn(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def _create_and_sign_wrap_tx(
        self,
        sender_privkey_str: str,
        wrapto_addr_str: str,
        dest_addr: str,
        dest_network: str,
        amount_pac: float,
        fee_pac: float,
        is_testnet: bool,
    ) -> Tuple[bytes, str]:
        from pactus.crypto import hrp as pactus_hrp
        from pactus.transaction.transaction import Transaction
        from pactus.amount import Amount
        from pactus.crypto.address import Address

        # Set HRP based on network
        original_hrp = (
            pactus_hrp.HRP.ADDRESS_HRP,
            pactus_hrp.HRP.PUBLIC_KEY_HRP,
            pactus_hrp.HRP.PRIVATE_KEY_HRP,
        )

        try:
            if is_testnet:
                pactus_hrp.HRP.use_testnet()
            else:
                pactus_hrp.HRP.ADDRESS_HRP = "pc"
                pactus_hrp.HRP.PUBLIC_KEY_HRP = "public"
                pactus_hrp.HRP.PRIVATE_KEY_HRP = "secret"

            # Parse private key (Pactus always uses Ed25519)
            from pactus.crypto.ed25519.private_key import PrivateKey as EdPrivateKey
            try:
                private_key = EdPrivateKey.from_string(sender_privkey_str)
            except ValueError:
                raise ValueError("Invalid Pactus private key format. Must be Ed25519.")

            # Derive sender address from private key
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

            # Create transaction (lock_time=0 for immediate execution)
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
        finally:
            (
                pactus_hrp.HRP.ADDRESS_HRP,
                pactus_hrp.HRP.PUBLIC_KEY_HRP,
                pactus_hrp.HRP.PRIVATE_KEY_HRP,
            ) = original_hrp

    def print_signed_transaction(self, signed_tx: bytes, environment: str, dest_network: str, sender_addr: str) -> None:
        import base64

        print()
        print(f"[Wrap Transaction] {environment}")
        print(f"Sender address: {sender_addr}")
        print(f"Destination: {dest_network}")
        print(f"Signed transaction (hex): {signed_tx.hex()}")
        print(f"Signed transaction (base64): {base64.b64encode(signed_tx).decode('ascii')}")

    def exit_program(self) -> None:
        print("\nExiting Hitchcock. Goodbye!")
        self.should_exit = True

    def prompt_choice(self, title: str, options: List[str]) -> str:
        options_map = {str(index): option for index, option in enumerate(options, start=1)}
        reverse_map = {option.lower(): option for option in options}

        while True:
            print()
            print(title)
            for idx, option in options_map.items():
                print(f"{idx}. {option}")
            print()
            choice = input("Choose an option: ").strip()
            if not choice:
                continue
            if choice in options_map:
                return options_map[choice]
            normalized = choice.lower()
            if normalized in reverse_map:
                return reverse_map[normalized]
            self.warn(f"Invalid choice: {choice!r}. Please try again.")

    def _generate_pactus_credentials(self, environment: str) -> "Credentials":
        from pactus.crypto import hrp as pactus_hrp

        original_hrp = (
            pactus_hrp.HRP.ADDRESS_HRP,
            pactus_hrp.HRP.PUBLIC_KEY_HRP,
            pactus_hrp.HRP.PRIVATE_KEY_HRP,
        )

        try:
            if environment.lower().startswith("test"):
                pactus_hrp.HRP.use_testnet()
            else:
                pactus_hrp.HRP.ADDRESS_HRP = "pc"
                pactus_hrp.HRP.PUBLIC_KEY_HRP = "public"
                pactus_hrp.HRP.PRIVATE_KEY_HRP = "secret"

            # Pactus always uses Ed25519
            from pactus.crypto.ed25519.private_key import PrivateKey as EdPrivateKey

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
        finally:
            (
                pactus_hrp.HRP.ADDRESS_HRP,
                pactus_hrp.HRP.PUBLIC_KEY_HRP,
                pactus_hrp.HRP.PRIVATE_KEY_HRP,
            ) = original_hrp

    def _generate_evm_credentials(self, network: str) -> "Credentials":
        from eth_account import Account

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

    def print_credentials(self, credentials: "Credentials") -> None:
        print()
        label = credentials.network
        if credentials.environment:
            label = f"{label} ({credentials.environment})"
        print(f"[{label}] Key Material")
        if credentials.variant:
            print(f"Type: {credentials.variant}")
        print(f"Private key: {credentials.private_key}")
        print(f"Public key:  {credentials.public_key}")
        print(f"Address:     {credentials.address}")

    @staticmethod
    def section_header(title: str) -> None:
        print()
        print(f"--- {title} ---")

    @staticmethod
    def section_footer(message: str) -> None:
        print()
        print(message)

    @staticmethod
    def warn(message: str) -> None:
        print(f"[warn] {message}")

    @staticmethod
    def print_banner() -> None:
        banner = r""" _     _            _                      _
| |   (_)  _       | |                    | |
| |__  _ _| |_ ____| |__   ____ ___   ___ | |  _
|  _ \| (_   _) ___)  _ \ / ___) _ \ / _ \| |_/ )
| | | | | | |( (___| | | ( (__| |_| | |_| |  _ (
|_| |_|_|  \__)____)_| |_|\____)___/ \___/|_| \_)
"""
        print(banner)
        print("Welcome to Hitchcock - the Wrapto troubleshooting toolkit.")
        print("⚠️  Hitchcock is a testing toolkit. Do not use the generated keys or accounts in production.")

    def _derive_address_from_private_key(
        self, network: str, privkey_str: str, is_testnet: bool
    ) -> Dict[str, str]:
        if network == "Pactus":
            from pactus.crypto import hrp as pactus_hrp
            from pactus.crypto.ed25519.private_key import PrivateKey as EdPrivateKey

            original_hrp = (
                pactus_hrp.HRP.ADDRESS_HRP,
                pactus_hrp.HRP.PUBLIC_KEY_HRP,
                pactus_hrp.HRP.PRIVATE_KEY_HRP,
            )

            try:
                if is_testnet:
                    pactus_hrp.HRP.use_testnet()
                else:
                    pactus_hrp.HRP.ADDRESS_HRP = "pc"
                    pactus_hrp.HRP.PUBLIC_KEY_HRP = "public"
                    pactus_hrp.HRP.PRIVATE_KEY_HRP = "secret"

                private_key = EdPrivateKey.from_string(privkey_str)
                public_key = private_key.public_key()
                address = public_key.account_address()

                return {
                    "private_key": private_key.string(),
                    "public_key": public_key.string(),
                    "address": address.string(),
                }
            finally:
                (
                    pactus_hrp.HRP.ADDRESS_HRP,
                    pactus_hrp.HRP.PUBLIC_KEY_HRP,
                    pactus_hrp.HRP.PRIVATE_KEY_HRP,
                ) = original_hrp
        else:
            # EVM networks
            from eth_account import Account
            from eth_keys import keys

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

    def print_address_info(self, address_info: Dict[str, str], network: str, environment: str | None) -> None:
        print()
        label = network
        if environment:
            label = f"{label} ({environment})"
        print(f"[{label}] Address Information")
        print(f"Private key: {address_info['private_key']}")
        print(f"Public key:  {address_info['public_key']}")
        print(f"Address:     {address_info['address']}")

    @staticmethod
    def clear_screen() -> None:
        print("\033c", end="")


@dataclass
class Credentials:
    network: str
    variant: str
    private_key: str
    public_key: str
    address: str
    environment: str | None = None


def main() -> int:
    cli = HitchcockCLI()
    cli.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())


