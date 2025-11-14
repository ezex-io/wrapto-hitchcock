"""Main CLI interface for Hitchcock."""

from __future__ import annotations

import base64
import sys
from typing import Any, Callable, Dict, List, Tuple

import config
from hitchcock import evm, models, pactus, utils


class HitchcockCLI:
    """Main CLI class for Hitchcock."""

    def __init__(self) -> None:
        self.actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Generate private key", self.generate_private_key),
            "2": ("Get Address from Private key", self.get_address_from_private_key),
            "3": ("Create and Sign Wrap Transaction (PAC->wPAC)", self.create_wrap_transaction),
            "4": ("Show PAC Info", self.show_pac_info),
            "5": ("Show wPAC Info", self.show_wpac_info),
            "6": ("Create and Sign Unwrap Transaction (wPAC->PAC)", self.create_unwrap_transaction),
            "7": ("Administrator Menu", self.administrator_menu),
            "0": ("Exit", self.exit_program),
        }
        self.should_exit = False

    def run(self) -> None:
        """Run the CLI main loop."""
        utils.clear_screen()
        utils.print_banner()

        while not self.should_exit:
            try:
                choice = self.prompt_main_menu()
                action = self.actions.get(choice)
                if action:
                    label, callback = action
                    utils.section_header(label)
                    try:
                        callback()
                    except KeyboardInterrupt:
                        utils.section_footer("Cancelled. Returning to main menu.")
                    except EOFError:
                        utils.section_footer("Received EOF. Exiting Hitchcock.")
                        self.should_exit = True
                else:
                    utils.warn(f"Unknown choice: {choice!r}")
            except KeyboardInterrupt:
                utils.section_footer("Interrupted. Returning to main menu.")
            except EOFError:
                print("\nGoodbye!")
                break

    def prompt_main_menu(self) -> str:
        """Prompt for main menu choice."""
        print()
        print("=== Hitchcock Main Menu ===")
        for key, (label, _) in self.actions.items():
            print(f"{key}. {label}")
        print()
        return input("Choose an option: ").strip()

    def prompt_choice(self, title: str, options: List[str]) -> str:
        """Prompt user to choose from a list of options."""
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
            utils.warn(f"Invalid choice: {choice!r}. Please try again.")

    def generate_private_key(self) -> None:
        """Generate private key for selected network."""
        network = self.prompt_choice(
            "Select a target network",
            ["Pactus", "Ethereum", "Polygon", "Binance Smart Chain", "Base"],
        )

        if network == "Pactus":
            environment = self.prompt_choice(
                "Select network environment",
                ["Mainnet", "Testnet"],
            )
            credentials = pactus.generate_credentials(environment)
        else:
            credentials = evm.generate_credentials(network)

        self.print_credentials(credentials)
        input("\nPress Enter to return to the main menu...")

    def get_address_from_private_key(self) -> None:
        """Get address from private key."""
        network = self.prompt_choice(
            "Select network",
            ["Pactus", "Ethereum", "Polygon", "Binance Smart Chain", "Base"],
        )

        if network == "Pactus":
            environment = self.prompt_choice(
                "Select network environment",
                ["Mainnet", "Testnet"],
            )
            is_testnet = environment.lower().startswith("test")
        else:
            environment = None
            is_testnet = False

        print()
        if network == "Pactus":
            privkey_prompt = "Enter Pactus private key: "
        else:
            privkey_prompt = f"Enter {network} private key (hex format, with or without 0x): "

        privkey_str = input(privkey_prompt).strip()
        if not privkey_str:
            utils.warn("Private key is required.")
            return

        try:
            if network == "Pactus":
                address_info = pactus.derive_address_from_private_key(privkey_str, is_testnet)
            else:
                address_info = evm.derive_address_from_private_key(privkey_str)

            self.print_address_info(address_info, network, environment)
        except Exception as e:
            utils.error(f"Failed to derive address: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def create_wrap_transaction(self) -> None:
        """Create and sign a wrap transaction (PAC->wPAC)."""
        environment = self.prompt_choice(
            "Select network environment",
            ["Mainnet", "Testnet"],
        )
        env_key = "testnet" if environment.lower().startswith("test") else "mainnet"
        is_testnet = env_key == "testnet"
        # Use deposit address for wrapping (locking PAC)
        wrapto_address = config.get_wrapto_address(env_key, "deposit")

        if not wrapto_address:
            utils.warn("Wrapto deposit address not found.")
            return

        print()
        sender_privkey_str = input("Enter Pactus sender private key: ").strip()
        if not sender_privkey_str:
            utils.warn("Sender private key is required.")
            return

        dest_network = self.prompt_choice(
            "Select destination network",
            ["Ethereum", "Polygon", "Binance Smart Chain", "Base"],
        )

        print()
        dest_address = input("Enter destination address: ").strip()
        if not dest_address:
            utils.warn("Destination address is required.")
            return

        print()
        amount_str = input("Enter amount in PAC (default: 1.0): ").strip()
        if not amount_str:
            amount_pac = 1.0
        else:
            try:
                amount_pac = float(amount_str)
            except ValueError:
                utils.warn(f"Invalid amount: {amount_str}. Using default 1.0 PAC.")
                amount_pac = 1.0

        print()
        fee_str = input("Enter fee in PAC (default: 0.001): ").strip()
        if not fee_str:
            fee_pac = 0.001
        else:
            try:
                fee_pac = float(fee_str)
            except ValueError:
                utils.warn(f"Invalid fee: {fee_str}. Using default 0.001 PAC.")
                fee_pac = 0.001

        try:
            signed_tx, sender_addr = pactus.create_and_sign_wrap_tx(
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
            utils.error(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def show_pac_info(self) -> None:
        """Show PAC balance in Wrapto deposit and withdraw addresses."""
        environment = self.prompt_choice(
            "Select network environment",
            ["Mainnet", "Testnet"],
        )
        env_key = "testnet" if environment.lower().startswith("test") else "mainnet"
        is_testnet = env_key == "testnet"

        try:
            # Get deposit and withdraw addresses
            deposit_address = config.get_wrapto_address(env_key, "deposit")
            withdraw_address = config.get_wrapto_address(env_key, "withdraw")

            if not deposit_address or not withdraw_address:
                utils.warn("Wrapto addresses not found.")
                return

            # Get balances
            deposit_balance = pactus.get_account_balance(deposit_address, is_testnet)
            withdraw_balance = pactus.get_account_balance(withdraw_address, is_testnet)

            self.print_wrapto_balances(
                environment,
                deposit_address,
                deposit_balance,
                withdraw_address,
                withdraw_balance,
            )
        except Exception as e:
            utils.error(f"Failed to fetch PAC balances: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def show_wpac_info(self) -> None:
        """Show wPAC (ERC-20 token) information."""
        environment = self.prompt_choice(
            "Select network environment",
            ["Mainnet", "Testnet"],
        )
        env_key = "mainnet" if environment.lower().startswith("main") else "testnet"

        # Calculate total wPAC supply across all networks
        total_supply = 0.0
        contract_name = "wpac"
        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            rpc_endpoint = config.get_rpc_endpoint(network, env_key)
            if address and rpc_endpoint:
                try:
                    contract_info = evm.get_wpac_info(address, rpc_endpoint)
                    if contract_info.get("total_supply") is not None:
                        total_supply += contract_info["total_supply"]
                except Exception:
                    pass  # Skip if can't fetch this network

        # Display total wPAC supply in bold and yellow
        if total_supply > 0:
            print()
            print(utils.bold_yellow(f"Total Supply: {total_supply:.9f} wPAC"))
            print()

        # Get available wPAC contracts
        contract_options = []
        contract_map = {}

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                display_name = f"wPAC on {network.capitalize()}"
                contract_options.append(display_name)
                contract_map[display_name] = (contract_name, network)

        if not contract_options:
            utils.warn("No contracts found for the selected environment.")
            input("\nPress Enter to return to the main menu...")
            return

        selected_display = self.prompt_choice("Select contract", contract_options)
        contract_name, network = contract_map[selected_display]

        contract_address = config.get_contract_address(contract_name, network, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to the main menu...")
            return

        try:
            contract_info = evm.get_wpac_info(contract_address, rpc_endpoint)
            self.print_wpac_info(network, environment, contract_address, contract_info)
        except Exception as e:
            utils.error(f"Failed to fetch wPAC info: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def create_unwrap_transaction(self) -> None:
        """Create and sign an unwrap transaction (wPAC->PAC)."""
        utils.warn("Unwrap transaction functionality not yet implemented.")
        utils.warn("This will require EVM transaction (burning wPAC) to trigger Pactus transaction.")
        input("\nPress Enter to return to the main menu...")

    def administrator_menu(self) -> None:
        """Administrator menu for wPAC contract management."""
        admin_actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Set Minter Address", self.set_minter_address),
            "2": ("Set Fee Collector Address", self.set_fee_collector_address),
            "0": ("Back to Main Menu", lambda: None),
        }

        while True:
            print()
            print("=== Administrator Menu ===")
            for key, (label, _) in admin_actions.items():
                print(f"{key}. {label}")
            print()

            choice = input("Choose an option: ").strip()
            if choice == "0":
                break

            action = admin_actions.get(choice)
            if action:
                label, callback = action
                utils.section_header(label)
                try:
                    callback()
                except KeyboardInterrupt:
                    utils.section_footer("Cancelled. Returning to administrator menu.")
                except EOFError:
                    utils.section_footer("Received EOF. Returning to administrator menu.")
                    break
            else:
                utils.warn(f"Unknown choice: {choice!r}")

    def set_minter_address(self) -> None:
        """Set the minter address for a wPAC contract."""
        environment = self.prompt_choice(
            "Select network environment",
            ["Mainnet", "Testnet"],
        )
        env_key = "mainnet" if environment.lower().startswith("main") else "testnet"

        # Get available wPAC contracts
        contract_options = []
        contract_map = {}
        contract_name = "wpac"

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                display_name = f"wPAC on {network.capitalize()}"
                contract_options.append(display_name)
                contract_map[display_name] = (contract_name, network)

        if not contract_options:
            utils.warn("No contracts found for the selected environment.")
            input("\nPress Enter to return to the administrator menu...")
            return

        selected_display = self.prompt_choice("Select contract", contract_options)
        contract_name, network = contract_map[selected_display]

        contract_address = config.get_contract_address(contract_name, network, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to the administrator menu...")
            return

        print()
        new_minter = input("Enter new minter address: ").strip()
        if not new_minter:
            utils.warn("Minter address is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        print()
        owner_privkey = input("Enter owner private key (hex format, with or without 0x): ").strip()
        if not owner_privkey:
            utils.warn("Owner private key is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        try:
            signed_tx = evm.create_set_minter_transaction(
                contract_address,
                new_minter,
                owner_privkey,
                rpc_endpoint,
            )
            self.print_signed_admin_transaction(signed_tx, network, environment, "Set Minter", new_minter)
        except Exception as e:
            utils.error(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the administrator menu...")

    def set_fee_collector_address(self) -> None:
        """Set the fee collector address for a wPAC contract."""
        environment = self.prompt_choice(
            "Select network environment",
            ["Mainnet", "Testnet"],
        )
        env_key = "mainnet" if environment.lower().startswith("main") else "testnet"

        # Get available wPAC contracts
        contract_options = []
        contract_map = {}
        contract_name = "wpac"

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                display_name = f"wPAC on {network.capitalize()}"
                contract_options.append(display_name)
                contract_map[display_name] = (contract_name, network)

        if not contract_options:
            utils.warn("No contracts found for the selected environment.")
            input("\nPress Enter to return to the administrator menu...")
            return

        selected_display = self.prompt_choice("Select contract", contract_options)
        contract_name, network = contract_map[selected_display]

        contract_address = config.get_contract_address(contract_name, network, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to the administrator menu...")
            return

        print()
        new_fee_collector = input("Enter new fee collector address: ").strip()
        if not new_fee_collector:
            utils.warn("Fee collector address is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        print()
        owner_privkey = input("Enter owner private key (hex format, with or without 0x): ").strip()
        if not owner_privkey:
            utils.warn("Owner private key is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        try:
            signed_tx = evm.create_set_fee_collector_transaction(
                contract_address,
                new_fee_collector,
                owner_privkey,
                rpc_endpoint,
            )
            self.print_signed_admin_transaction(signed_tx, network, environment, "Set Fee Collector", new_fee_collector)
        except Exception as e:
            utils.error(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the administrator menu...")

    def print_signed_admin_transaction(
        self, signed_tx: Dict[str, Any], network: str, environment: str, action: str, new_address: str
    ) -> None:
        """Print signed administrator transaction details."""
        print()
        print(f"[{action}] {network.capitalize()} ({environment})")
        print(f"Contract: {signed_tx.get('contract_address', 'N/A')}")
        print(f"New Address: {new_address}")
        print(f"Signed transaction (hex): {signed_tx.get('raw_transaction', 'N/A')}")
        if 'transaction_hash' in signed_tx:
            print(f"Transaction hash: {signed_tx['transaction_hash']}")

    def print_credentials(self, credentials: models.Credentials) -> None:
        """Print credentials information."""
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

    def print_address_info(
        self, address_info: Dict[str, str], network: str, environment: str | None
    ) -> None:
        """Print address information."""
        print()
        label = network
        if environment:
            label = f"{label} ({environment})"
        print(f"[{label}] Address Information")
        print(f"Private key: {address_info['private_key']}")
        print(f"Public key:  {address_info['public_key']}")
        print(f"Address:     {address_info['address']}")

    def print_signed_transaction(
        self, signed_tx: bytes, environment: str, dest_network: str, sender_addr: str
    ) -> None:
        """Print signed transaction information."""
        print()
        print(f"[Wrap Transaction] {environment}")
        print(f"Sender address: {sender_addr}")
        print(f"Destination: {dest_network}")
        print(f"Signed transaction (hex): {signed_tx.hex()}")
        print(f"Signed transaction (base64): {base64.b64encode(signed_tx).decode('ascii')}")

    def print_wrapto_balances(
        self,
        environment: str,
        deposit_address: str,
        deposit_balance: Any,
        withdraw_address: str,
        withdraw_balance: Any,
    ) -> None:
        """Print Wrapto deposit and withdraw address balances."""
        from pactus.amount import Amount

        print()
        print(f"[PAC Balance] Wrapto Project ({environment})")
        print()

        # Calculate total PAC
        total_balance = Amount(deposit_balance.value + withdraw_balance.value)
        total_pac = total_balance.value / 1e9

        # Display total PAC in bold and yellow
        print(utils.bold_yellow(f"Total PAC: {total_pac:.9f} PAC"))
        print()

        # Convert Amount to PAC for display
        deposit_pac = deposit_balance.value / 1e9
        withdraw_pac = withdraw_balance.value / 1e9

        print(f"Deposit Address (Locked/Cold):")
        print(f"  Address: {deposit_address}")
        print(f"  Balance: {deposit_pac:.9f} PAC")

        print()

        print(f"Withdraw Address (Unlocked/Warm):")
        print(f"  Address: {withdraw_address}")
        print(f"  Balance: {withdraw_pac:.9f} PAC")

    def print_wpac_info(
        self,
        network: str,
        environment: str,
        contract_address: str,
        contract_info: Dict[str, Any],
    ) -> None:
        """Print wPAC (ERC-20 token) information."""
        print()
        print(f"[wPAC Info] {network.capitalize()} ({environment})")
        print(f"Address: {contract_address}")
        print()

        # Display admin addresses
        if "owner" in contract_info and contract_info["owner"]:
            print(f"Owner: {contract_info['owner']}")
        else:
            print("Owner: N/A")

        if "minter" in contract_info and contract_info["minter"]:
            print(f"Minter: {contract_info['minter']}")
        else:
            print("Minter: N/A")

        if "fee_collector" in contract_info and contract_info["fee_collector"]:
            print(f"Fee Collector: {contract_info['fee_collector']}")
        else:
            print("Fee Collector: N/A")

        print()

        if "total_supply" in contract_info and contract_info["total_supply"] is not None:
            decimals = contract_info.get("decimals", 18)
            print(f"Total Supply: {contract_info['total_supply']:.{decimals}f} wPAC")

    def exit_program(self) -> None:
        """Exit the program."""
        print("\nExiting Hitchcock. Goodbye!")
        self.should_exit = True


def main() -> int:
    """Main entry point."""
    cli = HitchcockCLI()
    cli.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

