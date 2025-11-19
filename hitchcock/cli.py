"""Main CLI interface for Hitchcock."""

from __future__ import annotations

import base64
import sys
from typing import Any, Callable, Dict, List, Tuple

from hitchcock import config, evm, models, pactus, utils


class HitchcockCLI:
    """Main CLI class for Hitchcock."""

    def __init__(self, environment: str = "mainnet") -> None:
        self.environment = environment
        self.actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Generate private key", self.generate_private_key),
            "2": ("Get Address from Private key", self.get_address_from_private_key),
            "3": ("Show PAC Info", self.show_pac_info),
            "4": ("Show WPAC Info", self.show_wpac_info),
            "5": ("Create and Sign Wrap Transaction (PAC->WPAC)", self.create_wrap_transaction),
            "6": ("Create and Sign Unwrap Transaction (WPAC->PAC)", self.create_unwrap_transaction),
            "7": ("Dump All Bridges", self.dump_all_bridges),
            "8": ("Administrator Menu", self.administrator_menu),
            "0": ("Exit", self.exit_program),
        }
        self.should_exit = False

    def run(self) -> None:
        """Run the CLI main loop."""
        # utils.clear_screen()
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
        # Convert actions to simple dict for menu display
        menu_items = {key: label for key, (label, _) in self.actions.items()}
        utils.print_menu("Hitchcock Main Menu", menu_items)
        return input("Choose an option: ").strip()

    def prompt_choice(self, title: str, options: List[str]) -> str:
        """Prompt user to choose from a list of options."""
        options_map = {str(index): option for index, option in enumerate(options, start=1)}
        reverse_map = {option.lower(): option for option in options}

        while True:
            utils.print_menu(title, list(options_map.items()))
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
            environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
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
            environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
            is_testnet = self.environment == "testnet"
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
        """Create and sign a wrap transaction (PAC->WPAC)."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment
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
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment
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
        """Show WPAC (ERC-20 token) information."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        # Calculate total WPAC supply across all networks and fetch individual supplies
        total_supply = 0.0
        contract_name = "wpac"
        network_supplies = {}  # Store supply for each network

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            rpc_endpoint = config.get_rpc_endpoint(network, env_key)
            if address and rpc_endpoint:
                try:
                    # Use lightweight function that only fetches total supply
                    supply = evm.get_wpac_total_supply(address, rpc_endpoint)
                    if supply is not None:
                        total_supply += supply
                        network_supplies[network] = supply
                    else:
                        network_supplies[network] = None  # Mark as unavailable
                except Exception:
                    network_supplies[network] = None  # Mark as unavailable

        # Display total WPAC supply in bold and yellow
        if total_supply > 0:
            print()
            print(utils.bold_yellow(f"Total Supply: {total_supply:.9f} WPAC"))
            print()

        # Get available WPAC contracts with supply information
        contract_options = []
        contract_map = {}

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                # Get supply for this network
                supply = network_supplies.get(network)
                if supply is not None:
                    # Use fixed decimals from config
                    display_name = f"WPAC on {config.get_network_display_name(network)} ({supply:.{config.WPAC_DECIMALS}f} WPAC)"
                else:
                    display_name = f"WPAC on {config.get_network_display_name(network)} (N/A)"
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
            utils.error(f"Failed to fetch WPAC info: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def create_unwrap_transaction(self) -> None:
        """Create and sign an unwrap transaction (WPAC->PAC)."""
        utils.warn("Unwrap transaction functionality not yet implemented.")
        utils.warn("This will require EVM transaction (burning WPAC) to trigger Pactus transaction.")
        input("\nPress Enter to return to the main menu...")

    def administrator_menu(self) -> None:
        """Administrator menu for WPAC contract management."""
        admin_actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Set Minter Address", self.set_minter_address),
            "2": ("Set Fee Collector Address", self.set_fee_collector_address),
            "3": ("Transfer Ownership", self.transfer_ownership),
            "4": ("Upgrade Proxy Implementation", self.upgrade_proxy_implementation),
        }

        # Convert admin_actions to simple dict for menu display
        menu_items = {key: label for key, (label, _) in admin_actions.items()}
        # Add "0" option for going back to main menu
        menu_items["0"] = "Back to Main Menu"

        if self.environment == "mainnet":
            print()
            print(utils.bold_red("⚠ WARNING: You are connected to MAINNET."))
            print(utils.bold_red("All administrator actions will affect live contracts."))

        choice = ""
        while choice != "0":
            utils.print_menu("Administrator Menu", menu_items)
            choice = input("Choose an option: ").strip()

            if choice == "0":
                break

            action = admin_actions.get(choice)
            if action:
                label, callback = action
                utils.section_header(label)
                callback()
            else:
                utils.warn(f"Unknown choice: {choice!r}")

    def set_minter_address(self) -> None:
        """Set the minter address for a WPAC contract."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        # Get available WPAC contracts
        contract_options = []
        contract_map = {}
        contract_name = "wpac"

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                display_name = f"WPAC on {config.get_network_display_name(network)}"
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

        # Fetch current minter address
        try:
            contract_info = evm.get_wpac_info(contract_address, rpc_endpoint)
            current_minter = contract_info.get("minter")
            print()
            if current_minter:
                print(utils.bold_yellow(f"Current Minter Address: {current_minter}"))
            else:
                utils.warn("Could not fetch current minter address.")
        except Exception as e:
            utils.warn(f"Could not fetch current minter address: {e}")

        print()
        new_minter = input("Enter new minter address: ").strip()
        if not new_minter:
            utils.warn("Minter address is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        # Offer Trezor signing option for both Mainnet and Testnet
        use_trezor = False
        owner_privkey = None
        trezor_path = config.get_trezor_derivation_path()

        print()
        sign_method = self.prompt_choice(
            "Select signing method",
            ["Trezor Hardware Wallet", "Private Key"],
        )
        if sign_method == "Trezor Hardware Wallet":
            use_trezor = True
            print()
            trezor_path_input = input(f"Enter Trezor derivation path (default: {trezor_path}): ").strip()
            if trezor_path_input:
                trezor_path = trezor_path_input
            print()
            utils.info("Please connect and unlock your Trezor device...")
        else:
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
                use_trezor=use_trezor,
                trezor_path=trezor_path,
            )
            self.print_signed_admin_transaction(signed_tx, network, environment, "Set Minter", new_minter)

            # Ask if user wants to send the transaction
            print()
            send_choice = input("Send transaction to blockchain? (y/N): ").strip().lower()
            if send_choice in ["y", "yes"]:
                try:
                    result = evm.send_transaction(signed_tx["raw_transaction"], rpc_endpoint)
                    print()
                    utils.success("Transaction sent successfully!")
                    print()
                    print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(result['transaction_hash'])}")
                    if "block_number" in result:
                        print(f"{utils.bold('Block Number:')} {result['block_number']}")
                        status_text = "Success" if result['status'] == 1 else "Failed"
                        status_color = utils.bold_green if result['status'] == 1 else utils.bold_red
                        print(f"{utils.bold('Status:')} {status_color(status_text)}")
                        print(f"{utils.bold('Gas Used:')} {result['gas_used']}")
                except Exception as e:
                    utils.error(f"Failed to send transaction: {e}")
            else:
                utils.info("Transaction not sent. You can send it manually using the raw transaction hex above.")
        except Exception as e:
            utils.error(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the administrator menu...")

    def set_fee_collector_address(self) -> None:
        """Set the fee collector address for a WPAC contract."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        # Get available WPAC contracts
        contract_options = []
        contract_map = {}
        contract_name = "wpac"

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                display_name = f"WPAC on {config.get_network_display_name(network)}"
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

        # Fetch current fee collector address
        try:
            contract_info = evm.get_wpac_info(contract_address, rpc_endpoint)
            current_fee_collector = contract_info.get("fee_collector")
            print()
            if current_fee_collector:
                print(utils.bold_yellow(f"Current Fee Collector Address: {current_fee_collector}"))
            else:
                utils.warn("Could not fetch current fee collector address.")
        except Exception as e:
            utils.warn(f"Could not fetch current fee collector address: {e}")

        print()
        new_fee_collector = input("Enter new fee collector address: ").strip()
        if not new_fee_collector:
            utils.warn("Fee collector address is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        # Offer Trezor signing option for both Mainnet and Testnet
        use_trezor = False
        owner_privkey = None
        trezor_path = config.get_trezor_derivation_path()

        print()
        sign_method = self.prompt_choice(
            "Select signing method",
            ["Trezor Hardware Wallet", "Private Key"],
        )
        if sign_method == "Trezor Hardware Wallet":
            use_trezor = True
            print()
            trezor_path_input = input(f"Enter Trezor derivation path (default: {trezor_path}): ").strip()
            if trezor_path_input:
                trezor_path = trezor_path_input
            print()
            utils.info("Please connect and unlock your Trezor device...")
        else:
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
                use_trezor=use_trezor,
                trezor_path=trezor_path,
            )
            self.print_signed_admin_transaction(signed_tx, network, environment, "Set Fee Collector", new_fee_collector)

            # Ask if user wants to send the transaction
            print()
            send_choice = input("Send transaction to blockchain? (y/N): ").strip().lower()
            if send_choice in ["y", "yes"]:
                try:
                    result = evm.send_transaction(signed_tx["raw_transaction"], rpc_endpoint)
                    print()
                    utils.success("Transaction sent successfully!")
                    print()
                    print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(result['transaction_hash'])}")
                    if "block_number" in result:
                        print(f"{utils.bold('Block Number:')} {result['block_number']}")
                        status_text = "Success" if result['status'] == 1 else "Failed"
                        status_color = utils.bold_green if result['status'] == 1 else utils.bold_red
                        print(f"{utils.bold('Status:')} {status_color(status_text)}")
                        print(f"{utils.bold('Gas Used:')} {result['gas_used']}")
                except Exception as e:
                    utils.error(f"Failed to send transaction: {e}")
            else:
                utils.info("Transaction not sent. You can send it manually using the raw transaction hex above.")
        except Exception as e:
            utils.error(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the administrator menu...")

    def transfer_ownership(self) -> None:
        """Transfer ownership of a WPAC contract."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        # Get available WPAC contracts
        contract_options = []
        contract_map = {}
        contract_name = "wpac"

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                display_name = f"WPAC on {config.get_network_display_name(network)}"
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

        # Fetch current owner address
        try:
            contract_info = evm.get_wpac_info(contract_address, rpc_endpoint)
            current_owner = contract_info.get("owner")
            print()
            if current_owner:
                print(utils.bold_yellow(f"Current Owner Address: {current_owner}"))
            else:
                utils.warn("Could not fetch current owner address.")
        except Exception as e:
            utils.warn(f"Could not fetch current owner address: {e}")

        print()
        new_owner = input("Enter new owner address: ").strip()
        if not new_owner:
            utils.warn("Owner address is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        # Offer Trezor signing option for both Mainnet and Testnet
        use_trezor = False
        owner_privkey = None
        trezor_path = config.get_trezor_derivation_path()

        print()
        sign_method = self.prompt_choice(
            "Select signing method",
            ["Trezor Hardware Wallet", "Private Key"],
        )
        if sign_method == "Trezor Hardware Wallet":
            use_trezor = True
            print()
            trezor_path_input = input(f"Enter Trezor derivation path (default: {trezor_path}): ").strip()
            if trezor_path_input:
                trezor_path = trezor_path_input
            print()
            utils.info("Please connect and unlock your Trezor device...")
        else:
            print()
            owner_privkey = input("Enter owner private key (hex format, with or without 0x): ").strip()
            if not owner_privkey:
                utils.warn("Owner private key is required.")
                input("\nPress Enter to return to the administrator menu...")
                return

        try:
            signed_tx = evm.create_transfer_ownership_transaction(
                contract_address,
                new_owner,
                owner_privkey,
                rpc_endpoint,
                use_trezor=use_trezor,
                trezor_path=trezor_path,
            )
            self.print_signed_admin_transaction(signed_tx, network, environment, "Transfer Ownership", new_owner)

            # Ask if user wants to send the transaction
            print()
            send_choice = input("Send transaction to blockchain? (y/N): ").strip().lower()
            if send_choice in ["y", "yes"]:
                try:
                    result = evm.send_transaction(signed_tx["raw_transaction"], rpc_endpoint)
                    print()
                    utils.success("Transaction sent successfully!")
                    print()
                    print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(result['transaction_hash'])}")
                    if "block_number" in result:
                        print(f"{utils.bold('Block Number:')} {result['block_number']}")
                        status_text = "Success" if result['status'] == 1 else "Failed"
                        status_color = utils.bold_green if result['status'] == 1 else utils.bold_red
                        print(f"{utils.bold('Status:')} {status_color(status_text)}")
                        print(f"{utils.bold('Gas Used:')} {result['gas_used']}")
                except Exception as e:
                    utils.error(f"Failed to send transaction: {e}")
            else:
                utils.info("Transaction not sent. You can send it manually using the raw transaction hex above.")
        except Exception as e:
            utils.error(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the administrator menu...")

    def upgrade_proxy_implementation(self) -> None:
        """Upgrade the proxy implementation (set new logic contract)."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        contract_options = []
        contract_map = {}
        contract_name = "wpac"

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            if address:
                display_name = f"WPAC on {config.get_network_display_name(network)}"
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

        try:
            contract_info = evm.get_wpac_info(contract_address, rpc_endpoint)
            current_impl = contract_info.get("implementation_address")
            print()
            if current_impl:
                print(utils.bold_yellow(f"Current Implementation Address: {current_impl}"))
            else:
                utils.warn("Could not fetch current implementation address.")
        except Exception as e:
            utils.warn(f"Could not fetch current implementation address: {e}")

        print()
        new_impl = input("Enter new implementation address: ").strip()
        if not new_impl:
            utils.warn("Implementation address is required.")
            input("\nPress Enter to return to the administrator menu...")
            return

        use_trezor = False
        owner_privkey = None
        trezor_path = config.get_trezor_derivation_path()

        print()
        sign_method = self.prompt_choice(
            "Select signing method",
            ["Trezor Hardware Wallet", "Private Key"],
        )
        if sign_method == "Trezor Hardware Wallet":
            use_trezor = True
            print()
            trezor_path_input = input(f"Enter Trezor derivation path (default: {trezor_path}): ").strip()
            if trezor_path_input:
                trezor_path = trezor_path_input
            print()
            utils.info("Please connect and unlock your Trezor device...")
        else:
            print()
            owner_privkey = input("Enter owner private key (hex format, with or without 0x): ").strip()
            if not owner_privkey:
                utils.warn("Owner private key is required.")
                input("\nPress Enter to return to the administrator menu...")
                return

        try:
            signed_tx = evm.create_upgrade_to_transaction(
                contract_address,
                new_impl,
                owner_privkey,
                rpc_endpoint,
                use_trezor=use_trezor,
                trezor_path=trezor_path,
            )
            self.print_signed_admin_transaction(
                signed_tx,
                network,
                environment,
                "Upgrade Proxy Implementation",
                new_impl,
            )

            print()
            send_choice = input("Send transaction to blockchain? (y/N): ").strip().lower()
            if send_choice in ["y", "yes"]:
                try:
                    result = evm.send_transaction(signed_tx["raw_transaction"], rpc_endpoint)
                    print()
                    utils.success("Transaction sent successfully!")
                    print()
                    print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(result['transaction_hash'])}")
                    if "block_number" in result:
                        print(f"{utils.bold('Block Number:')} {result['block_number']}")
                        status_text = "Success" if result['status'] == 1 else "Failed"
                        status_color = utils.bold_green if result['status'] == 1 else utils.bold_red
                        print(f"{utils.bold('Status:')} {status_color(status_text)}")
                        print(f"{utils.bold('Gas Used:')} {result['gas_used']}")
                except Exception as e:
                    utils.error(f"Failed to send transaction: {e}")
            else:
                utils.info("Transaction not sent. You can send it manually using the raw transaction hex above.")
        except Exception as e:
            utils.error(f"Failed to create transaction: {e}")
            return

        input("\nPress Enter to return to the administrator menu...")

    def print_signed_admin_transaction(
        self, signed_tx: Dict[str, Any], network: str, environment: str, action: str, new_address: str
    ) -> None:
        """Print signed administrator transaction details."""
        print()
        print(utils.bold_cyan(f"[{action}] {config.get_network_display_name(network)} ({environment})"))
        print()
        print(f"{utils.bold('Contract:')} {signed_tx.get('contract_address', 'N/A')}")

        # Determine label based on action
        if "Minter" in action:
            label = "New Minter Address:"
        elif "Fee Collector" in action:
            label = "New Fee Collector Address:"
        elif "Implementation" in action:
            label = "New Implementation Address:"
        else:
            label = "New Address:"

        print(f"{utils.bold(label)} {utils.bold_yellow(new_address)}")
        print()
        print(f"{utils.bold('Signed Transaction (hex):')} {signed_tx.get('raw_transaction', 'N/A')}")
        if 'transaction_hash' in signed_tx:
            print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(signed_tx['transaction_hash'])}")

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
        """Print WPAC (ERC-20 token) information."""
        print()
        print(f"[WPAC Info] {config.get_network_display_name(network)} ({environment})")
        print(f"Address: {contract_address}")
        print()

        # Display ERC-20 standard properties
        if "name" in contract_info and contract_info["name"]:
            print(f"Name: {contract_info['name']}")
        else:
            print("Name: N/A")

        if "symbol" in contract_info and contract_info["symbol"]:
            print(f"Symbol: {contract_info['symbol']}")
        else:
            print("Symbol: N/A")

        if "decimals" in contract_info and contract_info["decimals"] is not None:
            print(f"Decimals: {contract_info['decimals']}")
        else:
            print("Decimals: N/A")

        print()

        if contract_info.get("implementation_address"):
            print(f"Implementation Address: {contract_info['implementation_address']}")
        else:
            print("Implementation Address: N/A")

        print()

        # Display admin addresses with balances
        if "owner" in contract_info and contract_info["owner"]:
            owner_addr = contract_info["owner"]
            if "owner_balance" in contract_info and contract_info["owner_balance"] is not None:
                symbol = contract_info.get("owner_balance_symbol", "ETH")
                balance = contract_info["owner_balance"]
                print(f"Owner: {owner_addr} ({balance:.6f} {symbol})")
            else:
                print(f"Owner: {owner_addr} (Balance: N/A)")
        else:
            print("Owner: N/A")

        if "minter" in contract_info and contract_info["minter"]:
            minter_addr = contract_info["minter"]
            if "minter_balance" in contract_info and contract_info["minter_balance"] is not None:
                symbol = contract_info.get("minter_balance_symbol", "ETH")
                balance = contract_info["minter_balance"]
                print(f"Minter: {minter_addr} ({balance:.6f} {symbol})")
            else:
                print(f"Minter: {minter_addr} (Balance: N/A)")
        else:
            print("Minter: N/A")

        if "fee_collector" in contract_info and contract_info["fee_collector"]:
            fee_collector_addr = contract_info["fee_collector"]
            if "fee_collector_balance" in contract_info and contract_info["fee_collector_balance"] is not None:
                symbol = contract_info.get("fee_collector_balance_symbol", "ETH")
                balance = contract_info["fee_collector_balance"]
                print(f"Fee Collector: {fee_collector_addr} ({balance:.6f} {symbol})")
            else:
                print(f"Fee Collector: {fee_collector_addr} (Balance: N/A)")
        else:
            print("Fee Collector: N/A")

        print()

        if "total_supply" in contract_info and contract_info["total_supply"] is not None:
            # Use fixed decimals from config
            print(f"Total Supply: {contract_info['total_supply']:.{config.WPAC_DECIMALS}f} WPAC")

        if "collected_fee" in contract_info and contract_info["collected_fee"] is not None:
            # Use fixed decimals from config
            print(f"Collected Fee: {contract_info['collected_fee']:.{config.WPAC_DECIMALS}f} WPAC")
        else:
            print("Collected Fee: N/A")

    def dump_all_bridges(self) -> None:
        """Dump all bridges from the bridge contract."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        # Get network selection
        network = self.prompt_choice(
            "Select network",
            ["Ethereum", "Polygon", "Binance Smart Chain", "Base"],
        )

        # Map display name to network key
        network_map = {
            "Ethereum": "ethereum",
            "Polygon": "polygon",
            "Binance Smart Chain": "bsc",
            "Base": "base",
        }
        network_key = network_map[network]

        # Get RPC endpoint
        rpc_endpoint = config.get_rpc_endpoint(network_key, env_key)
        if not rpc_endpoint:
            utils.warn("RPC endpoint not found for the selected network.")
            input("\nPress Enter to return to the main menu...")
            return

        # Get contract address from config (same as wpac contract)
        contract_address = config.get_contract_address("wpac", network_key, env_key)
        if not contract_address:
            utils.warn("Contract address not found for the selected network.")
            input("\nPress Enter to return to the main menu...")
            return

        try:
            utils.info(f"Fetching bridges from contract {contract_address}...")
            bridges = evm.dump_all_bridges(contract_address, rpc_endpoint)

            if not bridges:
                utils.warn("No bridges found.")
                input("\nPress Enter to return to the main menu...")
                return

            # Log total bridges count
            total_bridges = len(bridges)
            utils.info(f"Total Bridges: {total_bridges}")

            # Display bridges
            print()
            print(utils.bold_cyan(f"[Bridge Dump] {config.get_network_display_name(network_key)} ({environment})"))
            print()
            print(utils.bold_yellow(f"Total Bridges: {total_bridges}"))
            print()

            for bridge in bridges:
                if "error" in bridge:
                    bridge_label = utils.bold_red(f"Bridge #{bridge['index']}:")
                    print(f"{bridge_label} Error - {bridge['error']}")
                else:
                    bridge_label = utils.bold(f"Bridge #{bridge['index']}:")
                    print(bridge_label)
                    print(f"  {utils.bold('Sender:')} {bridge['sender']}")
                    print(f"  {utils.bold('Amount:')} {bridge['amount']}")
                    print(f"  {utils.bold('Destination Address:')} {bridge['destinationAddress']}")
                    print(f"  {utils.bold('Fee:')} {bridge['fee']}")
                print()

        except Exception as e:
            utils.error(f"Failed to dump bridges: {e}")
            return

        input("\nPress Enter to return to the main menu...")

    def exit_program(self) -> None:
        """Exit the program."""
        print("\nExiting Hitchcock. Goodbye!")
        self.should_exit = True


def main(environment: str = "mainnet") -> int:
    """Main entry point."""
    cli = HitchcockCLI(environment)
    cli.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

