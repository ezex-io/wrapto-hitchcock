"""Main CLI interface for Hitchcock."""

from __future__ import annotations

import readline
import sys
from typing import Any, Callable, Dict, List, Tuple
from pactus.types import Amount
from web3 import Web3
import requests
from hitchcock import config, evm, models, pactus, utils


class HitchcockCLI:
    """Main CLI class for Hitchcock."""

    def __init__(self, environment: str = "testnet") -> None:
        self.environment = environment
        self.actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Generate private key", self.generate_private_key),
            "2": ("Get Address from Private key", self.get_address_from_private_key),
            "3": ("Show PAC Info", self.show_pac_info),
            "4": ("Show WPAC Info", self.show_wpac_info),
            "5": ("WPAC Contract Tools", self.wpac_contract_tools_menu),
            "6": ("Send Wrap Transaction (PAC->WPAC)", self.create_wrap_transaction),
            "7": ("Send Unwrap Transaction (WPAC->PAC)", self.create_unwrap_transaction),
            "0": ("Exit", self.exit_program),
        }
        self.should_exit = False

    def run(self) -> None:
        """Run the CLI main loop."""
        # utils.clear_screen()
        utils.print_banner()

        # Display current environment
        environment_display = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_color = utils.bold_red if self.environment == "mainnet" else utils.bold_yellow
        print()
        print(f"{utils.bold('Environment:')} {env_color(environment_display)}")
        print()

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

    def prompt_input(self, prompt: str, default: str) -> str:
        """
        Prompt user for input with a default value pre-filled.

        Args:
            prompt: The prompt message (should include default in format like "Enter amount in PAC: ")
            default: The default value to pre-fill in the input field

        Returns:
            The user input or default value if empty
        """
        # Pre-fill the input with the default value
        readline.set_startup_hook(lambda: readline.insert_text(default))
        try:
            user_input = input(prompt).strip()
        finally:
            readline.set_startup_hook()
        return user_input if user_input else default

    def prompt_confirm(self, prompt: str, default: bool = False) -> bool:
        """
        Prompt user for yes/no confirmation.

        Args:
            prompt: The prompt message (should include (y/N) or (Y/n) format)
            default: The default value (True for yes, False for no)

        Returns:
            True if user confirmed (y/yes), False otherwise
        """
        user_input = input(prompt).strip().lower()
        if not user_input:
            return default
        return user_input in ["y", "yes"]

    def generate_private_key(self) -> None:
        """Generate private key for selected network."""
        network = self.prompt_choice(
            "Select a target network",
            ["Pactus", "Ethereum", "Polygon", "BSC", "Base"],
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
            ["Pactus", "Ethereum", "Polygon", "BNB Smart Chain (BSC)", "Base"],
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
            print(e)
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
        # Check .env first
        sender_privkey_str = config.get_pactus_sender_private_key()
        if not sender_privkey_str:
            sender_privkey_str = input("Enter Pactus sender private key: ").strip()

        if not sender_privkey_str:
            utils.warn("Sender private key is required.")
            return

        dest_network = self.prompt_choice(
            "Select destination network",
            ["Ethereum", "Polygon", "BNB Smart Chain (BSC)", "Base"],
        )

        print()
        dest_address = input("Enter destination address: ").strip()
        if not dest_address:
            utils.warn("Destination address is required.")
            return

        print()
        amount_str = self.prompt_input("Enter amount in PAC: ", "10.0")
        try:
            amount = Amount.from_string(amount_str)
        except ValueError:
            utils.warn(f"Invalid amount: {amount_str}. Using default 10.0 PAC.")
            amount = Amount.from_string("10.0")

        print()
        fee_str = self.prompt_input("Enter fee in PAC: ", "0.01")
        try:
            fee = Amount.from_string(fee_str)
        except ValueError:
            utils.warn(f"Invalid fee: {fee_str}. Using default 0.01 PAC.")
            fee = Amount.from_string("0.01")

        print()
        # Map network display name to memo format
        network_memo_map = {
            "Ethereum": "Eth",
            "Polygon": "Polygon",
            "BNB Smart Chain": "BSC",
            "BNB Smart Chain (BSC)": "BSC",
            "Base": "Base",
        }
        network_for_memo = network_memo_map.get(dest_network, dest_network)
        default_memo = f"{dest_address}@{network_for_memo}"
        memo = self.prompt_input("Enter memo: ", default_memo)

        try:

            signed_tx, sender_addr = pactus.create_and_sign_wrap_tx(
                sender_privkey_str,
                wrapto_address,
                dest_address,
                dest_network,
                amount,
                fee,
                is_testnet,
                memo,
            )
            self.print_signed_transaction(signed_tx, environment, dest_network, sender_addr)

            # Ask if user wants to broadcast
            print()
            if self.prompt_confirm("Broadcast transaction to blockchain? (y/N): "):
                try:
                    tx_id = pactus.broadcast_transaction(signed_tx, is_testnet)
                    print()
                    utils.success("Transaction broadcast successfully!")
                    print()
                    print(f"{utils.bold('Transaction ID:')} {utils.bold_cyan(tx_id)}")
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)
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
            print(e)
            return

        input("\nPress Enter to return to the main menu...")

    def show_wpac_info(self) -> None:
        """Show WPAC (ERC-20 token) information."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        # Calculate total WPAC supply across all networks and fetch individual supplies
        total_supply = Amount(0)
        contract_name = "wpac"
        network_supplies: Dict[str, Amount] = {}  # Store supply as Amount objects

        for network in config.list_networks():
            address = config.get_contract_address(contract_name, network, env_key)
            rpc_endpoint = config.get_rpc_endpoint(network, env_key)
            if address and rpc_endpoint:
                try:
                    # Use lightweight function that only fetches total supply
                    supply = evm.get_wpac_total_supply(address, rpc_endpoint)
                    # Keep Amount objects, add to total
                    total_supply = Amount(total_supply.value + supply.value)
                    network_supplies[network] = supply
                except Exception as e:
                    # Log error for debugging - network will not be in network_supplies
                    utils.warn(f"Failed to fetch WPAC supply for {network}: {e}")

        # Display total WPAC supply in bold and yellow
        if total_supply.value > 0:
            print()
            print(utils.bold_yellow(f"Total Supply: {total_supply} WPAC"))
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
                    display_name = f"WPAC on {config.get_network_display_name(network)} ({supply} WPAC)"
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
            print(e)
            return

        input("\nPress Enter to return to the main menu...")

    def create_unwrap_transaction(self) -> None:
        """Create and sign an unwrap transaction (WPAC->PAC)."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        print()
        # Select source network (where WPAC contract is)
        source_network = self.prompt_choice(
            "Select source network (where WPAC is held)",
            ["Ethereum", "Polygon", "BNB Smart Chain (BSC)", "Base"],
        )

        # Map network display name to network key
        network_map = {
            "Ethereum": "ethereum",
            "Polygon": "polygon",
            "BNB Smart Chain (BSC)": "bnb",
            "Base": "base",
        }
        network_key = network_map.get(source_network)
        if not network_key:
            utils.warn("Invalid network selection.")
            return

        # Get WPAC contract address and RPC endpoint
        contract_address = config.get_contract_address("wpac", network_key, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network_key, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to the main menu...")
            return

        print()
        # Get sender's EVM private key
        sender_privkey = config.get_evm_private_key(network_key)
        if not sender_privkey:
            sender_privkey = input("Enter EVM sender private key (hex format, with or without 0x): ").strip()

        if not sender_privkey:
            utils.warn("Sender private key is required.")
            return

        # Remove 0x prefix if present
        if sender_privkey.startswith("0x"):
            sender_privkey = sender_privkey[2:]

        print()
        dest_address = input("Enter destination Pactus address: ").strip()
        if not dest_address:
            utils.warn("Destination Pactus address is required.")
            return

        print()
        amount_str = self.prompt_input("Enter amount in WPAC: ", "10.0")
        try:
            amount = Amount.from_string(amount_str)
        except ValueError:
            utils.warn(f"Invalid amount: {amount_str}. Using default 10.0 WPAC.")
            amount = Amount.from_string("10.0")

        try:
            signed_tx = evm.create_bridge_transaction(
                contract_address=contract_address,
                destination_address=dest_address,
                amount=amount,
                sender_privkey=sender_privkey,
                rpc_endpoint=rpc_endpoint,
            )

            print()
            print(f"[Unwrap Transaction] {environment}")
            print(f"Source Network: {source_network}")
            print(f"Contract Address: {contract_address}")
            print(f"Destination Pactus Address: {dest_address}")
            print(f"Amount: {amount} WPAC")
            print(f"Transaction Hash: {utils.bold_cyan(signed_tx['transaction_hash'])}")
            print(f"Raw Transaction (hex): {signed_tx['raw_transaction']}")

            # Ask if user wants to broadcast
            print()
            if self.prompt_confirm("Broadcast transaction to blockchain? (y/N): "):
                try:
                    result = evm.send_transaction(signed_tx['raw_transaction'], rpc_endpoint)
                    print()
                    utils.success("Transaction broadcast successfully!")
                    print()
                    if 'transactionHash' in result:
                        print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(result['transactionHash'])}")
                    else:
                        print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(signed_tx['transaction_hash'])}")
                except Exception as e:
                    print(f"Error: {e}")
        except Exception as e:
            print(e)
            return

        input("\nPress Enter to return to the main menu...")

    def administrator_menu(self) -> None:
        """Administrator menu for WPAC contract management."""
        admin_actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Set Minter Address", self.set_minter_address),
            "2": ("Transfer Ownership", self.transfer_ownership),
            "3": ("Upgrade Proxy Implementation", self.upgrade_proxy_implementation),
            "4": ("Reprocess Failed Orders", self.reprocess_failed_orders),
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
            input("\nPress Enter to return to administrator menu...")
            return

        selected_display = self.prompt_choice("Select contract", contract_options)
        contract_name, network = contract_map[selected_display]

        contract_address = config.get_contract_address(contract_name, network, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to administrator menu...")
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
            print(e)

        print()
        new_minter = input("Enter new minter address: ").strip()
        if not new_minter:
            utils.warn("Minter address is required.")
            input("\nPress Enter to return to administrator menu...")
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
            # Check .env first
            owner_privkey = config.get_owner_private_key()
            if not owner_privkey:
                owner_privkey = input("Enter owner private key (hex format, with or without 0x): ").strip()
            if not owner_privkey:
                utils.warn("Owner private key is required.")
                input("\nPress Enter to return to administrator menu...")
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
            if self.prompt_confirm("Send transaction to blockchain? (y/N): "):
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
                    print(e)
            else:
                utils.info("Transaction not sent. You can send it manually using the raw transaction hex above.")
        except Exception as e:
            print(e)
            return

        input("\nPress Enter to return to administrator menu...")

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
            input("\nPress Enter to return to administrator menu...")
            return

        selected_display = self.prompt_choice("Select contract", contract_options)
        contract_name, network = contract_map[selected_display]

        contract_address = config.get_contract_address(contract_name, network, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to administrator menu...")
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
            print(e)

        print()
        new_owner = input("Enter new owner address: ").strip()
        if not new_owner:
            utils.warn("Owner address is required.")
            input("\nPress Enter to return to administrator menu...")
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
            # Check .env first
            owner_privkey = config.get_owner_private_key()
            if not owner_privkey:
                owner_privkey = input("Enter owner private key (hex format, with or without 0x): ").strip()
            if not owner_privkey:
                utils.warn("Owner private key is required.")
                input("\nPress Enter to return to administrator menu...")
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
            if self.prompt_confirm("Send transaction to blockchain? (y/N): "):
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
                    print(e)
            else:
                utils.info("Transaction not sent. You can send it manually using the raw transaction hex above.")
        except Exception as e:
            print(e)
            return

        input("\nPress Enter to return to administrator menu...")

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
            input("\nPress Enter to return to administrator menu...")
            return

        selected_display = self.prompt_choice("Select contract", contract_options)
        contract_name, network = contract_map[selected_display]

        contract_address = config.get_contract_address(contract_name, network, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to administrator menu...")
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
            input("\nPress Enter to return to administrator menu...")
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
            # Check .env first
            owner_privkey = config.get_owner_private_key()
            if not owner_privkey:
                owner_privkey = input("Enter owner private key (hex format, with or without 0x): ").strip()
            if not owner_privkey:
                utils.warn("Owner private key is required.")
                input("\nPress Enter to return to administrator menu...")
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
            if self.prompt_confirm("Send transaction to blockchain? (y/N): "):
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
                    print(e)
            else:
                utils.info("Transaction not sent. You can send it manually using the raw transaction hex above.")
        except Exception as e:
            print(e)
            return

        input("\nPress Enter to return to administrator menu...")

    def reprocess_failed_orders(self) -> None:
        """Reprocess a failed order by calling the wrapto backend API."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        print()
        # Check .env first
        admin_token = config.get_http_admin_admin_token()
        if not admin_token:
            admin_token = input("Enter admin token: ").strip()

        if not admin_token:
            utils.warn("Admin token is required.")
            input("\nPress Enter to return to administrator menu...")
            return

        print()
        order_id = input("Enter order ID: ").strip()
        if not order_id:
            utils.warn("Order ID is required.")
            input("\nPress Enter to return to administrator menu...")
            return

        # Get the backend API URL
        api_base_url = config.get_wrapto_backend_api(env_key)
        api_url = f"{api_base_url}/admin/rescan/{order_id}"

        print()
        utils.info(f"Calling API: {api_url}")
        print()

        try:
            headers = {
                "X-ADMIN-TOKEN": admin_token,
            }

            response = requests.get(api_url, headers=headers, timeout=30)

            print()
            print(utils.bold_cyan(f"[Reprocess Failed Order] {environment}"))
            print()
            print(f"{utils.bold('Order ID:')} {order_id}")
            print(f"{utils.bold('API URL:')} {api_url}")
            print(f"{utils.bold('Status Code:')} {response.status_code}")

            if response.status_code == 200:
                utils.success("Order reprocessing initiated successfully!")
                try:
                    response_data = response.json()
                    print()
                    print(f"{utils.bold('Response:')}")
                    print(response_data)
                except ValueError:
                    print()
                    print(f"{utils.bold('Response:')} {response.text}")
            else:
                utils.warn(f"API call failed with status code {response.status_code}")
                print()
                print(f"{utils.bold('Response:')} {response.text}")

        except requests.exceptions.RequestException as e:
            utils.error(f"Failed to call API: {e}")
            print()
            print(f"Error details: {str(e)}")
        except Exception as e:
            utils.error(f"Unexpected error: {e}")
            print()
            print(f"Error details: {str(e)}")

        input("\nPress Enter to return to administrator menu...")

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

    def print_wrapto_balances(
        self,
        environment: str,
        deposit_address: str,
        deposit_balance: Amount,
        withdraw_address: str,
        withdraw_balance: Amount,
    ) -> None:
        """Print Wrapto deposit and withdraw address balances."""
        print()
        print(f"[PAC Balance] Wrapto Project ({environment})")
        print()

        # Calculate total PAC using Amount objects
        total_balance = Amount(deposit_balance.value + withdraw_balance.value)

        # Display total PAC in bold and yellow
        print(utils.bold_yellow(f"Total PAC: {total_balance} PAC"))
        print()


        print("Deposit Address (Locked/Cold):")
        print(f"  Address: {deposit_address}")
        print(f"  Balance: {deposit_balance} PAC")

        print()

        print("Withdraw Address (Unlocked/Warm):")
        print(f"  Address: {withdraw_address}")
        print(f"  Balance: {withdraw_balance} PAC")

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
                print(f"Owner: {owner_addr} ({balance:} {symbol})")
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

        print()

        if "total_supply" in contract_info and contract_info["total_supply"] is not None:
            # Use fixed decimals from config
            print(f"Total Supply: {contract_info['total_supply']:.{config.WPAC_DECIMALS}f} WPAC")

    def wpac_contract_tools_menu(self) -> None:
        """WPAC Contract Tools menu - combines query, dump, and admin functions."""
        tools_actions: Dict[str, Tuple[str, Callable[[], None]]] = {
            "1": ("Query WPAC Balance", self.query_wpac_balance),
            "2": ("Dump All Bridges", self.dump_all_bridges),
            "3": ("Transfer Native Coin", self.transfer_native_coin),
            "4": ("Administrator Menu", self.administrator_menu),
        }

        # Convert tools_actions to simple dict for menu display
        menu_items = {key: label for key, (label, _) in tools_actions.items()}
        # Add "0" option for going back to main menu
        menu_items["0"] = "Back to Main Menu"

        choice = ""
        while choice != "0":
            utils.print_menu("WPAC Contract Tools", menu_items)
            choice = input("Choose an option: ").strip()

            if choice == "0":
                break

            action = tools_actions.get(choice)
            if action:
                label, callback = action
                utils.section_header(label)
                try:
                    callback()
                except KeyboardInterrupt:
                    utils.section_footer("Cancelled. Returning to WPAC Contract Tools menu.")
                except EOFError:
                    utils.section_footer("Received EOF. Returning to main menu.")
                    break
            else:
                utils.warn(f"Unknown choice: {choice!r}")

    def query_wpac_balance(self) -> None:
        """Query WPAC ERC-20 token balance for an address."""
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
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        selected_display = self.prompt_choice("Select contract", contract_options)
        contract_name, network = contract_map[selected_display]

        contract_address = config.get_contract_address(contract_name, network, env_key)
        rpc_endpoint = config.get_rpc_endpoint(network, env_key)

        if not contract_address or not rpc_endpoint:
            utils.warn("Contract address or RPC endpoint not found.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        print()
        address_to_query = input("Enter address to query balance for: ").strip()
        if not address_to_query:
            utils.warn("Address is required.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        native_balance_display = None

        try:
            balance: Amount = evm.get_wpac_balance(contract_address, address_to_query, rpc_endpoint)

            # Fetch native coin balance for the same address
            try:
                w3 = Web3(Web3.HTTPProvider(rpc_endpoint))
                if w3.is_connected():
                    native_balance_wei = w3.eth.get_balance(Web3.to_checksum_address(address_to_query))
                    native_balance = Web3.from_wei(native_balance_wei, "ether")
                    native_symbol = config.get_native_token_symbol(network)
                    native_balance_display = f"{native_balance:.6f} {native_symbol}"
            except Exception as balance_error:
                utils.warn(f"Failed to fetch native balance: {balance_error}")

            print()
            print(utils.bold_cyan(f"[WPAC Balance] {config.get_network_display_name(network)} ({environment})"))
            print()
            print(f"{utils.bold('Contract Address:')} {contract_address}")
            print(f"{utils.bold('Query Address:')} {address_to_query}")
            balance_text = f"{balance} WPAC"
            if native_balance_display:
                balance_text = f"{balance_text} ({native_balance_display})"
            print(f"{utils.bold('Balance:')} {utils.bold_yellow(balance_text)}")
        except Exception as e:
            utils.error(f"Failed to query balance: {e}")
            print(e)

        input("\nPress Enter to return to WPAC Contract Tools menu...")

    def dump_all_bridges(self) -> None:
        """Dump all bridges from the bridge contract and write to file."""
        from datetime import datetime

        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        # Get network selection
        network = self.prompt_choice(
            "Select network",
            ["Ethereum", "Polygon", "BNB Smart Chain", "Base"],
        )

        # Map display name to network key
        network_map = {
            "Ethereum": "ethereum",
            "Polygon": "polygon",
            "BNB Smart Chain": "bnb",
            "Base": "base",
        }
        network_key = network_map[network]

        # Get RPC endpoint
        rpc_endpoint = config.get_rpc_endpoint(network_key, env_key)
        if not rpc_endpoint:
            utils.warn("RPC endpoint not found for the selected network.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        # Get contract address from config (same as wpac contract)
        contract_address = config.get_contract_address("wpac", network_key, env_key)
        if not contract_address:
            utils.warn("Contract address not found for the selected network.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        try:
            utils.info(f"Fetching bridges from contract {contract_address}...")
            bridges = evm.dump_all_bridges(contract_address, rpc_endpoint)

            if not bridges:
                utils.warn("No bridges found.")
                input("\nPress Enter to return to WPAC Contract Tools menu...")
                return

            # Log total bridges count
            total_bridges = len(bridges)
            utils.info(f"Total Bridges: {total_bridges}")

            # Generate filename: bridges_{network}_{environment}.txt
            filename = f"bridges_{network_key}_{env_key}.txt"

            # Write bridges to file
            with open(filename, "w", encoding="utf-8") as f:
                # Write header information
                f.write("=" * 80 + "\n")
                f.write(f"Bridge Dump - {config.get_network_display_name(network_key)} ({environment})\n")
                f.write("=" * 80 + "\n")
                f.write(f"Smart Contract Address: {contract_address}\n")
                f.write(f"Network: {config.get_network_display_name(network_key)}\n")
                f.write(f"Environment: {environment}\n")
                f.write(f"Total Bridges: {total_bridges}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n")
                f.write("\n")

                # Write bridge data
                for bridge in bridges:
                    if "error" in bridge:
                        f.write(f"Bridge #{bridge['index']}: ERROR\n")
                        f.write(f"  Error: {bridge['error']}\n")
                    else:
                        f.write(f"Bridge #{bridge['index']}:\n")
                        f.write(f"  Sender: {bridge['sender']}\n")
                        f.write(f"  Amount: {bridge['amount']}\n")
                        f.write(f"  Destination Address: {bridge['destinationAddress']}\n")
                        f.write(f"  Fee: {bridge['fee']}\n")
                    f.write("\n")

            # Display summary
            print()
            print(utils.bold_cyan(f"[Bridge Dump] {config.get_network_display_name(network_key)} ({environment})"))
            print()
            print(utils.bold_yellow(f"Total Bridges: {total_bridges}"))
            print()
            print(utils.success(f"Bridges written to file: {utils.bold(filename)}"))
            print(f"Contract Address: {contract_address}")

        except Exception as e:
            print(e)
            return

        input("\nPress Enter to return to WPAC Contract Tools menu...")

    def transfer_native_coin(self) -> None:
        """Transfer native coin (ETH, MATIC, BNB, etc.) from one address to another."""
        environment = "Mainnet" if self.environment == "mainnet" else "Testnet"
        env_key = self.environment

        print()
        # Select network
        network = self.prompt_choice(
            "Select network",
            ["Ethereum", "Polygon", "BNB Smart Chain (BSC)", "Base"],
        )

        # Map network display name to network key
        network_map = {
            "Ethereum": "ethereum",
            "Polygon": "polygon",
            "BNB Smart Chain (BSC)": "bnb",
            "Base": "base",
        }
        network_key = network_map.get(network)
        if not network_key:
            utils.warn("Invalid network selection.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        # Get RPC endpoint
        rpc_endpoint = config.get_rpc_endpoint(network_key, env_key)
        if not rpc_endpoint:
            utils.warn("RPC endpoint not found for the selected network.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        print()
        from_address = input("Enter from address: ").strip()
        if not from_address:
            utils.warn("From address is required.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        # Show balance of from address
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_endpoint))
            if not w3.is_connected():
                utils.warn("Failed to connect to RPC endpoint.")
            else:
                balance_wei = w3.eth.get_balance(Web3.to_checksum_address(from_address))
                balance_ether = Web3.from_wei(balance_wei, "ether")
                native_symbol = config.get_network_display_name(network_key)
                print()
                print(f"{utils.bold('Balance:')} {utils.bold_yellow(f'{balance_ether} {native_symbol}')}")
        except Exception as e:
            utils.warn(f"Failed to fetch balance: {e}")

        print()
        to_address = input("Enter to address: ").strip()
        if not to_address:
            utils.warn("To address is required.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        print()
        amount_str = input("Enter amount (e.g., 0.1 for 0.1 ETH/MATIC/BNB): ").strip()
        if not amount_str:
            utils.warn("Amount is required.")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        try:
            amount_float = float(amount_str)
            # Convert to wei (1 ETH = 10^18 wei)
            amount_wei = int(amount_float * 1_000_000_000_000_000_000)
        except ValueError:
            utils.warn(f"Invalid amount: {amount_str}")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        # Select signing method
        print()
        sign_method = self.prompt_choice(
            "Select signing method",
            ["Trezor Hardware Wallet", "Private Key"],
        )

        use_trezor = sign_method == "Trezor Hardware Wallet"
        sender_privkey = None
        trezor_path = config.get_trezor_derivation_path()

        if use_trezor:
            print()
            trezor_path_input = input(f"Enter Trezor derivation path (default: {trezor_path}): ").strip()
            if trezor_path_input:
                trezor_path = trezor_path_input
            print()
            utils.info("Please connect and unlock your Trezor device...")
        else:
            print()
            # Check .env first
            sender_privkey = config.get_owner_private_key()
            if not sender_privkey:
                sender_privkey = input("Enter private key (hex format, with or without 0x): ").strip()
            if not sender_privkey:
                utils.warn("Private key is required.")
                input("\nPress Enter to return to WPAC Contract Tools menu...")
                return

        try:
            signed_tx = evm.create_native_transfer_transaction(
                from_address=from_address,
                to_address=to_address,
                amount_wei=amount_wei,
                sender_privkey=sender_privkey,
                rpc_endpoint=rpc_endpoint,
                use_trezor=use_trezor,
                trezor_path=trezor_path,
            )

            print()
            print(f"[Native Coin Transfer] {environment}")
            print(f"Network: {network}")
            print(f"From: {signed_tx['from']}")
            print(f"To: {signed_tx['to']}")
            print(f"Amount: {amount_str} {config.get_network_display_name(network_key)}")
            print(f"Transaction Hash: {utils.bold_cyan(signed_tx['transaction_hash'])}")
            print(f"Raw Transaction (hex): {signed_tx['raw_transaction']}")

            # Ask if user wants to broadcast
            print()
            if self.prompt_confirm("Broadcast transaction to blockchain? (y/N): "):
                try:
                    result = evm.send_transaction(signed_tx['raw_transaction'], rpc_endpoint)
                    print()
                    utils.success("Transaction broadcast successfully!")
                    print()
                    if 'transactionHash' in result:
                        print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(result['transactionHash'])}")
                    else:
                        print(f"{utils.bold('Transaction Hash:')} {utils.bold_cyan(signed_tx['transaction_hash'])}")
                except Exception as e:
                    error_msg = str(e)
                    print()
                    utils.warn("Failed to broadcast transaction via RPC endpoint.")
                    print()
                    if "txpool disabled" in error_msg or "stateless" in error_msg.lower():
                        print(utils.bold_yellow("⚠ RPC endpoint does not support sending transactions (stateless client)."))
                        print()
                        print("You can manually broadcast this transaction using:")
                        print(f"  {utils.bold_cyan('Raw Transaction (hex):')}")
                        print(f"  {signed_tx['raw_transaction']}")
                        print()
                        print("Options to broadcast:")
                        print("  1. Use a different RPC endpoint that supports transactions")
                        print("  2. Use a blockchain explorer's broadcast feature")
                        print("  3. Use a wallet that supports raw transaction broadcasting")
                    else:
                        print(f"Error: {error_msg}")
        except Exception as e:
            print()
            utils.warn(f"Failed to create transaction: {e}")
            input("\nPress Enter to return to WPAC Contract Tools menu...")
            return

        input("\nPress Enter to return to WPAC Contract Tools menu...")

    def exit_program(self) -> None:
        """Exit the program."""
        print("\nExiting Hitchcock. Goodbye!")
        self.should_exit = True


def main(environment: str = "testnet") -> int:
    """Main entry point."""
    cli = HitchcockCLI(environment)
    cli.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

