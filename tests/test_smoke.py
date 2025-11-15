#!/usr/bin/env python3
"""Smoke tests for Hitchcock to verify basic functionality."""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_imports():
    """Test that all modules can be imported."""
    try:
        import config
        from hitchcock import cli, evm, models, pactus, utils
        print("✓ All modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error during import: {e}")
        return False


def test_cli_initialization():
    """Test that CLI can be initialized."""
    try:
        from hitchcock.cli import HitchcockCLI
        cli = HitchcockCLI()
        assert hasattr(cli, 'actions')
        assert hasattr(cli, 'run')
        print("✓ CLI initialized successfully")
        return True
    except Exception as e:
        print(f"✗ CLI initialization error: {e}")
        return False


def test_evm_functions():
    """Test that EVM functions are callable."""
    try:
        from hitchcock import evm
        assert callable(evm.generate_credentials)
        assert callable(evm.derive_address_from_private_key)
        assert callable(evm.get_wpac_info)
        assert callable(evm.create_set_minter_transaction)
        assert callable(evm.create_set_fee_collector_transaction)
        print("✓ EVM functions are callable")
        return True
    except Exception as e:
        print(f"✗ EVM functions test error: {e}")
        return False


def test_pactus_functions():
    """Test that Pactus functions are callable."""
    try:
        from hitchcock import pactus
        assert callable(pactus.setup_hrp)
        assert callable(pactus.generate_credentials)
        assert callable(pactus.derive_address_from_private_key)
        assert callable(pactus.get_account_balance)
        assert callable(pactus.create_and_sign_wrap_tx)
        print("✓ Pactus functions are callable")
        return True
    except Exception as e:
        print(f"✗ Pactus functions test error: {e}")
        return False


def test_utils_functions():
    """Test that utility functions are callable."""
    try:
        from hitchcock import utils
        assert callable(utils.print_banner)
        assert callable(utils.error)
        assert callable(utils.warn)
        assert callable(utils.info)
        assert callable(utils.success)
        assert callable(utils.result)
        print("✓ Utility functions are callable")
        return True
    except Exception as e:
        print(f"✗ Utility functions test error: {e}")
        return False


def test_config():
    """Test that config module is accessible."""
    try:
        import config
        assert hasattr(config, 'CONTRACTS')
        assert hasattr(config, 'WRAPTO_ADDRESSES')
        assert callable(config.get_contract_address)
        assert callable(config.get_rpc_endpoint)
        assert callable(config.get_wrapto_address)
        print("✓ Config module is accessible")
        return True
    except Exception as e:
        print(f"✗ Config test error: {e}")
        return False


def test_entry_point():
    """Test that the main entry point can be imported."""
    try:
        from hitchcock.cli import main
        assert callable(main)
        print("✓ Main entry point is callable")
        return True
    except Exception as e:
        print(f"✗ Entry point test error: {e}")
        return False


def run_all_tests():
    """Run all smoke tests."""
    print("=" * 60)
    print("Running Hitchcock Smoke Tests")
    print("=" * 60)
    print()

    tests = [
        test_imports,
        test_cli_initialization,
        test_evm_functions,
        test_pactus_functions,
        test_utils_functions,
        test_config,
        test_entry_point,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
            print()
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            results.append(False)
            print()

    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 60)

    if all(results):
        print("✓ All smoke tests passed!")
        return 0
    else:
        print("✗ Some smoke tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())

