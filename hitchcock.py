#!/usr/bin/env python3
"""Backward compatibility entry point for Hitchcock."""

import argparse
import sys
from hitchcock.cli import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hitchcock CLI")
    parser.add_argument(
        "--testnet",
        action="store_true",
        help="Use testnet environment"
    )
    parser.add_argument(
        "--mainnet",
        action="store_true",
        help="Use mainnet environment"
    )

    args = parser.parse_args()

    # Determine environment: default to testnet if neither flag is set
    if args.testnet and args.mainnet:
        print("Error: Cannot specify both --testnet and --mainnet")
        sys.exit(1)

    environment = "mainnet" if args.mainnet else "testnet"

    sys.exit(main(environment))
