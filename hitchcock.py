#!/usr/bin/env python3
"""Backward compatibility entry point for Hitchcock."""

import sys
from hitchcock.cli import main

if __name__ == "__main__":
    sys.exit(main())
