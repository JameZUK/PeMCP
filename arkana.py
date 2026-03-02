#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Arkana - AI-Powered Binary Analysis

This is the entry point wrapper. The actual implementation has been
modularized into the arkana/ package.

Usage:
    python arkana.py --input-file <file> [--mcp-server] [options]

See arkana/ package for the modular source code.
"""
from arkana.main import main

if __name__ == '__main__':
    main()
