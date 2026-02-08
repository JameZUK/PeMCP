#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
PeMCP - Comprehensive PE File Analyzer with MCP Server

This is the entry point wrapper. The actual implementation has been
modularized into the pemcp/ package.

Usage:
    python PeMCP.py --input-file <file> [--mcp-server] [options]

See pemcp/ package for the modular source code.
"""
from pemcp.main import main

if __name__ == '__main__':
    main()
