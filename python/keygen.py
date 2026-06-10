#!/usr/bin/env python3
import os
key = os.urandom(32).hex()
print(f"export TINYVPN_KEY={key}")
print("\n# Run this on BOTH machines before starting tinyvpn")
