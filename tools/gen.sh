#!/bin/sh
# regenerate the generated SLEIGH include files
cd "$(dirname "$0")/.." && python3 tools/gen_float.py
