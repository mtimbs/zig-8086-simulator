#!/bin/bash
set -euo pipefail

INPUT="asm_examples/single_register_mov.asm"
OUTPUT="output.asm"

echo "Building ${INPUT}..."

nasm $INPUT

echo "Successfully built."

echo "Decoding built machine code."

zig run src/main.zig

echo "Decoded machine code to assembly. Output destination: ${OUTPUT}"

echo "Checking diff INPUT/OUTPUT....."

diff $INPUT $OUTPUT

echo "✅ Valid decoding "
