#!/usr/bin/env python3
"""Verify the runtime certificate signature against a decompressed Splatoon 3 main."""

import argparse
import struct
from pathlib import Path

SIGNATURE = bytes.fromhex(
    "1F2003D5 00000000 1F2003D5 00000000 000300AA 21008052 5F010071"
)
MASK = bytes.fromhex(
    "FFFFFFFF 00000000 FFFFFFFF 00000000 00FF00FF FFFFFFFF FFFFFFFF"
)
MOV_W10_TRUE = 0x5280002A
LDRB_W10_MASK = 0xFFC0001F
LDRB_W10_VALUE = 0x3940000A


def matches(candidate: bytes) -> bool:
    return all(not mask or actual == expected for actual, expected, mask in zip(candidate, SIGNATURE, MASK))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("main_dec", type=Path, help="decompressed NSO memory image")
    args = parser.parse_args()

    image = args.main_dec.read_bytes()
    matches_at = [
        offset - 4
        for offset in range(4, len(image) - len(SIGNATURE) + 1, 4)
        if matches(image[offset : offset + len(SIGNATURE)])
    ]

    if len(matches_at) != 1:
        print(f"ERROR: expected one signature match, found {len(matches_at)}")
        return 1

    target = matches_at[0]
    instruction = struct.unpack_from("<I", image, target)[0]
    if instruction != MOV_W10_TRUE and instruction & LDRB_W10_MASK != LDRB_W10_VALUE:
        print(f"ERROR: target 0x{target:X} has unexpected instruction 0x{instruction:08X}")
        return 1

    state = "already patched" if instruction == MOV_W10_TRUE else "patchable LDRB W10"
    print(f"OK: target=0x{target:X} instruction=0x{instruction:08X} ({state})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
