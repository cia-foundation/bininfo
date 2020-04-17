#!/usr/bin/env python3

from collections import namedtuple
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import struct


class Etype(Enum):
    IET_END                = 0
    IET_REL_I0             = 2
    IET_IMM_U0             = 3
    IET_REL_I8             = 4
    IET_IMM_U8             = 5
    IET_REL_I16            = 6
    IET_IMM_U16            = 7
    IET_REL_I32            = 8
    IET_IMM_U32            = 9
    IET_REL_I64            = 10
    IET_IMM_I64            = 11
    IET_REL32_EXPORT       = 16
    IET_IMM32_EXPORT       = 17
    IET_REL64_EXPORT       = 18
    IET_IMM64_EXPORT       = 19
    IET_ABS_ADDR           = 20
    IET_CODE_HEAP          = 21
    IET_ZEROED_CODE_HEAP   = 22
    IET_DATA_HEAP          = 23
    IET_ZEROED_DATA_HEAP   = 24
    IET_MAIN               = 25


@dataclass(frozen=True)
class Export:
    type: Etype
    name: bytes
    address: int


@dataclass(frozen=True)
class Relocation:
    type: Etype
    symbol: Optional[bytes]
    address: int


CBinFile = struct.Struct("<2sBB4sqqq")
BinFileHeader = namedtuple(
    "BinFileHeader",
    "jmp module_align_bits reserved bin_signature org patch_table_offset file_size",
)


# Read zero-terminated string. Return string & length including terminator.
def read_string(bytes_slice):
    terminator_pos = bytes_slice.find(b"\0")
    assert terminator_pos >= 0

    # If input is bytearray, make an immutable copy
    return bytes(bytes_slice[:terminator_pos]), terminator_pos + 1


def parse_patch_table(binfile, patch_table_offset):
    pos = patch_table_offset

    relocations = set()
    exports = set()

    last_etype, last_symbol = None, None

    while binfile[pos]:
        etype, value = struct.unpack("<BI", binfile[pos : pos + 5])
        pos += 5

        symbol_name, len_ = read_string(binfile[pos:])
        pos += len_

        if symbol_name == b"":
            symbol_name = None

        etype = Etype(etype)

        if etype == Etype.IET_ABS_ADDR:
            for j in range(value):
                (address,) = struct.unpack("<I", binfile[pos : pos + 4])
                pos += 4

                relocations.add(Relocation(etype, None, address))
        elif etype in {Etype.IET_REL32_EXPORT}:
            exports.add(Export(etype, symbol_name, value))
        elif etype in {Etype.IET_IMM_U32, Etype.IET_REL_I32}:
            if symbol_name is None:
                assert etype is last_etype and last_symbol is not None
                symbol_name = last_symbol

            relocations.add(Relocation(etype, symbol_name, value))
        elif etype == Etype.IET_MAIN:
            assert symbol_name is None

            exports.add(Export(etype, symbol_name, value))
        else:
            raise Exception(f"Unhandled etype {Etype(etype)}")

        last_etype, last_symbol = etype, symbol_name

    return relocations, exports


def parse(f, verbose=False):
    b = f.read(CBinFile.size)
    bfh = BinFileHeader._make(CBinFile.unpack(b))

    assert bfh.bin_signature == b"TOSB"
    assert bfh.module_align_bits >= 0 and bfh.module_align_bits < 64

    module_align = 1 << bfh.module_align_bits

    if verbose:
        print("BIN header:")
        print(f"    jmp                 [{bfh.jmp[0]:02X} {bfh.jmp[1]:02X}]h")
        print(f"    alignment           {module_align} byte(s)")
        print(f"    org                 {bfh.org:016X} ({bfh.org})")
        print(f"    patch_table_offset  {bfh.patch_table_offset:016X} ({bfh.patch_table_offset})")
        print(f"    file_size           {bfh.file_size:016X} ({bfh.file_size})")
        print()

    image_size = bfh.file_size - CBinFile.size
    image = bytearray(f.read(image_size))
    assert len(image) == image_size

    relocations, exports = parse_patch_table(image, bfh.patch_table_offset - CBinFile.size)

    return image, relocations, exports


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser()
    parser.add_argument("binfile", type=Path)
    args = parser.parse_args()

    print("binfile", args.binfile.name)
    print()

    with open(args.binfile, "rb") as f:
        image, relocations, exports = parse(f, verbose=True)
