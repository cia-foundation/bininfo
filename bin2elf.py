#!/usr/bin/env python3

from dataclasses import dataclass
from pathlib import Path
import struct
import sys

import binfile

from makeelf.elf import ELF, ELFDATA, EM, ET, SHN, STB, STT

@dataclass
class HolyCFunctionDecl:
    name: str
    return_type: str
    num_args: int
    dynamic_import: bool

@dataclass
class HolyCVariableDecl:
    name: str
    type: str

declared_exports = dict()
declared_imports = dict()
suffixed = dict()

def parse_holyc_declaration(line):
    line = line.strip()

    # skip comments & empty lines
    if not line or line.startswith("//"):
        return None

    # strip trailing semicolon
    assert line[-1:] == ";"
    line = line[:-1]

    # is this a function definition?
    open_paren_index = line.find("(")

    if open_paren_index == -1:
        # just a variable
        type, name = line.split()
        # re-assign *
        while name.startswith("*"):
            type = type + name[:1]
            name = name[1:]

        return HolyCVariableDecl(name, type)
    else:
        assert line[-1:] == ")"

        defn = line[:open_paren_index]
        args_str = line[open_paren_index + 1:-1].strip()

        if defn.startswith("import "):
            defn = defn[7:]
            dynamic_import = True
        else:
            dynamic_import = False

        type, name = defn.split()
        # re-assign *
        while name.startswith("*"):
            type = type + name[:1]
            name = name[1:]

        if len(args_str):
            args = args_str.split(",")
        else:
            args = []

        return HolyCFunctionDecl(name,
                                 return_type=type,
                                 num_args=len(args),
                                 dynamic_import=dynamic_import)


def load_export_defs(path, f):
    for line_no, line in enumerate(f, start=1):
        try:
            decl = parse_holyc_declaration(line)
        except:
            raise Exception(f"parse error {path}:{line_no}")

        if decl is not None:
            declared_exports[decl.name] = decl


def load_import_defs(path, f):
    for line_no, line in enumerate(f, start=1):
        try:
            decl = parse_holyc_declaration(line)
        except:
            raise Exception(f"parse error {path}:{line_no}")

        if decl is not None:
            declared_imports[decl.name] = decl


def make_object(f, image, relocations, exports, main_symbol_name, section_name, symbol_suffix):
    elf = ELF(e_data=ELFDATA.ELFDATA2LSB, e_machine=EM.EM_X86_64, e_type=ET.ET_REL)

    bincode_id = elf.append_section(section_name, image, sec_addr=0)

    # If there are relocations, prepare a reference to the section
    if len(relocations):
        section_sym = elf.append_symbol(sym_name=None, sym_section=bincode_id, sym_offset=0, sym_size=0,
                sym_type=STT.STT_SECTION)

    # Add exported symbols
    for export in sorted(exports, key=lambda e: e.address):
        if export.type == binfile.Etype.IET_MAIN:
            if main_symbol_name is None:
                continue

            symbol_name = main_symbol_name + symbol_suffix
        else:
            # Is the symbol a variable? We cannot tell from the BIN file, but it may have been specified in ExportDefs.HH.
            name_str = export.name.decode(errors="replace")
            if name_str in declared_exports and isinstance(declared_exports[name_str], HolyCVariableDecl):
                # In that case, do not apply mangling in order to make the variable visible in C code
                symbol_name = export.name
            else:
                # By default, we mangle
                symbol_name = export.name + symbol_suffix

        suffixed[export.name] = symbol_name

        elf.append_symbol(symbol_name, sym_section=bincode_id, sym_offset=export.address,
                sym_size=0, sym_binding=STB.STB_GLOBAL)

    # Convert relocations
    R_X86_64_PC32 = 2
    R_X86_64_32 = 10

    MAX_EXPECTED_16BIT_CODE_SIZE = 8 * 1024
    MAX_EXPECTED_IMAGE_SIZE = 1024 * 1024

    for reloc in sorted(relocations, key=lambda r: r.address):
        if reloc.type == binfile.Etype.IET_ABS_ADDR:
            assert reloc.symbol is None

            # extract addend from image
            addend, = struct.unpack("<I", image[reloc.address:reloc.address + 4])

            # Ignore nonsense relocations in 16-bit code until TempleRt is fixed
            if reloc.address < MAX_EXPECTED_16BIT_CODE_SIZE and addend > MAX_EXPECTED_IMAGE_SIZE:
                print(f"Warning: ignoring big addend {addend:08X}h for {reloc.type} @ {reloc.address:08X}h")
                continue

            elf.append_reloc(sec_name=section_name, r_offset=reloc.address, type=R_X86_64_32,
                    sym=section_sym, r_addend=addend)

            # zero out the location; probably not necessary, just to reduce confusion
            image[reloc.address:reloc.address + 4] = b"\0\0\0\0"
        elif reloc.type == binfile.Etype.IET_IMM_U32:
            assert reloc.symbol is not None

            symbol_name = reloc.symbol + symbol_suffix
            # TODO: cache symbol entries
            sym = elf.append_symbol(symbol_name, sym_section=SHN.SHN_UNDEF, sym_offset=0, sym_size=0,
                    sym_binding=STB.STB_GLOBAL)

            elf.append_reloc(sec_name=section_name, r_offset=reloc.address, type=R_X86_64_32,
                    sym=sym, r_addend=0)

            # zero out the location; probably not necessary, just to reduce confusion
            image[reloc.address:reloc.address + 4] = b"\0\0\0\0"
        elif reloc.type == binfile.Etype.IET_REL_I32:
            assert reloc.symbol is not None

            symbol_name = reloc.symbol + symbol_suffix
            # TODO: cache symbol entries
            sym = elf.append_symbol(symbol_name, sym_section=SHN.SHN_UNDEF, sym_offset=0, sym_size=0,
                    sym_binding=STB.STB_GLOBAL)

            # the relocaction is computed against the PC following the instruction,
            # so we need to subtract 4 bytes
            elf.append_reloc(sec_name=section_name, r_offset=reloc.address, type=R_X86_64_PC32,
                    sym=sym, r_addend=-4)

            # zero out the location; probably not necessary, just to reduce confusion
            image[reloc.address:reloc.address + 4] = b"\0\0\0\0"
        else:
            raise Exception(f"Relocation not handled: {reloc}")

    f.write(bytes(elf))


def make_export_thunks(f, exports, symbol_suffix):
    for _, defn in sorted(exports.items()):
        if not isinstance(defn, HolyCFunctionDecl):
            # Nothing to do here for variables -- if it has been exported with a suffix, we cannot rename it with a thunk
            # Therefore, variables are handled differently (earlier)
            continue

        thunk_name = defn.name
        suffixed_name = defn.name + symbol_suffix

        num_args = defn.num_args

        # TODO: which registers need to be saved? seems only RBX
        f.write(f"""
.section    .text.{thunk_name}
.type       {thunk_name}, %function  
.global     {thunk_name}

{thunk_name}:
    push %rbx
""")

        if num_args >= 3:
            raise Exception("Too many arguments, not implemented")

        if num_args >= 2:
            f.write("    push %rsi\n")

        if num_args >= 1:
            f.write("    push %rdi\n")

        f.write(f"""
    call {suffixed_name}
    /* callee cleans up stack */

    pop %rbx

    ret

    .size {thunk_name}, .-{thunk_name}
""")


def make_import_thunks(f, imports, symbol_suffix):
    for _, defn in sorted(imports.items()):
        if not isinstance(defn, HolyCFunctionDecl):
            continue

        thunk_name = defn.name + symbol_suffix
        plain_name = defn.name

        if defn.dynamic_import:
            resolve_import_func = "ResolveJitImport" + symbol_suffix
            # For imports of JIT-compiled functions the following HolyC helper function is needed:
            #   U8* ResolveJitImport(U8* thunk_addr, U8* func_name)
            # The imported function is resolved and its address returned, so we jump to RAX afterwards.
            # In addition, the helper may patch the thunk with a direct jump to the resolved function.
            #
            # On failure the helper should just abort the program, as there is not much meaningful recovery possible.
            f.write(f"""
.section    .text.{thunk_name}
.type       {thunk_name}, %function
.global     {thunk_name}

{thunk_name}:
    push $_s_{plain_name}
    lea {thunk_name}(%rip), %rax
    push %rax
    call {resolve_import_func}
    jmp *%rax

_s_{plain_name}:
    .asciz "{plain_name}"

    .size {thunk_name}, .-{thunk_name}
""")
        else:
            num_args = defn.num_args

            f.write(f"""
.section    .text.{thunk_name}
.type       {thunk_name}, %function  
.global     {thunk_name}

{thunk_name}:
    push %rdi
    push %rsi
    push %r10
    push %r11
""")

            if num_args >= 1:
                f.write("    mov 40(%rsp), %rdi\n")
            
            if num_args >= 2:
                f.write("    mov 48(%rsp), %rsi\n")

            if num_args >= 3:
                raise Exception("Too many arguments, not implemented")

            f.write(f"""
    call {plain_name}

    pop %r11
    pop %r10
    pop %rsi
    pop %rdi

    retq ${num_args * 8}

    .size {thunk_name}, .-{thunk_name}
""")


def write_export_table(f, exports, suffixed: dict):
    for export in sorted([e for e in exports if e.type != binfile.Etype.IET_MAIN], key=lambda e: e.name):
        try:
            name = export.name.decode()
            suffixed_name = suffixed[export.name].decode()
        except UnicodeDecodeError:
            print(f"Warning: skipping export generation for broken symbol name {export.name}")
            continue

        if not len(name):
            print(f"Warning: skipping export generation for anonymous symbol at {export.addr}")
            continue

        f.write(f'''
    .asciz "{name}"
    .4byte {suffixed_name}
''')

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert TempleOS BIN files to relocatable ELF objects")
    parser.add_argument("binfile", type=Path,
            help="Input in TempleOS BIN format")
    parser.add_argument("-o", dest="output", type=Path,
            help="Output name file name")
    parser.add_argument("--export-defs", dest="export_defs", type=Path,
            help="Provide HolyC definitions for thunk generation and name mangling")
    parser.add_argument("--import-defs", dest="import_defs", type=Path,
            help="Provide HolyC definitions for thunk generation and name mangling")
    parser.add_argument("--thunks-out", dest="thunks_output", type=Path,
            help="File where thunk assembly code will be written (in GNU as format)")
    parser.add_argument("--export-table-out", dest="export_table_output", type=Path,
            help="Generate an export table (in GNU as format) that can be linked into the program to get a list of symbols at runtime")
    parser.add_argument("--export-main",
            help="Export entry (IET_MAIN) as the specified name")
    parser.add_argument("--elf-section", default=".text")
    parser.add_argument("--symbol-suffix", default="$HolyC")
    args = parser.parse_args()

    with open(args.binfile, "rb") as f:
        image, relocations, exports = binfile.parse(f)

    if args.export_defs is not None:
        with open(args.export_defs, "rt") as f:
            load_export_defs(args.export_defs, f)

    if args.import_defs is not None:
        with open(args.import_defs, "rt") as f:
            load_import_defs(args.import_defs, f)

    if args.output is not None:
        with open(args.output, "wb") as f:
            make_object(f, image, relocations, exports,
                        main_symbol_name=args.export_main.encode() if args.export_main is not None else None,
                        section_name=args.elf_section.encode(),
                        symbol_suffix=args.symbol_suffix.encode())

    if args.thunks_output is not None:
        with open(args.thunks_output, "wt") as f:
            f.write("""/* This file is automatically generated -- do not edit! */
""")

            make_import_thunks(f, declared_imports, symbol_suffix=args.symbol_suffix)
            make_export_thunks(f, declared_exports, symbol_suffix=args.symbol_suffix)

    if args.export_table_output is not None:
        with open(args.export_table_output, "wt") as f:
            f.write("""/* This file is automatically generated -- do not edit! */

.section .holyc_sym, "a", @progbits
""")

            write_export_table(f, exports, suffixed=suffixed)
