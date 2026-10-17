import bisect
import re
import struct
from typing import Dict, List, Optional, Set, TextIO, Tuple

from iced_x86 import (
    Decoder,
    DecoderOptions,
    Formatter,
    FormatterSyntax,
    MemorySizeOptions,
    MemorySizeExt,
    Mnemonic,
    OpKind,
    Register,
)

from ...platforms import win32
from ...disassembler.iced_x86_disassembler import SCALAR_SIZES
from ...util import log, symbols

PREFIXES = {0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67}
LOAD_FORMS = {
    0x02,
    0x03,
    0x0A,
    0x0B,
    0x12,
    0x13,
    0x1A,
    0x1B,
    0x22,
    0x23,
    0x2A,
    0x2B,
    0x32,
    0x33,
    0x3A,
    0x3B,
    0x8A,
    0x8B,
}
STORE_FORMS_0F = {0x11, 0x29, 0x7F, 0xD6}
ACCUMULATOR = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D, 0xA9}
STRING_OPS = ("movs", "stos", "lods", "scas", "cmps")
LOCKABLE = {
    "add",
    "adc",
    "and",
    "btc",
    "btr",
    "bts",
    "cmpxchg",
    "cmpxchg8b",
    "dec",
    "inc",
    "neg",
    "not",
    "or",
    "sbb",
    "sub",
    "xadd",
    "xchg",
    "xor",
}
STATE_OPS = {
    "fnsave",
    "fsave",
    "frstor",
    "fnstenv",
    "fstenv",
    "fldenv",
    "fxsave",
    "fxrstor",
}
# GAS cannot reliably reproduce these encodings
UNSUPPORTED = {
    "enter",
    "salc",
    "fnstdw",
    "fnstsg",
    "fstpnce",
    "feni8087_nop",
    "fdisi8087_nop",
    "fsetpm287_nop",
    "ud0",
    "ud1",
    "int1",
    "fstp1",
    "ffreep",
    "les",
    "lds",
    "lss",
    "lfs",
    "lgs",
    "bound",
    "arpl",
    "daa",
    "das",
    "aaa",
    "aas",
    "aam",
    "aad",
    "into",
    "in",
    "out",
    "insb",
    "insw",
    "insd",
    "outsb",
    "outsw",
    "outsd",
    "hlt",
    "iretd",
    "iret",
    "ljmp",
    "lcall",
    "retf",
}
HEX = re.compile(r"0x[0-9a-f]+")
PLAIN = re.compile(r"^[A-Za-z_.$][A-Za-z0-9_.$@]*$")
# Don't treat these directories as arrays of pointers
RAW_DIRECTORIES = (win32.DIR_IMPORT, win32.DIR_RESOURCE, win32.DIR_DEBUG, win32.DIR_IAT)
X87_ALIASES = {
    0xD9: (3,),
    0xDC: (2, 3),
    0xDD: (1,),
    0xDE: (2,),
    0xDF: (1, 2, 3),
}


def merged_ranges(ranges: List[Tuple[int, int]]):
    merged: List[Tuple[int, int]] = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return merged, [low for low, _ in merged]


def range_end(va, ranges, starts):
    index = bisect.bisect_right(starts, va) - 1
    if index >= 0 and va < ranges[index][1]:
        return ranges[index][1]
    return None


def signed(value: int, size: int) -> int:
    value &= (1 << size * 8) - 1
    return value - (1 << size * 8) if value >> (size * 8 - 1) else value


def quote(name: str) -> str:
    if PLAIN.fullmatch(name):
        return name
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def alignment(start: int, end: int) -> int:
    # GAS pads the section size to this alignment
    return min(16, start & -start, end & -end)


def hex_bytes(data: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def encoding_prefix(insn, raw, offsets, formatter, count: int) -> Optional[str]:
    """Return GAS prefixes for this encoding, or None to emit bytes."""
    prefixes = raw[:count]
    repeat = next((value for value in prefixes if value in (0xF0, 0xF2, 0xF3)), 0)
    segment = next(
        (value for value in prefixes if value in (0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65)),
        0,
    )
    operand_size = 0x66 in prefixes
    address_size = 0x67 in prefixes
    mnemonic = formatter.format_mnemonic(insn).split()[-1]
    opcode = raw[count]
    # Keep VEX prefixes and address-size overrides unchanged
    if address_size or opcode in (0xC4, 0xC5, 0x62) or mnemonic in UNSUPPORTED:
        return None
    second = raw[count + 1] if opcode == 0x0F else None
    metadata = insn.op_code()
    has_modrm = 0xD8 <= opcode <= 0xDF or bool(
        re.search(r"/[r0-7]", metadata.op_code_string)
    )
    modrm_offset = count + (2 if second is not None else 1)
    if second in (0x38, 0x3A):
        modrm_offset += 1
    modrm = raw[modrm_offset] if has_modrm else 0
    mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
    sib = raw[modrm_offset + 1] if has_modrm and mod != 3 and rm == 4 else 0
    xmm = any(
        insn.op_kind(index) == OpKind.REGISTER
        and Register.XMM0 <= insn.op_register(index) <= Register.XMM31
        for index in range(insn.op_count)
    )
    words = metadata.operand_size == 16 or mnemonic in ("cbw", "cwd")
    immediate = int.from_bytes(
        raw[
            offsets.immediate_offset : offsets.immediate_offset + offsets.immediate_size
        ],
        "little",
    )
    displacement = signed(insn.memory_displacement, 4)
    # GAS clears unused SETcc ModRM bits
    if second is not None and 0x90 <= second <= 0x9F and reg:
        return None
    # Keep segment overrides on string instructions
    if segment and mnemonic.startswith(STRING_OPS) and 0xA4 <= opcode <= 0xAF:
        return None
    expected = (repeat != 0) + (segment != 0) + operand_size
    if count != expected:
        return None
    if segment and (
        mnemonic == "lea"
        or not (
            segment in (0x64, 0x65)
            and ("fs:" if segment == 0x64 else "gs:")
            in formatter.format_all_operands(insn)
        )
    ):
        return None
    if operand_size and (not (xmm or words) or opcode in (0x8C, 0x8E)):
        return None
    if operand_size and (
        0xD8 <= opcode <= 0xDF
        or opcode in (0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x68, 0x6A, 0xC2, 0xC3)
    ):
        return None
    if repeat == 0xF0 and (
        mnemonic not in LOCKABLE or not insn.op_count or insn.op0_kind != OpKind.MEMORY
    ):
        return None
    if repeat in (0xF2, 0xF3) and not (
        xmm or mnemonic.startswith(STRING_OPS) or mnemonic == "pause" or opcode == 0x0F
    ):
        return None
    if has_modrm and mod != 3 and rm == 4:
        base, index, scale = sib & 7, (sib >> 3) & 7, sib >> 6
        if (
            index == 4
            and (base != 4 or scale)
            or mod == 0
            and base == 5
            and index != 4
            and scale == 0
        ):
            return None
    # Undocumented x87 register aliases assemble to their canonical opcodes
    if mod == 3 and reg in X87_ALIASES.get(opcode, ()):
        return None
    if second is None and has_modrm:
        if opcode in (0xF6, 0xF7) and (reg == 1 or reg == 0 and mod == 3 and rm == 0):
            return None
        if (
            opcode in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3)
            and reg == 6
            or opcode == 0x82
        ):
            return None
        if mod == 3 and (
            opcode == 0xFF
            and reg in (0, 1, 6)
            or opcode in (0x8F, 0xC6, 0xC7)
            and reg == 0
        ):
            return None
        if mod == 3 and (
            opcode in (0x80, 0x81)
            and rm == 0
            or opcode == 0x87
            and 0 in (rm, reg)
            or opcode in (0xDC, 0xDE)
            and rm == 0
        ):
            return None
    if (
        opcode in ACCUMULATOR or opcode in (0x81, 0x69, 0x68)
    ) and offsets.immediate_size in (2, 4):
        if -128 <= signed(immediate, offsets.immediate_size) <= 127:
            return None
    if (
        opcode in (0xC0, 0xC1)
        and immediate == 1
        or opcode in (0x88, 0x89, 0x8A, 0x8B)
        and mod == 0
        and rm == 5
        and reg == 0
    ):
        return None
    if opcode == 0xC2 and immediate == 0 or opcode == 0xCD and immediate == 3:
        return None
    if (
        mnemonic == "nop"
        and insn.op_count
        or opcode in (0x9A, 0xEA)
        or opcode == 0xFF
        and reg in (3, 5)
    ):
        return None
    prefix = ""
    if second is None and has_modrm and mod == 3 and opcode in LOAD_FORMS:
        prefix = "{load} "
    elif second in STORE_FORMS_0F and mod == 3:
        prefix = "{store} "
    if (
        offsets.displacement_size == 1
        and displacement == 0
        and mod == 1
        and not (rm == 5 or rm == 4 and sib & 7 == 5)
    ):
        prefix += "{disp8} "
    elif offsets.displacement_size == 4 and -128 <= displacement <= 127 and mod == 2:
        prefix += "{disp32} "
    return prefix


class Program:
    def __init__(self):
        pe = win32.info
        if pe.is_pe32_plus:
            log.error("Win32 disassembly only supports PE32 (i386)")
        self.image = win32.raw_image
        self.sections = sorted(
            (
                (pe.image_base + section.virtual_address, section)
                for section in pe.sections
                if section.virtual_size or section.raw_size
            ),
            key=lambda item: item[0],
        )
        if not self.sections:
            log.error("No sections to disassemble")
        self.starts = [va for va, _ in self.sections]
        self.start = self.starts[0]
        self.end = max(
            va + max(section.virtual_size, section.raw_size)
            for va, section in self.sections
        )
        declared_symbols = symbols.get_all_symbols()
        self.names: Dict[int, List[str]] = {}
        for symbol in declared_symbols:
            self.names.setdefault(symbol.vram_start, []).append(symbol.name)

        self.literal_ranges = []
        self.scalar_ranges = []
        self.nonreferenceable: Set[int] = set()
        self.reference_ranges = sorted(
            (symbol.vram_start, symbol.vram_start + symbol.given_size)
            for symbol in declared_symbols
            if symbol.given_size is not None and symbol.given_size > 0
        )
        self.reference_starts = [low for low, _ in self.reference_ranges]
        self.reference_limits = []
        limit = 0
        for _, high in self.reference_ranges:
            limit = max(limit, high)
            self.reference_limits.append(limit)
        for symbol in declared_symbols:
            scalar_size = SCALAR_SIZES.get(symbol.type)
            size = (
                symbol.given_size if symbol.given_size is not None else scalar_size or 4
            )
            span = (symbol.vram_start, symbol.vram_start + size)
            if symbol.can_reference is False:
                self.literal_ranges.append(span)
                if scalar_size:
                    self.scalar_ranges.append(span)
            if symbol.can_be_referenced is False:
                self.nonreferenceable.add(symbol.vram_start)
        self.literal_ranges, self.literal_starts = merged_ranges(self.literal_ranges)
        self.scalar_ranges, self.scalar_starts = merged_ranges(self.scalar_ranges)
        self.sizes: Dict[int, bytearray] = {}
        self.inner: Dict[int, bytearray] = {}
        self.functions: Set[int] = set()
        self.calls: Set[int] = set()
        self.code_labels: Set[int] = set()
        self.labels: Set[int] = set()
        self.data: Set[int] = set()
        self.tables: Dict[int, int] = {}
        self.byte_tables: Set[int] = set()
        self.jumps: List[Tuple[int, int]] = []
        self.raw_ranges = []
        for index in RAW_DIRECTORIES:
            rva, size = pe.get_data_directory(index)
            if rva:
                found = self.section(pe.image_base + rva)
                if found is None:
                    continue
                start, section = found
                # Import and resource data can extend past the directory size
                self.raw_ranges.append(
                    (
                        pe.image_base + rva,
                        start + section.virtual_size
                        if index in (win32.DIR_IMPORT, win32.DIR_RESOURCE)
                        else pe.image_base + rva + size,
                    )
                )
        self.formatter = Formatter(FormatterSyntax.MASM)
        self.formatter.hex_prefix = "0x"
        self.formatter.hex_suffix = ""
        self.formatter.uppercase_hex = False
        self.formatter.small_hex_numbers_in_decimal = False
        self.formatter.add_leading_zero_to_hex_numbers = False
        self.formatter.space_after_operand_separator = True
        self.formatter.space_between_memory_add_operators = True
        self.formatter.memory_size_options = MemorySizeOptions.ALWAYS
        self.formatter.show_branch_size = False
        self.formatter.use_pseudo_ops = False
        self.formatter.masm_add_ds_prefix32 = False
        self.formatter.masm_displ_in_brackets = True
        self.formatter.prefer_st0 = True
        references: Set[int] = set()
        for start, section in self.sections:
            references |= (
                self.sweep(start, section)
                if section.is_code
                else self.scan(start, section)
            )
        if pe.entry_point_rva and self.is_instruction(pe.entry_point_va):
            self.functions.add(pe.entry_point_va)
        self.functions |= {
            target for target in self.calls if self.is_instruction(target)
        }
        self.functions |= {
            symbol.vram_start
            for symbol in declared_symbols
            if symbol.type == "func" and self.is_instruction(symbol.vram_start)
        }
        for target in references:
            found = self.section(target)
            if found is not None and not found[1].is_code:
                self.data.add(target)
            elif self.is_instruction(target) and target not in self.functions:
                self.code_labels.add(target)
        # Jumps between functions need global labels when split into separate files
        starts = sorted(self.functions)
        for source, target in self.jumps:
            if target not in self.functions and self.is_instruction(target):
                if bisect.bisect_right(starts, source) != bisect.bisect_right(
                    starts, target
                ):
                    self.code_labels.add(target)

    def section(self, va: int):
        index = bisect.bisect_right(self.starts, va) - 1
        if index >= 0:
            start, section = self.sections[index]
            if va < start + max(section.virtual_size, section.raw_size):
                return start, section
        return None

    def raw_data(self, section) -> bytes:
        if section.raw_size and section.raw_pointer + section.raw_size > len(
            self.image
        ):
            log.error(f"Section '{section.name}' extends past the end of the file")
        return self.image[section.raw_pointer : section.raw_pointer + section.raw_size]

    def is_instruction(self, va: int) -> bool:
        found = self.section(va)
        if found is None:
            return False
        sizes = self.sizes.get(found[0])
        offset = va - found[0]
        return sizes is not None and offset < len(sizes) and sizes[offset] != 0

    def is_inner(self, va: int) -> bool:
        found = self.section(va)
        if found is None:
            return False
        inner = self.inner.get(found[0])
        offset = va - found[0]
        return inner is not None and offset < len(inner) and inner[offset] != 0

    def raw(self, va: int) -> bool:
        return any(low <= va < high for low, high in self.raw_ranges)

    def literal(self, va: int) -> bool:
        return range_end(va, self.literal_ranges, self.literal_starts) is not None

    def reference_name(self, va: int) -> Optional[str]:
        if va in self.names:
            return None if va in self.nonreferenceable else self.name(va)
        index = bisect.bisect_right(self.reference_starts, va) - 1
        while index >= 0 and va < self.reference_limits[index]:
            low, high = self.reference_ranges[index]
            if low < va < high:
                if low in self.nonreferenceable:
                    return None
                return f"{quote(self.names[low][-1])} + 0x{va - low:X}"
            index -= 1
        return self.name(va)

    def padding(self, data: bytes, offset: int) -> Optional[int]:
        if offset < len(data) and data[offset] != 0xCC:
            return None
        end = offset
        while end < len(data) and data[end] == 0xCC:
            end += 1
        return end if end == len(data) or end % 16 == 0 else None

    def sweep(self, start: int, section) -> Set[int]:
        raw_data = self.raw_data(section)
        data = raw_data[: section.virtual_size or section.raw_size]
        sizes = self.sizes[start] = bytearray(len(raw_data))
        inner = self.inner[start] = bytearray(len(raw_data))
        references: Set[int] = set()
        pending: Dict[int, int] = {}
        function = start
        offset = 0
        self.functions.add(start)
        while offset < len(data):
            va = start + offset
            scalar_end = range_end(va, self.scalar_ranges, self.scalar_starts)
            if scalar_end is not None:
                offset = min(scalar_end - start, len(data))
                continue
            if va in pending:
                count = self.read_table(va, pending.pop(va), data, start)
                for index in range(count * 4):
                    inner[offset + index] = index & 3 != 0
                offset += count * 4
                if count:
                    continue
            padding_end = self.padding(data, offset)
            if padding_end is not None:
                offset = padding_end
                function = start + offset
                if offset < len(data):
                    self.functions.add(function)
                continue
            if va in self.byte_tables:
                offset += 1
                while (
                    offset < len(data)
                    and start + offset not in pending
                    and self.padding(data, offset) is None
                ):
                    offset += 1
                continue
            if not any(data[offset : offset + 16]):
                offset += 1
                continue
            stop = (
                min(
                    (table for table in pending if table > va),
                    default=start + len(data),
                )
                - start
            )
            scalar_index = bisect.bisect_right(self.scalar_starts, va)
            if scalar_index < len(self.scalar_starts):
                stop = min(stop, self.scalar_starts[scalar_index] - start)
            decoded = False
            for instruction in self.decode(
                data[offset : min(stop, offset + 0x1000)], va
            ):
                if instruction.is_invalid:
                    break
                decoded = True
                address, size = instruction.ip, instruction.len
                sizes[offset] = size
                inner[offset + 1 : offset + size] = b"\1" * (size - 1)
                offset += size
                target = (
                    instruction.near_branch_target
                    if instruction.op0_kind
                    in (OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32)
                    else None
                )
                if target is not None and instruction.is_call_near:
                    self.calls.add(target)
                elif target is not None:
                    self.labels.add(target)
                    self.jumps.append((address, target))
                else:
                    table = None
                    if (
                        instruction.is_jmp_near_indirect
                        and instruction.op0_kind == OpKind.MEMORY
                        and instruction.memory_base == Register.NONE
                        and MemorySizeExt.size(instruction.memory_size) == 4
                        and Register.EAX <= instruction.memory_index <= Register.EDI
                        and instruction.memory_index_scale == 4
                    ):
                        table = instruction.memory_displacement
                    elif (
                        instruction.mnemonic == Mnemonic.MOVZX
                        and instruction.op0_kind == OpKind.REGISTER
                        and Register.EAX <= instruction.op0_register <= Register.EDI
                        and instruction.op1_kind == OpKind.MEMORY
                        and MemorySizeExt.size(instruction.memory_size) == 1
                        and Register.EAX <= instruction.memory_base <= Register.EDI
                        and instruction.memory_index == Register.NONE
                    ):
                        table = instruction.memory_displacement
                    if table is not None and address < table < start + len(data):
                        if instruction.is_jmp_near_indirect:
                            pending[table] = function
                        else:
                            self.byte_tables.add(table)
                        stop = min(stop, table - start)
                    if not self.literal(address):
                        for index in range(instruction.op_count):
                            kind = instruction.op_kind(index)
                            value = (
                                instruction.memory_displacement
                                if kind == OpKind.MEMORY
                                else instruction.immediate(index)
                                if OpKind.IMMEDIATE8 <= kind <= OpKind.IMMEDIATE32TO64
                                else None
                            )
                            if value is not None and self.start <= value < self.end:
                                references.add(value)
                if (
                    offset >= stop
                    or start + offset in self.byte_tables
                    or self.padding(data, offset) is not None
                ):
                    break
            if not decoded:
                offset += 1
        return references

    def read_table(self, table: int, function: int, data: bytes, start: int) -> int:
        count = 0
        while table - start + count * 4 + 4 <= len(data):
            entry = struct.unpack_from("<I", data, table - start + count * 4)[0]
            if not (function <= entry < table):
                break
            self.labels.add(entry)
            count += 1
        self.tables[table] = count
        return count

    def scan(self, start: int, section) -> Set[int]:
        data = self.raw_data(section)
        references: Set[int] = set()
        for offset in range(0, len(data) - 3, 4):
            value = struct.unpack_from("<I", data, offset)[0]
            if (
                self.start <= value < self.end
                and not self.raw(start + offset)
                and not self.literal(start + offset)
            ):
                references.add(value)
        return references

    def name(self, va: int) -> Optional[str]:
        if self.is_inner(va):
            return None
        if va in self.names:
            return quote(self.names[va][-1])
        if va in self.functions:
            return f"_func_{va:08X}"
        if va in self.tables:
            return f"jtbl_{va:08X}"
        if va in self.code_labels:
            return f"L_{va:08X}"
        if va in self.labels and self.is_instruction(va):
            return f".L{va:08X}"
        if va in self.data:
            return f"_D_{va:08X}"
        return None

    def label(self, out: TextIO, va: int):
        name = self.name(va)
        if name is None:
            return

        names = [quote(item) for item in self.names[va]] if va in self.names else [name]
        for name in dict.fromkeys(names):
            if not name.startswith((".L", "jtbl_")):
                out.write(f"\n.globl {name}\n")
            out.write(f"{name}:\n")

    def symbolic(self, text: str) -> str:
        def replace(match):
            name = self.reference_name(int(match.group(0), 16))
            if name is None or name.startswith(".L"):
                return match.group(0)
            before = text[: match.start()].rstrip()
            if before.endswith(("[", "+")):
                return name
            if before == "" or before.endswith(","):
                return f"offset {name}"
            return match.group(0)

        return HEX.sub(replace, text)

    @staticmethod
    def decode(data: bytes, address: int):
        # Allow older x87 instructions
        return Decoder(32, data, ip=address, options=DecoderOptions.OLD_FPU)

    def instruction_text(self, instruction, symbolic=False) -> str:
        text = self.formatter.format(instruction)
        text = re.sub(r"\bst([0-7])\b", r"st(\1)", text)
        # GAS rejects explicit default segments without a segment prefix
        if not instruction.has_segment_prefix:
            text = text.replace("ds:", "").replace("ss:", "")
        if symbolic:
            mnemonic = self.formatter.format_mnemonic(instruction)
            text = mnemonic + self.symbolic(text[len(mnemonic) :])
        return text

    def format(self, insn, raw, offsets) -> Optional[str]:
        if insn.is_invalid:
            return None
        mnemonic = self.formatter.format_mnemonic(insn)
        count = 0
        while count < len(raw) and raw[count] in PREFIXES:
            count += 1
        opcode = raw[count]
        if insn.op0_kind in (OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32):
            target = insn.near_branch_target
            name = self.name(target)
            if name is None or count:
                return None
            span = target - insn.ip - (2 if target <= insn.ip else insn.len)
            far = insn.len >= 5 and opcode in (0xE9, 0x0F) and -128 <= span <= 127
            return f"{'{disp32} ' if far else ''}{mnemonic} {name}"
        prefix = encoding_prefix(insn, raw, offsets, self.formatter, count)
        if prefix is None:
            return None
        if insn.is_string_instruction and 0xA4 <= opcode <= 0xAF:
            return mnemonic
        text = self.instruction_text(insn, symbolic=not self.literal(insn.ip))
        if (
            opcode in (0x86, 0x87)
            and insn.op0_kind == OpKind.REGISTER
            and insn.op1_kind == OpKind.REGISTER
        ):
            # GAS selects the opposite register-field order from MASM
            text = (
                mnemonic
                + " "
                + self.formatter.format_operand(insn, 1)
                + ", "
                + self.formatter.format_operand(insn, 0)
            )
        if mnemonic in STATE_OPS:
            text = re.sub(r"\w+ ptr ", "", text)
        return prefix + text

    def raw_instruction(self, insn, raw, offsets) -> str:
        """Emit raw bytes, keeping symbols in address fields."""
        fields = {}
        branch = insn.op0_kind in (OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32)
        if branch and offsets.immediate_size == 4:
            name = self.name(insn.near_branch_target)
            if name is not None:
                fields[offsets.immediate_offset] = f"{name} - . - 4"
        if not branch and not self.literal(insn.ip):
            for offset, size in (
                (offsets.displacement_offset, offsets.displacement_size),
                (offsets.immediate_offset, offsets.immediate_size),
            ):
                value = int.from_bytes(raw[offset : offset + size], "little")
                name = self.reference_name(value) if size == 4 else None
                if name is not None and not name.startswith(".L"):
                    fields[offset] = name
        parts = []
        offset = 0
        for field in sorted(fields):
            if field > offset:
                parts.append(".byte " + hex_bytes(raw[offset:field]))
            parts.append(f".long {fields[field]}")
            offset = field + 4
        if offset < len(raw):
            parts.append(".byte " + hex_bytes(raw[offset:]))
        return "; ".join(parts)

    def write_code(
        self, out: TextIO, start: int, end: int, section_line=".section .text"
    ):
        found = self.section(start)
        if found is None or found[0] not in self.sizes:
            log.error(f"Code split starts outside a code section at 0x{start:08X}")
        section_start, section = found
        sizes = self.sizes[section_start]
        data = self.raw_data(section)
        if not section_start <= start <= end <= section_start + len(data):
            log.error(f"Code split 0x{start:08X}-0x{end:08X} is outside its section")
        for side, boundary in (("start", start), ("end", end)):
            offset = boundary - section_start
            # An x86 instruction is at most 15 bytes long
            for previous in range(max(0, offset - 14), offset):
                if sizes[previous] and previous + sizes[previous] > offset:
                    instruction_start = section_start + previous
                    instruction_end = instruction_start + sizes[previous]
                    log.error(
                        f"Code split {side} 0x{boundary:08X} is inside decoded "
                        f"instruction 0x{instruction_start:08X}-0x{instruction_end:08X}"
                    )
            for table, count in self.tables.items():
                table_end = table + count * 4
                if table < boundary < table_end:
                    log.error(
                        f"Code split {side} 0x{boundary:08X} is inside inferred "
                        f"switch table 0x{table:08X}-0x{table_end:08X}"
                    )
        out.write(
            f".intel_syntax noprefix\n{section_line}\n.balign {alignment(start, end)}\n"
        )
        offset = start - section_start
        limit = end - section_start
        while offset < limit:
            va = section_start + offset
            self.label(out, va)
            if self.tables.get(va):
                for index in range(self.tables[va]):
                    entry = struct.unpack_from("<I", data, offset)[0]
                    out.write(
                        f"    /* {section_start + offset:08X} */ .long {self.name(entry) or f'0x{entry:08X}'}\n"
                    )
                    offset += 4
                continue
            if not sizes[offset]:
                run = offset + 1
                while (
                    run < limit
                    and not sizes[run]
                    and run - offset < 16
                    and self.name(section_start + run) is None
                ):
                    run += 1
                out.write(f"    /* {va:08X} */ .byte {hex_bytes(data[offset:run])}\n")
                offset = run
                continue
            stop = offset + sizes[offset]
            while (
                stop < limit
                and sizes[stop]
                and (self.name(section_start + stop) or ".L").startswith(".L")
            ):
                stop += sizes[stop]
            decoder = self.decode(data[offset:stop], va)
            for insn in decoder:
                if insn.ip != va:
                    self.label(out, insn.ip)
                raw = data[insn.ip - section_start : insn.ip - section_start + insn.len]
                offsets = decoder.get_constant_offsets(insn)
                text = self.format(insn, raw, offsets)
                out.write(
                    f"    /* {insn.ip:08X} {raw.hex().upper()} */ {text or self.raw_instruction(insn, raw, offsets)}\n"
                )
            offset = stop

    def write_data(self, out: TextIO, start: int, end: int, section_line: str):
        found = self.section(start)
        if found is None:
            log.error(f"Data split starts outside a section at 0x{start:08X}")
        section_start, section = found
        if (
            not section_start
            <= start
            <= end
            <= section_start + max(section.virtual_size, section.raw_size)
        ):
            log.error(f"Data split 0x{start:08X}-0x{end:08X} is outside its section")
        raw_end = section_start + section.raw_size
        data = self.raw_data(section)[
            start - section_start : min(end, raw_end) - section_start
        ]
        marks = sorted(va for va in self.data | set(self.names) if start < va < end)
        out.write(f"{section_line}\n.balign {alignment(start, end)}\n")
        va = start
        while va < end:
            self.label(out, va)
            mark_index = bisect.bisect_right(marks, va)
            following = marks[mark_index] if mark_index < len(marks) else end
            if va >= raw_end:
                out.write(f"    .space 0x{following - va:X}\n")
                va = following
                continue
            chunk = data[va - start : min(following, raw_end) - start]
            text = self.string(chunk)
            if text is not None:
                out.write(f"    /* {va:08X} */ .asciz {text}\n")
                va += chunk.index(0) + 1
            elif va & 3 == 0 and len(chunk) >= 4:
                value = struct.unpack_from("<I", chunk)[0]
                name = (
                    None
                    if self.raw(va) or self.literal(va)
                    else self.reference_name(value)
                )
                out.write(f"    /* {va:08X} */ .long {name or f'0x{value:08X}'}\n")
                va += 4
            else:
                size = min(len(chunk), 4 - (va & 3))
                out.write(f"    /* {va:08X} */ .byte {hex_bytes(chunk[:size])}\n")
                va += size

    @staticmethod
    def string(chunk: bytes) -> Optional[str]:
        end = chunk.find(0)
        if end < 4 or any(
            not (0x20 <= b < 0x7F or b in (9, 10, 13)) for b in chunk[:end]
        ):
            return None
        text = chunk[:end].decode("ascii").replace("\\", "\\\\").replace('"', '\\"')
        return (
            '"'
            + text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            + '"'
        )


_program: Optional[Program] = None


def reset():
    global _program
    _program = None


def program() -> Program:
    global _program
    if _program is None:
        _program = Program()
    return _program
