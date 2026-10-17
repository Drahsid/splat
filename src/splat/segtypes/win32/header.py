import struct
from typing import ClassVar, List

from ..common.header import CommonSegHeader
from ..linker_entry import write_file_if_different
from ...platforms import win32 as win32_platform


_MACHINE_TYPES = {
    0x014C: "i386",
    0x0162: "MIPS R3000 LE",
    0x0166: "MIPS R4000 LE",
    0x0168: "MIPS R10000",
    0x0184: "Alpha AXP",
    0x01C0: "ARM (legacy CE)",
    0x01C2: "ARM Thumb",
    0x01C4: "ARMNT (Thumb-2)",
    0x01F0: "PowerPC LE",
    0x01F1: "PowerPC w/ FP",
    0x0200: "Itanium (IA-64)",
    0x0266: "MIPS16",
    0x0366: "MIPSFPU",
    0x0466: "MIPSFPU16",
    0x0EBC: "EFI byte code",
    0x5032: "RISC-V 32-bit",
    0x5064: "RISC-V 64-bit",
    0x5128: "RISC-V 128-bit",
    0x6232: "LoongArch 32-bit",
    0x6264: "LoongArch 64-bit",
    0x8664: "amd64",
    0x9041: "Mitsubishi M32R LE",
    0xAA64: "ARM64",
    0xC0EE: "CLR/CEE",
}


_SUBSYSTEMS = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    8: "NATIVE_WINDOWS",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

_DLL_CHARACTERISTICS = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]


_FILE_CHARACTERISTICS = [
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0010, "AGGRESSIVE_WS_TRIM"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0080, "BYTES_REVERSED_LO"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_HI"),
]


def _decode_flags(value: int, table) -> str:
    names = []
    known_mask = 0
    for bit, name in table:
        if value & bit:
            names.append(name)
        known_mask |= bit
    leftover = value & ~known_mask
    if leftover:
        names.append(f"unknown 0x{leftover:X}")
    return " | ".join(names) if names else "(none)"


class Win32SegHeader(CommonSegHeader):
    def get_linker_section(self) -> str:
        return ".header"

    def split(self, rom_bytes):
        write_file_if_different(
            self.out_path(), "\n".join(self.parse_header(rom_bytes))
        )

    def _numeric_field(self, data: bytes, offset: int, size: int, label: str) -> str:
        directive = {1: "byte", 2: "short", 4: "long", 8: "quad"}[size]
        return self.get_line(directive, data[offset : offset + size][::-1], label)

    def parse_header(self, rom_bytes) -> List[str]:
        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)
        pe = win32_platform.info

        out = self._summary_block(pe)
        out.append(".section .header")
        out.append("")

        out.append("/* DOS header */")
        out.append(self.get_line("ascii", rom_bytes[0x00:0x02], "Magic"))
        out.append(self._byte_block(rom_bytes[0x02:0x3C], "DOS header tail"))
        out.append(self._numeric_field(rom_bytes, 0x3C, 4, "e_lfanew"))
        out.append("")

        pe_off = pe.pe_header_offset
        if pe_off > 0x40:
            out.append(self._byte_block(rom_bytes[0x40:pe_off], "DOS stub"))
            out.append("")

        out.append("/* PE header */")
        out.append(self.get_line("ascii", rom_bytes[pe_off : pe_off + 4], "Signature"))
        for offset, size, label in [
            (4, 2, "Machine"),
            (6, 2, "NumberOfSections"),
            (8, 4, "TimeDateStamp"),
            (12, 4, "PointerToSymbolTable"),
            (16, 4, "NumberOfSymbols"),
            (20, 2, "SizeOfOptionalHeader"),
            (22, 2, "Characteristics"),
        ]:
            out.append(self._numeric_field(rom_bytes, pe_off + offset, size, label))
        size_opt_hdr = struct.unpack_from("<H", rom_bytes, pe_off + 20)[0]
        out.append("")

        opt_off = pe_off + 24
        opt_end = opt_off + size_opt_hdr
        out.append("/* Optional header */")
        out.extend(self._dump_optional_header(rom_bytes, opt_off, opt_end))
        out.append("")

        sect_off = opt_end
        for i, section in enumerate(pe.sections):
            base = sect_off + i * 40
            out.append(f"/* Section {i}: {section.name!r} */")
            out.append(self._byte_block(rom_bytes[base : base + 8], "Name"))
            for offset, size, label in [
                (8, 4, "VirtualSize"),
                (12, 4, "VirtualAddress"),
                (16, 4, "SizeOfRawData"),
                (20, 4, "PointerToRawData"),
                (24, 4, "PointerToRelocations"),
                (28, 4, "PointerToLinenumbers"),
                (32, 2, "NumberOfRelocations"),
                (34, 2, "NumberOfLinenumbers"),
                (36, 4, "Characteristics"),
            ]:
                out.append(self._numeric_field(rom_bytes, base + offset, size, label))
        out.append("")

        tail_start = sect_off + len(pe.sections) * 40
        if tail_start < self.rom_end:
            out.append(
                self._byte_block(rom_bytes[tail_start : self.rom_end], "Header padding")
            )

        out.append("")
        return out

    @staticmethod
    def _byte_block(data: bytes, comment: str) -> str:
        if not data:
            return f"/* {comment}: empty */"
        hexed = ", ".join(f"0x{b:02X}" for b in data)
        return f".byte {hexed} /* {comment} */"

    def _summary_block(self, pe) -> List[str]:
        width = 16 if pe.is_pe32_plus else 8
        fields = [
            ("Machine", _MACHINE_TYPES.get(pe.machine, f"0x{pe.machine:04X}")),
            ("ImageBase", f"0x{pe.image_base:0{width}X}"),
            (
                "EntryPoint",
                f"0x{pe.entry_point_va:0{width}X}" if pe.entry_point_rva else "(none)",
            ),
            ("Subsystem", _SUBSYSTEMS.get(pe.subsystem, f"0x{pe.subsystem:04X}")),
            (
                "Characteristics",
                _decode_flags(pe.characteristics, _FILE_CHARACTERISTICS),
            ),
            (
                "DllCharacteristics",
                _decode_flags(pe.dll_characteristics, _DLL_CHARACTERISTICS),
            ),
        ]
        if pe.linker_major or pe.linker_minor:
            fields.append(
                (
                    "Linker",
                    win32_platform.linker_version_label(
                        pe.linker_major, pe.linker_minor
                    ),
                )
            )
        return [f"/* {name}: {value} */" for name, value in fields] + [""]

    _DATA_DIRECTORY_NAMES: ClassVar[List[str]] = [
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Table",
        "Certificate Table",
        "Base Relocation Table",
        "Debug",
        "Architecture",
        "Global Ptr",
        "TLS Table",
        "Load Config Table",
        "Bound Import",
        "IAT",
        "Delay Import Descriptor",
        "CLR Runtime Header",
        "Reserved",
    ]

    def _dump_optional_header(
        self, rom_bytes: bytes, opt_off: int, opt_end: int
    ) -> List[str]:
        opt_end = min(opt_end, len(rom_bytes))
        out: List[str] = []
        if opt_end - opt_off < 2:
            out.append(self._byte_block(rom_bytes[opt_off:opt_end], "Optional header"))
            return out

        magic = struct.unpack_from("<H", rom_bytes, opt_off)[0]
        is_pe32_plus = magic == win32_platform.OPT_MAGIC_PE32_PLUS
        size_int = 8 if is_pe32_plus else 4
        fields = [
            (2, "Magic"),
            (1, "MajorLinkerVersion"),
            (1, "MinorLinkerVersion"),
            (4, "SizeOfCode"),
            (4, "SizeOfInitializedData"),
            (4, "SizeOfUninitializedData"),
            (4, "AddressOfEntryPoint"),
            (4, "BaseOfCode"),
            (4, "BaseOfData"),
            (size_int, "ImageBase"),
            (4, "SectionAlignment"),
            (4, "FileAlignment"),
            (2, "MajorOperatingSystemVersion"),
            (2, "MinorOperatingSystemVersion"),
            (2, "MajorImageVersion"),
            (2, "MinorImageVersion"),
            (2, "MajorSubsystemVersion"),
            (2, "MinorSubsystemVersion"),
            (4, "Win32VersionValue"),
            (4, "SizeOfImage"),
            (4, "SizeOfHeaders"),
            (4, "CheckSum"),
            (2, "Subsystem"),
            (2, "DllCharacteristics"),
            (size_int, "SizeOfStackReserve"),
            (size_int, "SizeOfStackCommit"),
            (size_int, "SizeOfHeapReserve"),
            (size_int, "SizeOfHeapCommit"),
            (4, "LoaderFlags"),
            (4, "NumberOfRvaAndSizes"),
        ]
        o = opt_off
        num_dirs = 0
        for size, label in fields:
            if label == "BaseOfData" and is_pe32_plus:
                continue
            if o + size > opt_end:
                tail = rom_bytes[o:opt_end]
                if tail:
                    out.append(self._byte_block(tail, f"truncated past {label}"))
                return out
            out.append(self._numeric_field(rom_bytes, o, size, label))
            if label == "NumberOfRvaAndSizes":
                num_dirs = struct.unpack_from("<I", rom_bytes, o)[0]
            o += size

        if num_dirs > 0:
            out.append("/* Data directories */")
        for i in range(min(num_dirs, 256)):
            if o + 8 > opt_end:
                break
            label = (
                self._DATA_DIRECTORY_NAMES[i]
                if i < len(self._DATA_DIRECTORY_NAMES)
                else f"Directory {i}"
            )
            out.append(self._numeric_field(rom_bytes, o, 4, f"{label}.VirtualAddress"))
            out.append(self._numeric_field(rom_bytes, o + 4, 4, f"{label}.Size"))
            o += 8

        if o < opt_end:
            out.append(self._byte_block(rom_bytes[o:opt_end], "Optional header tail"))

        return out
