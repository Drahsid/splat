from dataclasses import dataclass, field
from pathlib import Path
import struct
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

from ..util import log

if TYPE_CHECKING:
    from ..segtypes.win32.unit import Win32Unit


DOS_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
MACHINE_ARM32 = 0x01C4
MACHINE_ARM64 = 0xAA64

# IMAGE_OPTIONAL_HEADER.Magic
OPT_MAGIC_PE32 = 0x10B
OPT_MAGIC_PE32_PLUS = 0x20B

# IMAGE_DIRECTORY_ENTRY_*
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_CERTIFICATE = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_ARCHITECTURE = 7
DIR_GLOBALPTR = 8
DIR_TLS = 9
DIR_LOAD_CONFIG = 10
DIR_BOUND_IMPORT = 11
DIR_IAT = 12
DIR_DELAY_IMPORT = 13
DIR_COM_DESCRIPTOR = 14

# Section header flags (IMAGE_SCN_*)
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000
SCN_MEM_EXECUTE = 0x20000000


@dataclass
class PESection:
    name: str
    virtual_size: int
    virtual_address: int  # RVA
    raw_size: int
    raw_pointer: int  # file offset
    characteristics: int

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & (SCN_CNT_CODE | SCN_MEM_EXECUTE))

    @property
    def is_bss(self) -> bool:
        return bool(self.characteristics & SCN_CNT_UNINITIALIZED_DATA)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def is_readonly_data(self) -> bool:
        return (
            bool(self.characteristics & SCN_CNT_INITIALIZED_DATA)
            and not self.is_writable
            and not self.is_code
        )


@dataclass
class PEExport:
    name: Optional[str]
    ordinal: int
    rva: int
    forwarder: Optional[str] = None


@dataclass
class PEImport:
    dll: str
    name: Optional[str]
    ordinal: Optional[int]
    iat_rva: int


@dataclass
class PEBoundImport:
    dll: str
    timestamp: int
    forwarder_refs: List[str] = field(default_factory=list)


@dataclass
class CLRHeader:
    cb_size: int  # always 72
    runtime_major: int
    runtime_minor: int
    metadata_rva: int
    metadata_size: int
    flags: int
    entry_point_token_or_rva: int
    resources_rva: int
    resources_size: int
    strong_name_signature_rva: int
    strong_name_signature_size: int


@dataclass
class UnwindInfo:
    version: int
    flags: int
    prolog_size: int
    frame_register: int  # 0 = none; otherwise the x86_64 register index
    frame_register_offset: int  # nibble × 16
    codes: List[Tuple[int, str, int]] = field(default_factory=list)
    chained_function_rva: Optional[int] = None


@dataclass
class COFFSymbol:
    name: str
    value: int  # VA or RVA depending on storage class
    section_number: int  # 1-based, 0 = undefined, -1 = absolute, -2 = debug
    sym_type: int  # combined base + complex type
    storage_class: int
    aux_records: int  # number of trailing IMAGE_AUX_SYMBOL entries


@dataclass
class PEResource:
    rtype: object  # int (standard) or str (custom-named type)
    rid: object  # int or str
    language: int
    rva: int
    size: int


@dataclass
class PEInfo:
    machine: int = 0
    num_sections: int = 0
    timestamp: int = 0
    characteristics: int = 0

    is_pe32_plus: bool = False
    image_base: int = 0
    entry_point_rva: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    size_of_stack_reserve: int = 0
    size_of_stack_commit: int = 0
    size_of_heap_reserve: int = 0
    size_of_heap_commit: int = 0
    linker_major: int = 0
    linker_minor: int = 0

    pe_header_offset: int = 0
    sections: List[PESection] = field(default_factory=list)

    # (RVA, size)
    data_directories: List[Tuple[int, int]] = field(default_factory=list)
    exports: List[PEExport] = field(default_factory=list)
    export_dll_name: Optional[str] = None
    imports: List[PEImport] = field(default_factory=list)
    bound_imports: List[PEBoundImport] = field(default_factory=list)
    delay_imports: List[PEImport] = field(default_factory=list)
    # (begin_rva, end_rva, unwind_rva)
    runtime_functions: List[Tuple[int, int, int]] = field(default_factory=list)
    security_cookie_va: int = 0
    # Handler RVAs (PE32 only)
    safe_seh_handlers: List[int] = field(default_factory=list)
    # Valid indirect call targets (RVAs)
    cfg_function_rvas: List[int] = field(default_factory=list)
    cfg_flags: int = 0
    # RVAs with pointer relocations
    pointer_rvas: Set[int] = field(default_factory=set)
    coff_symtab_ptr: int = 0
    coff_num_symbols: int = 0
    coff_symbols: List["COFFSymbol"] = field(default_factory=list)
    pdb_path: Optional[str] = None
    pdb_guid: Optional[str] = None
    pdb_age: Optional[int] = None
    tls_callback_vas: List[int] = field(default_factory=list)
    # Unwind info by RVA (PE32+ only)
    unwind_info: Dict[int, UnwindInfo] = field(default_factory=dict)
    clr_header: Optional[CLRHeader] = None
    resources: List[PEResource] = field(default_factory=list)
    version_info: dict = field(default_factory=dict)

    @property
    def entry_point_va(self) -> int:
        return self.image_base + self.entry_point_rva

    def section_by_name(self, name: str) -> Optional[PESection]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def get_data_directory(self, index: int) -> Tuple[int, int]:
        if index < len(self.data_directories):
            return self.data_directories[index]
        return 0, 0

    def rva_to_file_offset(self, rva: int) -> Optional[int]:
        for s in self.sections:
            sec_end = s.virtual_address + max(s.virtual_size, s.raw_size)
            if not (s.virtual_address <= rva < sec_end):
                continue
            # The rest of the section is zero filled in memory
            offset_in_section = rva - s.virtual_address
            if offset_in_section >= s.raw_size:
                return None
            return s.raw_pointer + offset_in_section
        return None

    def va_to_file_offset(self, va: int) -> Optional[int]:
        return self.rva_to_file_offset(va - self.image_base)


info: PEInfo = PEInfo()
raw_image: bytes = b""
translation_units: List["Win32Unit"] = []
translation_units_by_name: Dict[Path, "Win32Unit"] = {}


def resolve_exact_encoding(
    yaml: object, parent: "Optional[object]", default: bool = False
) -> bool:
    if isinstance(yaml, dict):
        v = yaml.get("exact_encoding")
        if v is not None:
            return bool(v)
    if parent is not None:
        parent_yaml = getattr(parent, "yaml", None)
        if isinstance(parent_yaml, dict):
            v = parent_yaml.get("exact_encoding")
            if v is not None:
                return bool(v)
    return default


def sanitize_label(s: str) -> str:
    out = "".join(c if c.isalnum() or c == "_" else "_" for c in s)
    if out and out[0].isdigit():
        out = "_" + out
    return out


def compute_iat_labels(pe: PEInfo) -> Dict[int, str]:
    out: Dict[int, str] = {}

    def populate(items: List[PEImport], prefix: str) -> None:
        seen: Set[str] = set()
        for imp in items:
            slot_va = pe.image_base + imp.iat_rva
            nm = imp.name or f"ordinal_{imp.ordinal}"
            safe = sanitize_label(nm)
            dll_safe = sanitize_label(imp.dll) or "unknown"
            full = f"{prefix}_{dll_safe}_{safe}"
            if full in seen:
                full = f"{full}__rva{imp.iat_rva:X}"
            seen.add(full)
            out[slot_va] = full

    populate(pe.imports, "imp")
    populate(pe.delay_imports, "dimp")
    return out


def compute_export_labels(
    pe: PEInfo, reserved: Optional[Set[str]] = None
) -> Dict[int, str]:
    out: Dict[int, str] = {}
    seen: Set[str] = set(reserved or set())
    for exp in pe.exports:
        if exp.forwarder is not None:
            continue
        nm = exp.name or f"export_{exp.ordinal}"
        safe = sanitize_label(nm)
        if safe in seen:
            safe = f"{safe}__ord{exp.ordinal}"
        seen.add(safe)
        out[pe.image_base + exp.rva] = safe
    return out


def parse_pe(data: bytes) -> PEInfo:
    if len(data) < 0x40 or data[:2] != DOS_MAGIC:
        log.error("Target does not start with an MZ header")

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != PE_MAGIC:
        log.error(f"Missing PE header at 0x{pe_off:X}")

    coff_off = pe_off + 4
    (
        machine,
        num_sections,
        timestamp,
        coff_symtab_ptr,
        coff_num_symbols,
        size_of_optional_header,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_off)

    opt_off = coff_off + 20
    if size_of_optional_header < 2:
        log.error("Missing PE optional header")
    if opt_off + size_of_optional_header > len(data):
        log.error("PE optional header extends past the end of the file")

    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe32_plus = magic == OPT_MAGIC_PE32_PLUS
    if magic not in (OPT_MAGIC_PE32, OPT_MAGIC_PE32_PLUS):
        log.error(f"Unknown PE optional header magic 0x{magic:04X}")

    if machine in (MACHINE_AMD64, MACHINE_ARM64) and not is_pe32_plus:
        log.error(f"Machine type 0x{machine:04X} requires a PE32+ header")
    if machine in (MACHINE_I386, MACHINE_ARM32) and is_pe32_plus:
        log.error(f"Machine type 0x{machine:04X} requires a PE32 header")

    min_opt = 112 if is_pe32_plus else 96
    if size_of_optional_header < min_opt:
        log.error(
            f"PE optional header is too short ({size_of_optional_header} bytes, "
            f"expected at least {min_opt})"
        )

    pe = PEInfo(
        machine=machine,
        num_sections=num_sections,
        timestamp=timestamp,
        characteristics=characteristics,
        is_pe32_plus=is_pe32_plus,
        pe_header_offset=pe_off,
        coff_symtab_ptr=coff_symtab_ptr,
        coff_num_symbols=coff_num_symbols,
    )

    pe.linker_major = data[opt_off + 2]
    pe.linker_minor = data[opt_off + 3]
    pe.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
    pe.section_alignment = struct.unpack_from("<I", data, opt_off + 32)[0]
    pe.file_alignment = struct.unpack_from("<I", data, opt_off + 36)[0]
    pe.size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
    pe.size_of_headers = struct.unpack_from("<I", data, opt_off + 60)[0]
    pe.subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
    pe.dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]

    pointer_format = "Q" if is_pe32_plus else "I"
    base_offset = 24 if is_pe32_plus else 28
    pe.image_base = struct.unpack_from(
        f"<{pointer_format}", data, opt_off + base_offset
    )[0]
    (
        pe.size_of_stack_reserve,
        pe.size_of_stack_commit,
        pe.size_of_heap_reserve,
        pe.size_of_heap_commit,
    ) = struct.unpack_from(f"<4{pointer_format}", data, opt_off + 72)

    dd_off = opt_off + min_opt
    num_rva = struct.unpack_from("<I", data, dd_off - 4)[0]
    directory_count = min(num_rva, 16, (size_of_optional_header - min_opt) // 8)
    for index in range(directory_count):
        pe.data_directories.append(struct.unpack_from("<II", data, dd_off + index * 8))

    section_off = opt_off + size_of_optional_header
    # PE limits NumberOfSections to 96.
    capped_num_sections = min(num_sections, 96)
    for i in range(capped_num_sections):
        sh = section_off + i * 40
        if sh + 40 > len(data):
            log.error(f"Section header {i} extends past the end of the file")
        raw_name = data[sh : sh + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        (
            virt_size,
            virt_addr,
            raw_size,
            raw_ptr,
            scn_chars,
        ) = struct.unpack_from("<4I12xI", data, sh + 8)
        pe.sections.append(
            PESection(
                name=name,
                virtual_size=virt_size,
                virtual_address=virt_addr,
                raw_size=raw_size,
                raw_pointer=raw_ptr,
                characteristics=scn_chars,
            )
        )

    parse_exports(data, pe)
    parse_imports(data, pe)
    parse_bound_imports(data, pe)
    parse_delay_imports(data, pe)
    parse_relocations(data, pe)
    parse_exception_table(data, pe)
    parse_load_config(data, pe)
    parse_debug(data, pe)
    parse_tls(data, pe)
    parse_resources(data, pe)
    parse_version_info(data, pe)
    parse_coff_symtab(data, pe)
    parse_unwind_info(data, pe)
    parse_clr_header(data, pe)
    return pe


_MAX_CSTR_LEN = 4096


def _read_cstr(data: bytes, off: int) -> str:
    if off < 0 or off >= len(data):
        return ""
    cap = min(off + _MAX_CSTR_LEN, len(data))
    end = data.find(b"\x00", off, cap)
    if end < 0:
        end = cap
    return data[off:end].decode("ascii", errors="replace")


def parse_exports(data: bytes, pe: PEInfo) -> None:
    exp_rva, exp_size = pe.get_data_directory(DIR_EXPORT)
    if exp_rva == 0 or exp_size == 0:
        return
    exp_off = pe.rva_to_file_offset(exp_rva)
    if exp_off is None or exp_off + 40 > len(data):
        return

    (
        name_rva,
        ord_base,
        num_funcs,
        num_names,
        funcs_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack_from("<12x7I", data, exp_off)

    if name_rva:
        name_off = pe.rva_to_file_offset(name_rva)
        if name_off is not None:
            pe.export_dll_name = _read_cstr(data, name_off)

    funcs_off = pe.rva_to_file_offset(funcs_rva) if funcs_rva else None
    names_off = pe.rva_to_file_offset(names_rva) if names_rva else None
    ordinals_off = pe.rva_to_file_offset(ordinals_rva) if ordinals_rva else None

    if funcs_off is None:
        return

    EXPORT_LIMIT = 65536
    num_funcs = min(num_funcs, EXPORT_LIMIT)
    num_names = min(num_names, EXPORT_LIMIT)

    # Exports can have an ordinal without a name
    name_for_ordinal: Dict[int, str] = {}
    if names_off is not None and ordinals_off is not None:
        for i in range(num_names):
            if names_off + i * 4 + 4 > len(data):
                break
            if ordinals_off + i * 2 + 2 > len(data):
                break
            name_ptr_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
            ordinal_idx = struct.unpack_from("<H", data, ordinals_off + i * 2)[0]
            name_off = pe.rva_to_file_offset(name_ptr_rva)
            if name_off is None:
                continue
            name_for_ordinal[ordinal_idx] = _read_cstr(data, name_off)

    for i in range(num_funcs):
        if funcs_off + i * 4 + 4 > len(data):
            break
        func_rva = struct.unpack_from("<I", data, funcs_off + i * 4)[0]
        if func_rva == 0:
            continue
        forwarder: Optional[str] = None
        # Addresses in the export directory point to forwarder strings
        if exp_rva <= func_rva < exp_rva + exp_size:
            f_off = pe.rva_to_file_offset(func_rva)
            if f_off is not None:
                forwarder = _read_cstr(data, f_off)
        pe.exports.append(
            PEExport(
                name=name_for_ordinal.get(i),
                ordinal=i + ord_base,
                rva=func_rva,
                forwarder=forwarder,
            )
        )


def _walk_thunk_array(
    data: bytes,
    pe: PEInfo,
    thunk_off: int,
    slot_rva: int,
    dll_name: str,
    dest: List[PEImport],
) -> None:
    thunk_size = 8 if pe.is_pe32_plus else 4
    thunk_fmt = "<Q" if pe.is_pe32_plus else "<I"
    ordinal_flag = 1 << (thunk_size * 8 - 1)
    for _ in range(65536):
        if thunk_off + thunk_size > len(data):
            break
        thunk = struct.unpack_from(thunk_fmt, data, thunk_off)[0]
        if thunk == 0:
            break
        name: Optional[str] = None
        ordinal: Optional[int] = None
        if thunk & ordinal_flag:
            ordinal = thunk & 0xFFFF
        else:
            hint_off = pe.rva_to_file_offset(thunk & 0x7FFFFFFF)
            if hint_off is not None and hint_off + 2 < len(data):
                # Preserve the hint as an ordinal if the name is absent
                hint = struct.unpack_from("<H", data, hint_off)[0]
                raw = _read_cstr(data, hint_off + 2)
                if raw:
                    name = raw
                elif hint:
                    ordinal = hint
        dest.append(
            PEImport(dll=dll_name, name=name, ordinal=ordinal, iat_rva=slot_rva)
        )
        thunk_off += thunk_size
        slot_rva += thunk_size


def parse_imports(data: bytes, pe: PEInfo) -> None:
    imp_rva, imp_size = pe.get_data_directory(DIR_IMPORT)
    if imp_rva == 0 or imp_size == 0:
        return
    imp_off = pe.rva_to_file_offset(imp_rva)
    if imp_off is None:
        return

    desc_off = imp_off
    for _desc_i in range(4096):
        if desc_off + 20 > len(data):
            break
        ilt_rva, dll_name_rva, iat_rva = struct.unpack_from("<I8xII", data, desc_off)
        if ilt_rva == 0 and dll_name_rva == 0 and iat_rva == 0:
            break
        desc_off += 20

        dll_off = pe.rva_to_file_offset(dll_name_rva)
        dll_name = _read_cstr(data, dll_off) if dll_off is not None else "?"

        # Use the IAT if the import lookup table is absent
        thunk_off = pe.rva_to_file_offset(ilt_rva or iat_rva)
        if thunk_off is None or iat_rva == 0:
            continue

        _walk_thunk_array(data, pe, thunk_off, iat_rva, dll_name, pe.imports)


def parse_delay_imports(data: bytes, pe: PEInfo) -> None:
    di_rva, di_size = pe.get_data_directory(DIR_DELAY_IMPORT)
    if di_rva == 0 or di_size == 0:
        return
    di_off = pe.rva_to_file_offset(di_rva)
    if di_off is None:
        return

    desc_off = di_off
    end = min(di_off + di_size, len(data))
    for _desc_i in range(4096):
        if desc_off + 32 > end:
            break
        (
            attrs,
            dll_name_field,
            iat_field,
            int_field,
        ) = struct.unpack_from("<II4xII12x", data, desc_off)
        if attrs == 0 and dll_name_field == 0 and iat_field == 0 and int_field == 0:
            break
        desc_off += 32

        # Older delay import descriptors use absolute addresses
        def to_rva(field: int, attrs: int = attrs) -> int:
            if attrs & 1:
                return field
            return field - pe.image_base if field >= pe.image_base else field

        dll_name_rva = to_rva(dll_name_field)
        iat_rva = to_rva(iat_field)
        int_rva = to_rva(int_field) if int_field else iat_rva

        dll_off = pe.rva_to_file_offset(dll_name_rva)
        dll_name = _read_cstr(data, dll_off) if dll_off is not None else "?"

        int_off = pe.rva_to_file_offset(int_rva)
        if int_off is None or iat_rva == 0:
            continue

        _walk_thunk_array(data, pe, int_off, iat_rva, dll_name, pe.delay_imports)


def parse_bound_imports(data: bytes, pe: PEInfo) -> None:
    bi_rva, bi_size = pe.get_data_directory(DIR_BOUND_IMPORT)
    if bi_rva == 0 or bi_size == 0:
        return
    bi_off = pe.rva_to_file_offset(bi_rva)
    if bi_off is None:
        return
    end = min(bi_off + bi_size, len(data))

    cur = bi_off
    for _bi_i in range(4096):
        if cur + 8 > end:
            break
        ts, name_off, n_fwd = struct.unpack_from("<IHH", data, cur)
        if ts == 0 and name_off == 0 and n_fwd == 0:
            break
        name_abs = bi_off + name_off
        dll_name = _read_cstr(data, name_abs) if name_abs < len(data) else "?"
        cur += 8
        fwds: List[str] = []
        for _ in range(n_fwd):
            if cur + 8 > end:
                break
            _ts, fname_off, _rsv = struct.unpack_from("<IHH", data, cur)
            fname_abs = bi_off + fname_off
            if fname_abs < len(data):
                fwds.append(_read_cstr(data, fname_abs))
            cur += 8
        pe.bound_imports.append(
            PEBoundImport(dll=dll_name, timestamp=ts, forwarder_refs=fwds)
        )


def parse_load_config(data: bytes, pe: PEInfo) -> None:
    lc_rva, lc_size = pe.get_data_directory(DIR_LOAD_CONFIG)
    if lc_rva == 0 or lc_size == 0:
        return
    lc_off = pe.rva_to_file_offset(lc_rva)
    if lc_off is None:
        return

    if pe.is_pe32_plus:
        if lc_off + 0x60 > len(data):
            return
        pe.security_cookie_va = struct.unpack_from("<Q", data, lc_off + 0x58)[0]
        if lc_off + 0x98 <= len(data):
            cfg_table_va = struct.unpack_from("<Q", data, lc_off + 0x80)[0]
            cfg_count = struct.unpack_from("<Q", data, lc_off + 0x88)[0]
            pe.cfg_flags = struct.unpack_from("<I", data, lc_off + 0x90)[0]
            _read_cfg_table(data, pe, cfg_table_va, cfg_count)
        return

    if lc_off + 0x48 > len(data):
        return
    pe.security_cookie_va = struct.unpack_from("<I", data, lc_off + 0x3C)[0]
    seh_table_va = struct.unpack_from("<I", data, lc_off + 0x40)[0]
    seh_count = struct.unpack_from("<I", data, lc_off + 0x44)[0]
    if seh_table_va and seh_count:
        # The table address is absolute, but its entries are RVAs
        table_off = pe.va_to_file_offset(seh_table_va)
        if table_off is not None:
            for i in range(min(seh_count, 1_000_000)):
                entry_off = table_off + i * 4
                if entry_off + 4 > len(data):
                    break
                pe.safe_seh_handlers.append(
                    struct.unpack_from("<I", data, entry_off)[0]
                )

    if lc_off + 0x60 <= len(data):
        cfg_table_va = struct.unpack_from("<I", data, lc_off + 0x54)[0]
        cfg_count = struct.unpack_from("<I", data, lc_off + 0x58)[0]
        pe.cfg_flags = struct.unpack_from("<I", data, lc_off + 0x5C)[0]
        _read_cfg_table(data, pe, cfg_table_va, cfg_count)


def _read_cfg_table(data: bytes, pe: PEInfo, table_va: int, count: int) -> None:
    if not table_va or not count:
        return
    table_off = pe.va_to_file_offset(table_va)
    if table_off is None:
        return
    # The high four flag bits give the number of extra bytes per entry
    extra = (pe.cfg_flags >> 28) & 0x0F
    stride = 4 + min(extra, 7)
    for i in range(min(count, 1_000_000)):
        entry_off = table_off + i * stride
        if entry_off + 4 > len(data):
            break
        rva = struct.unpack_from("<I", data, entry_off)[0]
        pe.cfg_function_rvas.append(rva)


def parse_exception_table(data: bytes, pe: PEInfo) -> None:
    et_rva, et_size = pe.get_data_directory(DIR_EXCEPTION)
    if et_rva == 0 or et_size == 0:
        return
    et_off = pe.rva_to_file_offset(et_rva)
    if et_off is None:
        return
    end = min(et_off + et_size, len(data))
    max_entries = min((end - et_off) // 12, 1_000_000)
    for i in range(max_entries):
        cur = et_off + i * 12
        begin, fin, uw = struct.unpack_from("<III", data, cur)
        if begin == 0 and fin == 0 and uw == 0:
            break
        pe.runtime_functions.append((begin, fin, uw))


RELOC_TYPE_ABSOLUTE = 0
RELOC_TYPE_HIGHLOW = 3
RELOC_TYPE_DIR64 = 10


def parse_relocations(data: bytes, pe: PEInfo) -> None:
    rel_rva, rel_size = pe.get_data_directory(DIR_BASERELOC)
    if rel_rva == 0 or rel_size == 0:
        return
    rel_off = pe.rva_to_file_offset(rel_rva)
    if rel_off is None:
        return

    end = min(rel_off + rel_size, len(data))
    accept = {RELOC_TYPE_HIGHLOW, RELOC_TYPE_DIR64}
    block = rel_off
    while block + 8 <= end:
        page_rva, block_size = struct.unpack_from("<II", data, block)
        if block_size < 8 or block + block_size > end:
            break
        entries_end = block + block_size
        entry = block + 8
        while entry + 2 <= entries_end:
            word = struct.unpack_from("<H", data, entry)[0]
            entry += 2
            kind = word >> 12
            if kind not in accept:
                continue
            pe.pointer_rvas.add(page_rva + (word & 0x0FFF))
        block += block_size


def parse_debug(data: bytes, pe: PEInfo) -> None:
    dbg_rva, dbg_size = pe.get_data_directory(DIR_DEBUG)
    if dbg_rva == 0 or dbg_size == 0:
        return
    dbg_off = pe.rva_to_file_offset(dbg_rva)
    if dbg_off is None:
        return

    end = min(dbg_off + dbg_size, len(data))
    entry = dbg_off
    while entry + 28 <= end:
        entry_type, size_of_data, ptr_to_raw = struct.unpack_from(
            "<12xII4xI", data, entry
        )
        entry += 28
        if entry_type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        if ptr_to_raw == 0 or size_of_data < 4:
            continue
        if ptr_to_raw + size_of_data > len(data):
            continue
        cv = data[ptr_to_raw : ptr_to_raw + size_of_data]
        magic = cv[:4]
        if magic == b"RSDS" and len(cv) >= 24:
            g0, g1, g2, g3 = struct.unpack_from("<IHH8s", cv, 4)
            tail = "-".join(f"{b:02X}" for b in g3)
            pe.pdb_guid = f"{g0:08X}-{g1:04X}-{g2:04X}-{tail}"
            pe.pdb_age = struct.unpack_from("<I", cv, 20)[0]
            pe.pdb_path = _read_cstr(cv, 24)
            return
        if magic == b"NB10" and len(cv) >= 16:
            sig = struct.unpack_from("<I", cv, 8)[0]
            pe.pdb_guid = f"{sig:08X}"
            pe.pdb_age = struct.unpack_from("<I", cv, 12)[0]
            pe.pdb_path = _read_cstr(cv, 16)
            return


def parse_tls(data: bytes, pe: PEInfo) -> None:
    tls_rva, tls_size = pe.get_data_directory(DIR_TLS)
    if tls_rva == 0 or tls_size == 0:
        return
    tls_off = pe.rva_to_file_offset(tls_rva)
    if tls_off is None:
        return

    ptr_size = 8 if pe.is_pe32_plus else 4
    ptr_fmt = "<Q" if pe.is_pe32_plus else "<I"
    if tls_off + 4 * ptr_size > len(data):
        return
    cb_va = struct.unpack_from(ptr_fmt, data, tls_off + 3 * ptr_size)[0]
    if cb_va == 0:
        return
    cb_off = pe.va_to_file_offset(cb_va)
    if cb_off is None:
        return

    for _cb_i in range(1024):
        if cb_off + ptr_size > len(data):
            break
        v = struct.unpack_from(ptr_fmt, data, cb_off)[0]
        if v == 0:
            break
        pe.tls_callback_vas.append(v)
        cb_off += ptr_size


def linker_version_label(major: int, minor: int) -> str:
    mapping = {
        2: "MSVC 2.x",
        3: "MSVC 4.x",
        4: "MSVC 4.x",
        5: "MSVC 5.0",
        6: "MSVC 6.0",
        7: "MSVC 7.0 / VS .NET 2002",
        8: "MSVC 8.0 / VS 2005",
        9: "MSVC 9.0 / VS 2008",
        10: "MSVC 10.0 / VS 2010",
        11: "MSVC 11.0 / VS 2012",
        12: "MSVC 12.0 / VS 2013",
        14: "MSVC 14.x / VS 2015-2022",
    }
    return mapping.get(major, f"linker v{major}.{minor:02d}")


RESOURCE_TYPE_NAMES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}


def _read_resource_name(data: bytes, name_field: int, root_off: int) -> object:
    """Return either the integer ID, or the decoded UTF-16 name string."""
    if name_field & 0x80000000:
        name_off = root_off + (name_field & 0x7FFFFFFF)
        if name_off + 2 > len(data):
            return name_field & 0x7FFFFFFF
        length = struct.unpack_from("<H", data, name_off)[0]
        text_off = name_off + 2
        text_end = text_off + length * 2
        if text_end > len(data):
            return name_field & 0x7FFFFFFF
        return data[text_off:text_end].decode("utf-16-le", errors="replace")
    return name_field


def parse_resources(data: bytes, pe: PEInfo) -> None:
    rsrc_rva, rsrc_size = pe.get_data_directory(DIR_RESOURCE)
    if rsrc_rva == 0 or rsrc_size == 0:
        return
    root_off = pe.rva_to_file_offset(rsrc_rva)
    if root_off is None:
        return

    def walk_dir(dir_off: int, depth: int, path: tuple) -> None:
        # Limit recursion in malformed trees
        if depth > 8:
            return
        if dir_off + 16 > len(data):
            return
        n_named, n_id = struct.unpack_from("<HH", data, dir_off + 12)
        total = min(n_named + n_id, 65536)
        entry_off = dir_off + 16
        for _ in range(total):
            if entry_off + 8 > len(data):
                return
            name_field, data_field = struct.unpack_from("<II", data, entry_off)
            entry_off += 8
            name_val = _read_resource_name(data, name_field, root_off)
            if data_field & 0x80000000:
                sub_off = root_off + (data_field & 0x7FFFFFFF)
                walk_dir(sub_off, depth + 1, path + (name_val,))
            else:
                leaf_off = root_off + data_field
                if leaf_off + 16 > len(data):
                    continue
                leaf_rva, leaf_size, _cp, _rsv = struct.unpack_from(
                    "<IIII", data, leaf_off
                )
                if len(path) >= 2:
                    rtype, rid = path[0], path[1]
                else:
                    rtype, rid = path[0], None
                pe.resources.append(
                    PEResource(
                        rtype=rtype,
                        rid=rid,
                        language=name_val if isinstance(name_val, int) else 0,
                        rva=leaf_rva,
                        size=leaf_size,
                    )
                )

    walk_dir(root_off, 0, ())


def _align4(off: int) -> int:
    return (off + 3) & ~3


def _read_wstr(blob: bytes, off: int) -> tuple:
    """Return the UTF-16 string and the offset after its terminator."""
    end = off
    while end + 1 < len(blob):
        if blob[end] == 0 and blob[end + 1] == 0:
            break
        end += 2
    text = blob[off:end].decode("utf-16-le", errors="replace")
    return text, end + 2


def _walk_versioninfo_node(blob: bytes, off: int, out: dict, base_off: int) -> int:
    """Read a version-info node and return the offset past it."""
    if off + 6 > len(blob):
        return len(blob)
    w_length, w_value_length, w_type = struct.unpack_from("<HHH", blob, off)
    node_end = off + w_length
    if w_length == 0 or node_end > len(blob):
        return len(blob)
    key, body_off = _read_wstr(blob, off + 6)
    body_off = _align4(body_off - base_off) + base_off

    value_end = body_off
    if (
        w_value_length > 0
        and body_off + (w_value_length * (2 if w_type == 1 else 1)) <= node_end
    ):
        if w_type == 1:
            value = blob[body_off : body_off + w_value_length * 2]
            if key not in {"VS_VERSION_INFO", "StringFileInfo", "VarFileInfo"}:
                out[key] = value.decode("utf-16-le", errors="replace").split("\x00", 1)[
                    0
                ]
            value_end = body_off + w_value_length * 2
        else:
            # Translation stores language and codepage pairs.
            if key == "Translation" and w_value_length >= 4:
                translations = []
                pair_off = body_off
                while pair_off + 4 <= node_end:
                    langid, codepage = struct.unpack_from("<HH", blob, pair_off)
                    translations.append(f"0x{langid:04X}/0x{codepage:04X}")
                    pair_off += 4
                    if pair_off - body_off >= w_value_length:
                        break
                out["Translation"] = ", ".join(translations)
            value_end = body_off + w_value_length
    value_end = _align4(value_end - base_off) + base_off

    child = value_end
    while child < node_end:
        next_child = _walk_versioninfo_node(blob, child, out, base_off)
        if next_child <= child:
            break
        child = _align4(next_child - base_off) + base_off

    return node_end


_UNWIND_OP_NAMES = {
    0: "PUSH_NONVOL",
    1: "ALLOC_LARGE",
    2: "ALLOC_SMALL",
    3: "SET_FPREG",
    4: "SAVE_NONVOL",
    5: "SAVE_NONVOL_FAR",
    6: "EPILOG",
    7: "SPARE_CODE",
    8: "SAVE_XMM128",
    9: "SAVE_XMM128_FAR",
    10: "PUSH_MACHFRAME",
}


def parse_clr_header(data: bytes, pe: PEInfo) -> None:
    clr_rva, clr_size = pe.get_data_directory(DIR_COM_DESCRIPTOR)
    if clr_rva == 0 or clr_size == 0:
        return
    f_off = pe.rva_to_file_offset(clr_rva)
    if f_off is None or f_off + 72 > len(data):
        return
    (
        cb_size,
        rt_major,
        rt_minor,
        md_rva,
        md_size,
        flags,
        entry_tok,
        res_rva,
        res_size,
        sn_rva,
        sn_size,
    ) = struct.unpack_from("<IHHIIIIIIII", data, f_off)
    pe.clr_header = CLRHeader(
        cb_size=cb_size,
        runtime_major=rt_major,
        runtime_minor=rt_minor,
        metadata_rva=md_rva,
        metadata_size=md_size,
        flags=flags,
        entry_point_token_or_rva=entry_tok,
        resources_rva=res_rva,
        resources_size=res_size,
        strong_name_signature_rva=sn_rva,
        strong_name_signature_size=sn_size,
    )


def parse_unwind_info(data: bytes, pe: PEInfo) -> None:
    if not pe.is_pe32_plus:
        return
    seen: Set[int] = set()
    for _begin, _end, raw_uw in pe.runtime_functions:
        uw = raw_uw & 0x7FFFFFFF
        if not uw or uw in seen:
            continue
        seen.add(uw)
        f_off = pe.rva_to_file_offset(uw)
        if f_off is None or f_off + 4 > len(data):
            continue
        version_flags, prolog_size, n_codes, frame = struct.unpack_from(
            "<BBBB", data, f_off
        )
        flags = version_flags >> 3

        codes_off = f_off + 4
        codes_end = codes_off + n_codes * 2
        if codes_end > len(data):
            continue
        codes: List[Tuple[int, str, int]] = []
        i = 0
        while i < n_codes:
            code_off = codes_off + i * 2
            offset_in_prolog = data[code_off]
            packed = data[code_off + 1]
            op = packed & 0x0F
            info = packed >> 4
            codes.append((offset_in_prolog, _UNWIND_OP_NAMES.get(op, f"op{op}"), info))
            # Skip the extra operands before reading the next unwind code
            extra_slots = {1: 1 + (1 if info else 0), 4: 1, 5: 2, 8: 1, 9: 2}.get(op, 0)
            i += 1 + extra_slots

        chained_rva: Optional[int] = None
        if flags & 0x04:  # UNW_FLAG_CHAININFO
            # The chained record follows the codes at a four-byte boundary
            chain_off = _align4(codes_end)
            if chain_off + 12 <= len(data):
                chained_rva = struct.unpack_from("<I", data, chain_off)[0]

        pe.unwind_info[uw] = UnwindInfo(
            version=version_flags & 0x07,
            flags=flags,
            prolog_size=prolog_size,
            frame_register=frame & 0x0F,
            frame_register_offset=(frame >> 4) * 16,
            codes=codes,
            chained_function_rva=chained_rva,
        )


def parse_coff_symtab(data: bytes, pe: PEInfo) -> None:
    if not pe.coff_symtab_ptr or not pe.coff_num_symbols:
        return
    base = pe.coff_symtab_ptr
    n_syms = pe.coff_num_symbols
    end = base + n_syms * 18
    if end > len(data):
        return
    str_table_off = end

    def _read_name(record_off: int) -> str:
        name_bytes = data[record_off : record_off + 8]
        # Long names use an offset into the string table
        if name_bytes[:4] == b"\x00\x00\x00\x00":
            str_off = struct.unpack_from("<I", name_bytes, 4)[0]
            abs_off = str_table_off + str_off
            if abs_off >= len(data):
                return ""
            return _read_cstr(data, abs_off)
        return name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    i = 0
    while i < min(n_syms, 1_000_000):
        rec = base + i * 18
        name = _read_name(rec)
        value, section_number, sym_type, storage_class, aux = struct.unpack_from(
            "<IhHBB", data, rec + 8
        )
        pe.coff_symbols.append(
            COFFSymbol(
                name=name,
                value=value,
                section_number=section_number,
                sym_type=sym_type,
                storage_class=storage_class,
                aux_records=aux,
            )
        )
        # Auxiliary records occupy symbol-table slots too
        i += 1 + aux


def parse_version_info(data: bytes, pe: PEInfo) -> None:
    for r in pe.resources:
        if not (isinstance(r.rtype, int) and r.rtype == 16):
            continue
        f_off = pe.rva_to_file_offset(r.rva)
        if f_off is None or f_off + r.size > len(data):
            continue
        blob = data[f_off : f_off + r.size]
        try:
            _walk_versioninfo_node(blob, 0, pe.version_info, 0)
        except Exception:
            log.write(f"Could not parse version info at RVA 0x{r.rva:X}", status="warn")


def init(target_bytes: bytes):
    global info, raw_image
    from ..segtypes.win32 import x86

    translation_units.clear()
    translation_units_by_name.clear()
    x86.reset()
    info = parse_pe(target_bytes)
    raw_image = target_bytes
    if info.machine not in (MACHINE_I386, MACHINE_AMD64):
        log.error(
            f"Unsupported machine type 0x{info.machine:04X} (expected i386 or amd64)"
        )
