"""Read i386 COFF objects."""

from dataclasses import dataclass
import re
import struct
from typing import Dict, List, Optional, Set, Tuple

LNK_INFO = 0x200
LNK_REMOVE = 0x800
LNK_COMDAT = 0x1000
CLASS_EXTERNAL = 2
CLASS_STATIC = 3
CLASS_WEAK_EXTERNAL = 105
SELECT_ASSOCIATIVE = 5


@dataclass
class CoffSymbol:
    index: int
    offset: int
    name: str
    value: int
    section: int
    kind: int
    storage: int
    auxiliary: int
    weak_target: Optional[int] = None


@dataclass
class CoffRelocation:
    offset: int
    kind: int
    symbol: CoffSymbol


@dataclass
class CoffSection:
    index: int
    name: str
    header: int
    flags: int
    size: int
    raw: int
    line_count: int
    alignment: int
    code: bool
    body: bytes
    relocations: List[CoffRelocation]


@dataclass
class CoffObject:
    data: bytes
    sections: List[CoffSection]
    symbols: Dict[int, CoffSymbol]

    @classmethod
    def parse(cls, data: bytes) -> "CoffObject":
        def span(offset: int, size: int) -> None:
            if offset < 0 or size < 0 or offset + size > len(data):
                raise ValueError("truncated COFF object")

        span(0, 20)
        machine, count, _, symbol_table, symbol_count, optional_size, _ = (
            struct.unpack_from("<HHIIIHH", data)
        )
        if machine != 0x14C or optional_size:
            raise ValueError("expected an i386 COFF object")

        span(20, count * 40)
        span(symbol_table, symbol_count * 18 + 4)
        if symbol_table < 20 + count * 40:
            raise ValueError("invalid COFF symbol table")

        strings = symbol_table + symbol_count * 18
        string_size = struct.unpack_from("<I", data, strings)[0]
        if string_size < 4:
            raise ValueError("invalid COFF string table")

        span(strings, string_size)

        def string(offset: int) -> str:
            end = data.find(b"\0", strings + offset, strings + string_size)
            if not 4 <= offset < string_size or end < 0:
                raise ValueError("invalid COFF string")

            return data[strings + offset : end].decode("latin1")

        def name(raw: bytes) -> str:
            if raw[:4] == b"\0" * 4:
                return string(struct.unpack_from("<I", raw, 4)[0])

            return raw.rstrip(b"\0").decode("latin1")

        symbols: Dict[int, CoffSymbol] = {}
        index = 0
        while index < symbol_count:
            offset = symbol_table + index * 18
            raw, value, section, kind, storage, auxiliary = struct.unpack_from(
                "<8sIhHBB", data, offset
            )
            if section > count or index + auxiliary >= symbol_count:
                raise ValueError("invalid COFF symbol")

            symbol = CoffSymbol(
                index, offset, name(raw), value, section, kind, storage, auxiliary
            )
            if storage == CLASS_WEAK_EXTERNAL:
                if auxiliary != 1 or section:
                    raise ValueError("invalid COFF weak external")
                symbol.weak_target = struct.unpack_from("<I", data, offset + 18)[0]

            symbols[index] = symbol
            index += 1 + auxiliary

        sections = []
        for index in range(count):
            header = 20 + index * 40
            (
                raw_name,
                _,
                _,
                size,
                raw,
                relocations,
                lines,
                relocation_count,
                line_count,
                flags,
            ) = struct.unpack_from("<8sIIIIIIHHI", data, header)
            section_name = (
                string(int(raw_name[1:].rstrip(b"\0")))
                if raw_name.startswith(b"/")
                else name(raw_name)
            )
            if raw:
                span(raw, size)

            span(relocations, relocation_count * 10)
            span(lines, line_count * 6)
            if flags & 0x1000000:
                raise ValueError("COFF relocation overflow is unsupported")

            fields = []
            for offset in range(relocations, relocations + relocation_count * 10, 10):
                position, symbol, kind = struct.unpack_from("<IIH", data, offset)
                if symbol not in symbols:
                    raise ValueError("invalid COFF relocation symbol")

                fields.append(CoffRelocation(position, kind, symbols[symbol]))

            sections.append(
                CoffSection(
                    index + 1,
                    section_name,
                    header,
                    flags,
                    size,
                    raw,
                    line_count,
                    1 << max(0, ((flags >> 20) & 15) - 1),
                    bool(flags & 0x20),
                    data[raw : raw + size] if raw else bytes(size),
                    fields,
                )
            )

        return cls(data, sections, symbols)


def included_symbols(contents: bytes) -> Set[str]:
    token = re.compile(
        rb'[ \t\r\n]+|/(DEFAULTLIB|INCLUDE):(?:"([^"\x00-\x1f]+)"|([^"\x00-\x20]+))(?=[ \t\r\n]|$)',
        re.IGNORECASE,
    )
    names = set()
    cursor = 0
    while cursor < len(contents):
        match = token.match(contents, cursor)
        if match is None:
            raise ValueError(f"invalid MSVC directive at offset {cursor}")

        if match.group(1) and match.group(1).upper() == b"INCLUDE":
            names.add((match.group(2) or match.group(3)).decode("latin1"))

        cursor = match.end()

    return names


def linker_requirements(requirements: Dict[str, Tuple[str, ...]]) -> List[str]:
    def quote(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines = []
    for name, chain in sorted(requirements.items()):
        # COFF weak name as strong disables its fallback in ld
        lines.append(f"EXTERN({quote(chain[-1])})")
        condition = " || ".join(f"DEFINED({quote(candidate)})" for candidate in chain)
        lines.append(f"ASSERT({condition}, {quote('unresolved /INCLUDE: ' + name)})")

    return lines


def select_sections(
    obj: CoffObject, addresses: Dict[str, int], ranges: List[Tuple[int, int]]
) -> Tuple[bytearray, Dict[str, Tuple[str, ...]], Set[int]]:
    data = bytearray(obj.data)

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    sections = {section.index: section for section in obj.sections}
    linker_metadata: Set[int] = set()
    forced: Set[str] = set()

    for item in obj.sections:
        section, name, flags = item.index, item.name, item.flags
        if name in (".drectve", ".sxdata"):
            require(bool(item.raw) or not item.size, "linker metadata has no data")
            require(
                not item.relocations and not item.line_count and not flags & LNK_COMDAT,
                "linker metadata has relocations, line numbers or COMDAT ownership",
            )

            if name == ".drectve":
                forced.update(included_symbols(item.body))
            else:
                require(
                    bool(flags & LNK_INFO) and item.size % 4 == 0,
                    "invalid SafeSEH metadata",
                )

            linker_metadata.add(section)

    symbols = obj.symbols
    definitions: Dict[int, List[str]] = {}
    defined_symbols: Dict[str, Tuple[int, int]] = {}
    external_symbols: Dict[str, int] = {}
    weak_symbols: Dict[str, int] = {}
    parents: Dict[int, int] = {}
    section_aux: Dict[int, int] = {}
    children: Dict[int, List[int]] = {}

    for index, item in symbols.items():
        offset, name, value = item.offset, item.name, item.value
        section, kind, storage, aux_count = (
            item.section,
            item.kind,
            item.storage,
            item.auxiliary,
        )

        if storage in (CLASS_EXTERNAL, CLASS_WEAK_EXTERNAL):
            external_symbols.setdefault(name, index)
        if storage == CLASS_WEAK_EXTERNAL:
            weak_symbols[name] = index

        if section > 0 and storage == CLASS_EXTERNAL:
            definitions.setdefault(section, []).append(name)
            definition = (section, value)
            require(
                defined_symbols.setdefault(name, definition) == definition,
                "multiple external definitions: " + name,
            )

        if (
            storage == CLASS_STATIC
            and section > 0
            and aux_count
            and value == 0
            and kind == 0
            and name == sections[section].name
        ):
            require(
                aux_count == 1 and section not in section_aux,
                "invalid section definition",
            )

            section_aux[section] = offset + 18
            parent, selection = struct.unpack_from("<HB", data, offset + 18 + 12)
            if selection == SELECT_ASSOCIATIVE:
                require(
                    bool(sections[section].flags & LNK_COMDAT)
                    and parent in sections
                    and parent != section,
                    "invalid associative COMDAT parent",
                )

                parents[section] = parent
                children.setdefault(parent, []).append(section)

    owned_symbols = {
        symbol.name
        for symbol in symbols.values()
        if symbol.name in addresses
        and any(start <= addresses[symbol.name] < end for start, end in ranges)
    }

    def reference(index: int) -> Tuple[int, Tuple[str, ...]]:
        visited = set()
        names = []

        while True:
            require(index in symbols, "invalid relocation or weak external target")
            require(index not in visited, "cyclic weak externals")
            visited.add(index)
            symbol = symbols[index]
            name, section, storage = symbol.name, symbol.section, symbol.storage

            if not names or names[-1] != name:
                names.append(name)

            if storage in (CLASS_EXTERNAL, CLASS_WEAK_EXTERNAL):
                if name in defined_symbols:
                    return defined_symbols[name][0], tuple(names)

                if (
                    name in weak_symbols
                    and name in addresses
                    and name not in owned_symbols
                ):
                    return 0, tuple(names)

                if name in weak_symbols and index != weak_symbols[name]:
                    index = weak_symbols[name]
                    continue

            if symbol.weak_target is None:
                return section, tuple(names)

            index = symbol.weak_target

    def referenced_section(index: int) -> int:
        return reference(index)[0]

    requirements = {
        name: reference(external_symbols[name])[1]
        if name in external_symbols
        else (name,)
        for name in forced
    }

    for section in linker_metadata:
        require(
            not definitions.get(section), "linker metadata has external definitions"
        )

    removed = set()
    for section, item in sections.items():
        flags = item.flags
        if not flags & LNK_COMDAT:
            continue

        require(section in section_aux, "COMDAT has no section definition")
        if section in parents:
            continue

        names = definitions.get(section, [])
        # The first extern definition is the COMDAT key, static COMDATs have none
        if names and names[0] in addresses and names[0] not in owned_symbols:
            removed.add(section)

    for section in parents:
        ancestry = set()
        parent = section

        while parent in parents:
            require(parent not in ancestry, "cyclic associative COMDATs")
            ancestry.add(parent)
            parent = parents[parent]

        require(
            bool(sections[parent].flags & LNK_COMDAT),
            "associative parent is not a COMDAT",
        )
        if parent in removed:
            removed.add(section)

    # Ordinary sections
    live = set()
    forced_sections = {
        referenced_section(index)
        for index, symbol in symbols.items()
        if symbol.name in forced
        and symbol.storage in (CLASS_EXTERNAL, CLASS_WEAK_EXTERNAL)
    }

    for section, item in sections.items():
        flags = item.flags
        if (
            section in removed
            or section in linker_metadata
            or item.name.startswith(".debug")
        ):
            continue

        names = definitions.get(section, [])
        if (
            not flags & LNK_COMDAT
            or section in forced_sections
            or any(name in owned_symbols for name in names)
        ):
            live.add(section)

    pending = list(live)
    while pending:
        section = pending.pop()
        item = sections[section]
        targets = children.get(section, [])[:]
        if section in parents:
            targets.append(parents[section])
        targets.extend(
            referenced_section(relocation.symbol.index)
            for relocation in item.relocations
        )

        for target in targets:
            if target > 0 and target not in removed and target not in live:
                live.add(target)
                pending.append(target)

    removed.update(
        section
        for section, item in sections.items()
        if item.flags & LNK_COMDAT and section not in live
    )

    # Discarded externs can resolve by name, discarded locals cannot
    for section, item in sections.items():
        if section in removed:
            continue

        for relocation in item.relocations:
            symbol = relocation.symbol
            require(
                referenced_section(symbol.index) not in linker_metadata,
                "live relocation to linker metadata",
            )
            require(
                symbol.section not in removed or symbol.storage == CLASS_EXTERNAL,
                "live relocation to discarded local symbol " + symbol.name,
            )

    for symbol in symbols.values():
        if symbol.section in removed and symbol.storage == CLASS_EXTERNAL:
            struct.pack_into("<Ih", data, symbol.offset + 8, 0, 0)

    for section, item in sections.items():
        offset = item.header
        flags = item.flags & ~LNK_COMDAT
        if section in linker_metadata:
            # BFD processes linker metadata before /DISCARD/
            struct.pack_into("<II", data, offset + 16, 0, 0)
            if section in section_aux:
                struct.pack_into("<I", data, section_aux[section], 0)
        if section in removed:
            flags |= LNK_REMOVE
            data[offset : offset + 8] = b".discard"

        struct.pack_into("<I", data, offset + 36, flags)
        if section in section_aux:
            struct.pack_into("<HB", data, section_aux[section] + 12, 0, 0)

    return data, requirements, removed
