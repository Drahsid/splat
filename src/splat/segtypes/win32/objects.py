"""COFF object inputs for Win32 splits and linker scripts."""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
import re
import struct
import subprocess
import os
from pathlib import Path

from ...util.coff import (
    CLASS_EXTERNAL,
    CLASS_STATIC,
    CLASS_WEAK_EXTERNAL,
    LNK_COMDAT,
    LNK_INFO,
    LNK_REMOVE,
    SELECT_ASSOCIATIVE,
    CoffObject,
    CoffSection,
    CoffSymbol,
    append_symbols,
    fold_sections,
    linker_requirements,
    reference_sections,
    rename_symbols,
    select_sections,
)
from .cpp import assembly_includes, function_ranges
from . import x86
from ..linker_entry import path_to_object_path, write_file_if_different
from ...util import options, symbols
from ...platforms import win32


@dataclass
class TargetSection:
    address: int
    body: bytes
    raw_size: int
    code: bool
    writable: bool


@dataclass
class ObjectInput:
    source: Path
    output: Path
    coff: CoffObject
    is_library: bool
    bounds: Tuple[int, int]
    ranges: List[Tuple[int, int, str]] = field(default_factory=list)
    assembly: Dict[Path, Tuple[int, int]] = field(default_factory=dict)
    sections: List[CoffSection] = field(default_factory=list)
    definitions: Dict[int, List[CoffSymbol]] = field(default_factory=dict)
    masks: Dict[int, bytearray] = field(default_factory=dict)
    unsupported: Set[int] = field(default_factory=set)

    def __post_init__(self):
        for section in self.coff.sections:
            if (
                not section.size
                or section.flags & (LNK_INFO | LNK_REMOVE)
                or section.name.startswith((".debug", ".drectve"))
            ):
                continue

            self.sections.append(section)
            mask = bytearray(b"\1" * section.size)
            for relocation in section.relocations:
                if (
                    relocation.kind not in (6, 20)
                    or relocation.offset + 4 > section.size
                ):
                    self.unsupported.add(section.index)
                    continue

                mask[relocation.offset : relocation.offset + 4] = b"\0" * 4

            self.masks[section.index] = mask
            self.definitions[section.index] = []

        for symbol in self.coff.symbols.values():
            if symbol.storage == CLASS_EXTERNAL and symbol.section in self.definitions:
                self.definitions[symbol.section].append(symbol)


def target_sections(image: win32.PEInfo, data: bytes) -> List[TargetSection]:
    result = []

    for section in image.sections:
        raw_size = min(section.raw_size, section.virtual_size)
        body = data[section.raw_pointer : section.raw_pointer + raw_size]
        body += bytes(max(0, section.virtual_size - len(body)))
        result.append(
            TargetSection(
                image.image_base + section.virtual_address,
                body,
                raw_size,
                section.is_code,
                section.is_writable,
            )
        )

    return result


def _section_kind(name):
    return ".text" if name == ".text$mn" or name.startswith(".text$asm/") else name


def _bytes(images, address, size):
    for image in images:
        offset = address - image.address
        if 0 <= offset and offset + size <= len(image.body):
            return image.body[offset : offset + size]

    return None


def _allowed(unit, section, address, images, owned=True):
    if owned and not any(
        start <= address
        and address + section.size <= end
        and kind == _section_kind(section.name)
        for start, end, kind in unit.ranges
    ):
        return False

    for image in images:
        offset = address - image.address
        if 0 <= offset and offset + section.size <= len(image.body):
            if (
                section.code != image.code
                or bool(section.flags & win32.SCN_MEM_WRITE) != image.writable
            ):
                return False

            if not section.raw:
                return offset >= image.raw_size

            return offset + section.size <= image.raw_size

    return False


def _expected(unit, symbol, addresses, placements):
    if (
        symbol.storage in (CLASS_EXTERNAL, CLASS_WEAK_EXTERNAL)
        and symbol.name in addresses
    ):
        return addresses[symbol.name]

    if symbol.storage == CLASS_EXTERNAL:
        encoded = re.fullmatch(r"_(?:D|func)_([0-9A-F]{8})", symbol.name)
        if encoded:
            return int(encoded[1], 16)

    if symbol.storage == CLASS_WEAK_EXTERNAL:
        return _expected(
            unit, unit.coff.symbols[symbol.weak_target], addresses, placements
        )

    if symbol.section > 0 and symbol.section in placements:
        return placements[symbol.section] + symbol.value

    if symbol.section == -1:
        return symbol.value

    return None


def _observed(section, relocation, actual, address):
    offset = relocation.offset
    addend = struct.unpack_from("<I", section.body, offset)[0]
    result = struct.unpack_from("<I", actual, offset)[0] - addend
    if relocation.kind == 20:
        result += address + offset + 4

    return result & 0xFFFFFFFF


def _check(unit, section, address, images, addresses, placements, observation=False):
    if (
        section.index in unit.unsupported
        or address % section.alignment
        or not _allowed(unit, section, address, images, not observation)
    ):
        return False

    actual = _bytes(images, address, section.size)
    if any(
        mask and byte != actual[index]
        for index, (mask, byte) in enumerate(
            zip(unit.masks[section.index], section.body)
        )
    ):
        return False

    for symbol in unit.definitions[section.index]:
        if (
            symbol.name in addresses
            and addresses[symbol.name] != address + symbol.value
        ):
            return False

    for relocation in section.relocations:
        expected = _expected(unit, relocation.symbol, addresses, placements)
        if (
            expected is not None
            and _observed(section, relocation, actual, address) != expected
        ):
            return False

    return True


def _find(unit, section, images, addresses, placements, hints):
    anchored = {
        addresses[symbol.name] - symbol.value
        for symbol in unit.definitions[section.index]
        if symbol.name in addresses
    }
    canonical = bool(anchored)
    if not anchored:
        anchored = {
            hints[symbol.name] - symbol.value
            for symbol in unit.definitions[section.index]
            if symbol.name in hints
        }

    if anchored:
        if len(anchored) != 1:
            return []

        address = next(iter(anchored))
        return (
            [address]
            if _check(unit, section, address, images, addresses, placements, canonical)
            else []
        )

    if not section.code and not section.flags & LNK_COMDAT:
        whole = {
            start
            for start, end, kind in unit.ranges
            if end - start == section.size and kind == section.name
        }
        if whole:
            return [
                address
                for address in whole
                if _check(unit, section, address, images, addresses, placements)
            ]

    if (
        not section.raw
        or section.index in unit.unsupported
        or (not section.code and sum(unit.masks[section.index]) < 16)
    ):
        return []

    offset, end = max(
        (match.span() for match in re.finditer(rb"\x01+", unit.masks[section.index])),
        key=lambda span: (span[1] - span[0], span[0]),
        default=(0, 0),
    )
    length = end - offset
    if not section.code and length < 8:
        return []

    anchor = section.body[offset : offset + length]
    found = []

    for lower, upper, kind in unit.ranges:
        if kind != _section_kind(section.name):
            continue

        body = _bytes(images, lower, upper - lower)
        if body is None:
            continue

        cursor = 0
        while True:
            hit = body.find(anchor, cursor)
            if hit < 0:
                break

            cursor = hit + 1
            address = lower + hit - offset
            if _check(unit, section, address, images, addresses, placements):
                found.append(address)
                if len(found) == 2:
                    return found

    return found


def _place(unit, images, addresses, hints=None):
    placements = {}
    by_index = {section.index: section for section in unit.sections}
    associated = associated_sections(unit)

    for section in unit.sections:
        found = _find(unit, section, images, addresses, placements, hints or {})
        if len(found) == 1:
            placements[section.index] = found[0]

    changed = True
    while changed:
        changed = False
        for section in unit.sections:
            address = placements.get(section.index)
            if address is None:
                continue

            actual = _bytes(images, address, section.size)
            for relocation in section.relocations:
                symbol = relocation.symbol
                other = by_index.get(symbol.section)
                if other is None or other.index in placements:
                    continue

                inferred = (
                    _observed(section, relocation, actual, address) - symbol.value
                ) & 0xFFFFFFFF
                if _check(
                    unit,
                    other,
                    inferred,
                    images,
                    addresses,
                    placements,
                    other.index in associated,
                ):
                    placements[other.index] = inferred
                    changed = True

    return placements


def _issues(unit, section, address, images, addresses, placements):
    actual = _bytes(images, address, section.size)
    unresolved = []
    mismatched = []

    for relocation in section.relocations:
        expected = _expected(unit, relocation.symbol, addresses, placements)
        if expected is None:
            unresolved.append(relocation.symbol.name)
        elif _observed(section, relocation, actual, address) != expected:
            mismatched.append(relocation.symbol.name)

    return unresolved, mismatched


def _resolve_candidates(output, candidates, images, manual_addresses):
    remaining = [dict(placements) for _, placements in output]

    while True:
        proposals = {}
        for (unit, _), placements, eligible in zip(output, remaining, candidates):
            for section in unit.sections:
                if section.index not in eligible or section.index not in placements:
                    continue

                for symbol in unit.definitions[section.index]:
                    target = placements[section.index] + symbol.value
                    proposals.setdefault(symbol.name, set()).add(target)

        addresses = dict(manual_addresses)
        conflicts = []
        for name, values in proposals.items():
            if len(values) == 1:
                addresses[name] = next(iter(values))
            else:
                conflicts.append(name)

        changed = False
        for (unit, _), placements, eligible in zip(output, remaining, candidates):
            for section in unit.sections:
                address = placements.get(section.index)
                if address is None:
                    continue

                if (
                    section.index not in eligible
                    and _allowed(unit, section, address, images)
                ) or any(
                    _issues(unit, section, address, images, addresses, placements)
                ):
                    del placements[section.index]
                    changed = True

        if not changed:
            return addresses, conflicts


def resolve_objects(units, images, manual_addresses):
    addresses = dict(manual_addresses)
    definitions = {
        symbol.name
        for unit in units
        for section in unit.sections
        for symbol in unit.definitions[section.index]
    }
    hints = {}

    for _ in range(16):
        candidates = []
        references = {}
        output = [(unit, _place(unit, images, addresses, hints)) for unit in units]
        for unit, placements in output:
            eligible = set()
            candidates.append(eligible)
            anchored = [
                (
                    section.index,
                    placements[section.index],
                    placements[section.index] + section.size,
                )
                for section in unit.sections
                if section.index in placements
                and (
                    not section.flags & LNK_COMDAT
                    or any(
                        symbol.name in manual_addresses
                        and manual_addresses[symbol.name]
                        == placements[section.index] + symbol.value
                        for symbol in unit.definitions[section.index]
                    )
                )
            ]

            matched_code = [
                (placements[section.index], section.size)
                for section in unit.sections
                if section.code
                and section.index in placements
                and _allowed(unit, section, placements[section.index], images)
                and not any(
                    _issues(
                        unit,
                        section,
                        placements[section.index],
                        images,
                        addresses,
                        placements,
                    )
                )
            ]

            for section in unit.sections:
                address = placements.get(section.index)
                if address is None:
                    continue

                _, mismatched = _issues(
                    unit, section, address, images, addresses, placements
                )
                if not mismatched:
                    actual = _bytes(images, address, section.size)
                    for relocation in section.relocations:
                        symbol = relocation.symbol
                        if (
                            symbol.storage == CLASS_EXTERNAL
                            and symbol.name in definitions
                            and symbol.name not in addresses
                        ):
                            references.setdefault(symbol.name, set()).add(
                                _observed(section, relocation, actual, address)
                            )

                overlap = bool(
                    section.flags & LNK_COMDAT
                    and (
                        any(
                            index != section.index
                            and start < address + section.size
                            and end > address
                            for index, start, end in anchored
                        )
                        or any(
                            size > section.size
                            and start <= address
                            and address + section.size <= start + size
                            for start, size in matched_code
                        )
                    )
                )
                if (
                    _allowed(unit, section, address, images)
                    and not overlap
                    and not mismatched
                ):
                    eligible.add(section.index)

        following, conflicts = _resolve_candidates(
            output, candidates, images, manual_addresses
        )
        following_hints = {
            name: next(iter(values))
            for name, values in references.items()
            if len(values) == 1
        }
        if following == addresses and following_hints == hints:
            if conflicts:
                raise ValueError(f"conflicting definitions for {conflicts[0]}")

            return following, output

        addresses = following
        hints = following_hints

    raise ValueError("object symbol discovery did not converge")


@dataclass
class ObjectSelection:
    unit: ObjectInput
    placements: Dict[int, int]
    contents: bytearray
    requirements: Dict[str, Tuple[str, ...]]
    sections: List[CoffSection]
    folded: Dict[int, int]
    references: Dict[int, str]


def associated_sections(unit):
    associated = {}
    for symbol in unit.coff.symbols.values():
        if (
            symbol.storage == CLASS_STATIC
            and symbol.auxiliary
            and symbol.section in unit.definitions
            and not symbol.value
            and not symbol.kind
            and symbol.name == unit.coff.sections[symbol.section - 1].name
        ):
            parent, kind = struct.unpack_from("<HB", unit.coff.data, symbol.offset + 30)
            if kind == SELECT_ASSOCIATIVE:
                associated[symbol.section] = parent

    return associated


def select_object(unit, placements, images, addresses) -> ObjectSelection:
    ranges = [(start, end) for start, end, _ in unit.ranges]
    static_functions = {
        symbol.section
        for symbol in unit.coff.symbols.values()
        if symbol.storage == CLASS_STATIC and symbol.kind & 0x20
    }
    roots = tuple(
        section.index
        for section in unit.sections
        if section.code
        and section.flags & LNK_COMDAT
        and section.index in static_functions
        and not unit.definitions[section.index]
        and section.index in placements
        and _allowed(unit, section, placements[section.index], images)
    )
    contents, forced, removed = select_sections(unit.coff, addresses, ranges, roots)
    sections = [section for section in unit.sections if section.index not in removed]
    occupied = []
    associated = associated_sections(unit)
    shared = set()
    providers = {}
    folded = {}

    for section in sections:
        address = placements.get(section.index)
        if address is None or not _check(
            unit,
            section,
            address,
            images,
            addresses,
            placements,
            section.index in associated,
        ):
            raise ValueError(f"{unit.source}: unplaced section {section.index}")

        unresolved, mismatched = _issues(
            unit, section, address, images, addresses, placements
        )
        if unresolved or mismatched:
            raise ValueError(
                f"{unit.source}: unresolved section {section.index}: {unresolved + mismatched}"
            )

        if not _allowed(unit, section, address, images):
            shared.add(section.index)
            continue

        if (
            section.code
            and section.flags & LNK_COMDAT
            and section.index not in associated
            and section.index not in associated.values()
        ):
            key = (
                address,
                section.name,
                section.body,
                tuple(
                    (
                        relocation.offset,
                        relocation.kind,
                        _expected(unit, relocation.symbol, addresses, placements),
                    )
                    for relocation in section.relocations
                ),
            )
            if key in providers:
                folded[section.index] = providers[key]
                continue
            providers[key] = section.index

        occupied.append((address, address + section.size))

    occupied.sort()
    if any(end > following for (_, end), (following, _) in zip(occupied, occupied[1:])):
        raise ValueError(f"{unit.source}: overlapping retained sections")

    sections = [section for section in sections if section.index not in shared]
    references = {}
    for section in sections:
        for relocation in section.relocations:
            symbol = relocation.symbol
            if symbol.section in shared:
                address = placements[symbol.section] + symbol.value
                prefix = "L_" if unit.coff.sections[symbol.section - 1].code else "_D_"
                references[symbol.index] = f"{prefix}{address:08X}"
    if shared:
        reference_sections(unit.coff, contents, shared, references)

    return ObjectSelection(
        unit, placements, contents, forced, sections, folded, references
    )


def fold_references(selected):
    candidates = []
    providers = {}

    for selection in selected:
        unit = selection.unit
        associated = associated_sections(unit)

        retained = {section.index for section in selection.sections}
        for section in unit.sections:
            definitions = unit.definitions[section.index]
            if (
                not section.code
                or not section.flags & LNK_COMDAT
                or section.relocations
                or section.index in associated
                or section.index in associated.values()
                or section.index in selection.folded
                or section.index not in selection.placements
                or len(definitions) != 1
                or definitions[0].value
                or not definitions[0].kind & 0x20
            ):
                continue

            key = (selection.placements[section.index], section.body)
            symbol = definitions[0]
            if section.index in retained:
                providers.setdefault(key, []).append(symbol.name)
            else:
                candidates.append((key, symbol))

    names = {}
    for key, symbol in candidates:
        found = providers.get(key, [])
        if len(found) == 1 and found[0] != symbol.name:
            names[symbol.name] = found[0]

    for selection in selected:
        retained = {section.index for section in selection.sections}
        renames = {
            symbol.index: names[symbol.name]
            for symbol in selection.unit.coff.symbols.values()
            if symbol.storage in (CLASS_EXTERNAL, CLASS_WEAK_EXTERNAL)
            and symbol.section not in retained
            and symbol.name in names
        }
        if renames:
            rename_symbols(selection.unit.coff, selection.contents, renames)

        selection.requirements = {
            name: tuple(names.get(item, item) for item in chain)
            for name, chain in selection.requirements.items()
        }


def _static_functions(selection):
    unit = selection.unit
    sections = {
        section.index
        for section in selection.sections
        if section.code and section.index not in selection.folded
    }
    external = {
        symbol.name: (symbol.section, symbol.value)
        for symbol in unit.coff.symbols.values()
        if symbol.storage == CLASS_EXTERNAL and symbol.section in sections
    }
    functions = {
        f"_func_{selection.placements[symbol.section] + symbol.value:08X}": symbol
        for symbol in unit.coff.symbols.values()
        if symbol.storage == CLASS_STATIC
        and symbol.kind & 0x20
        and symbol.section in sections
        and (symbol.section, symbol.value) not in external.values()
    }
    for name in functions:
        if name in external:
            raise ValueError(f"{unit.source}: conflicting static function label {name}")

    return functions


def symbol_records(selected, manual):
    records = {}

    for selection in selected:
        unit = selection.unit
        for name, symbol in _static_functions(selection).items():
            if name not in manual:
                records[name] = (
                    selection.placements[symbol.section] + symbol.value,
                    "type:func",
                )
        for index, name in selection.references.items():
            symbol = unit.coff.symbols[index]
            kind = "label" if unit.coff.sections[symbol.section - 1].code else "u8"
            records[name] = (
                selection.placements[symbol.section] + symbol.value,
                f"type:{kind}",
            )
        for section in selection.sections:
            address = selection.placements[section.index]
            definitions = sorted(
                unit.definitions[section.index], key=lambda symbol: symbol.value
            )

            for symbol in definitions:
                kind = (
                    ("func" if symbol.kind & 0x20 else "label")
                    if section.code
                    else "u8"
                )
                attributes = f"type:{kind}"
                source_function = kind == "func" and not unit.is_library
                if kind == "u8" or section.flags & LNK_COMDAT or source_function:
                    boundaries = (
                        unit.coff.symbols.values()
                        if kind == "u8" or source_function
                        else definitions
                    )
                    end = min(
                        (
                            other.value
                            for other in boundaries
                            if other.section == section.index
                            and other.value > symbol.value
                            and (not source_function or other.kind & 0x20)
                        ),
                        default=section.size,
                    )
                    attributes += f" size:0x{end - symbol.value:X}"

                if kind == "u8" and not section.relocations:
                    attributes += " can_reference:false"

                if symbol.name not in manual:
                    records[symbol.name] = (address + symbol.value, attributes)

    return records


def symbol_lines(records):
    counts = {}

    for address, _ in records.values():
        counts[address] = counts.get(address, 0) + 1

    return [
        f"{name} = 0x{address:08X}; // {attributes}"
        + (" allow_duplicated:true" if counts[address] > 1 else "")
        for name, (address, attributes) in sorted(
            records.items(), key=lambda item: (item[1][0], item[0])
        )
    ]


@dataclass
class Contribution:
    start: int
    end: int
    alignment: int
    path: Path
    section: str
    kind: str


contributions: Dict[Path, List[Contribution]] = {}
requirements: Set[str] = set()


def reset():
    contributions.clear()
    requirements.clear()


def read_member(library: Path, member: str, listings: Dict[Path, List[str]]) -> bytes:
    if library not in listings:
        listings[library] = subprocess.check_output(
            [os.environ.get("AR", "ar"), "t", str(library)], text=True
        ).splitlines()

    member = member.replace("\\", "/")
    matches = [
        name
        for name in listings[library]
        if (
            name.replace("\\", "/") == member
            if "/" in member
            else name.replace("\\", "/").rsplit("/", 1)[-1] == member
        )
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{library}: expected one member {member}, found {len(matches)}"
        )

    return subprocess.check_output(
        [os.environ.get("AR", "ar"), "pP", str(library), matches[0]]
    )


def load_objects(segments) -> List[ObjectInput]:
    entries = [entry for segment in segments for entry in segment.get_linker_entries()]
    owners = {
        entry.object_path: entry
        for entry in entries
        if entry.segment.type in ("lib", "c", "cpp")
    }
    grouped = {path: [] for path in owners}

    for entry in entries:
        if entry.object_path in grouped:
            grouped[entry.object_path].append(entry)

    listings: Dict[Path, List[str]] = {}
    objects = []

    for output, owner in owners.items():
        source = owner.src_paths[0]
        is_library = owner.segment.type == "lib"

        if is_library:
            if not owner.segment.library.exists():
                continue

            data = read_member(owner.segment.library, owner.segment.object, listings)
        else:
            compiled = output.with_suffix(".obj")
            if not compiled.exists() or not source.exists():
                continue

            data = compiled.read_bytes()

        bounds = (owner.segment.vram_start, owner.segment.vram_end)
        unit = ObjectInput(source, output, CoffObject.parse(data), is_library, bounds)
        for entry in grouped[output]:
            low, high = entry.segment.vram_start, entry.segment.vram_end
            unit.ranges.append((low, high, entry.section_link))

        objects.append(unit)

    return objects


def add_symbols(records, segments):
    symbols.handle_sym_addrs(
        options.opts.build_path / "objects",
        symbol_lines(records),
        segments,
    )
    x86.reset()


def write_object(selection):
    unit = selection.unit
    contents = selection.contents
    requirements.update(linker_requirements(selection.requirements))
    parts = []
    if selection.folded:
        fold_sections(unit.coff, contents, selection.folded)

    functions = _static_functions(selection)
    if functions:
        append_symbols(
            contents,
            [
                (name, symbol.value, symbol.section, symbol.kind)
                for name, symbol in functions.items()
            ],
        )

    for section in selection.sections:
        if section.index in selection.folded:
            continue

        start = selection.placements[section.index]
        name = f".n{section.index:X}"
        contents[section.header : section.header + 8] = name.encode().ljust(8, b"\0")
        parts.append(
            Contribution(
                start,
                start + section.size,
                section.alignment,
                unit.output,
                name,
                _section_kind(section.name),
            )
        )

    for path, (start, end) in unit.assembly.items():
        parts.append(
            Contribution(
                start,
                end,
                x86.alignment(start, end),
                path_to_object_path(path),
                f".text${path.as_posix()}",
                ".text",
            )
        )

    parts.sort(key=lambda part: part.start)
    for previous, following in zip(parts, parts[1:]):
        if previous.end > following.start:
            raise ValueError(
                f"{unit.source}: overlapping contributions at 0x{following.start:X}"
            )

    contributions[unit.output] = parts
    write_file_if_different(unit.output, bytes(contents))


def prepare(segments, target: bytes):
    reset()
    objects = load_objects(segments)
    if not objects:
        return

    manual = {
        symbol.name: symbol.vram_start
        for symbol in symbols.get_all_symbols()
        if symbol.given_name
    }
    images = target_sections(win32.info, target)
    libraries = [unit for unit in objects if unit.is_library]
    sources = [unit for unit in objects if not unit.is_library]
    library_addresses, resolved = resolve_objects(libraries, images, manual)
    selected_libraries = [
        select_object(unit, placements, images, library_addresses)
        for unit, placements in resolved
    ]
    add_symbols(symbol_records(selected_libraries, manual), segments)

    for unit in sources:
        bounds = dict(function_ranges(*unit.bounds))
        for path in assembly_includes(unit.source):
            start = int(path.stem, 16)
            end = bounds[start]
            unit.assembly[path] = (start, end)
            unit.ranges = [
                (low, high, kind)
                for lower, upper, kind in unit.ranges
                for low, high in ((lower, min(upper, start)), (max(lower, end), upper))
                if low < high
            ]

    addresses, resolved = resolve_objects(sources, images, library_addresses)
    selected_sources = [
        select_object(unit, placements, images, addresses)
        for unit, placements in resolved
    ]
    add_symbols(symbol_records(selected_sources, manual), segments)

    if not options.opts.is_mode_active("ld"):
        return

    added_names = addresses.keys() - library_addresses.keys()
    for index, selection in enumerate(selected_libraries):
        if any(
            symbol.name in added_names
            for symbol in selection.unit.coff.symbols.values()
        ):
            selected_libraries[index] = select_object(
                selection.unit, selection.placements, images, addresses
            )

    selected = selected_libraries + selected_sources
    fold_references(selected)
    for selection in selected:
        unit = selection.unit
        if unit.assembly:
            bounds = dict(function_ranges(*unit.bounds))
            for path, (start, end) in unit.assembly.items():
                if bounds.get(start) != end:
                    raise ValueError(
                        f"{path}: function boundary changed during object discovery"
                    )

        write_object(selection)


def emit_entry(entry, writer) -> bool:
    if entry.object_path not in contributions:
        return False

    low, high = entry.segment.vram_start, entry.segment.vram_end
    for part in contributions[entry.object_path]:
        if part.kind != entry.section_link or not low <= part.start < high:
            continue

        if part.end > high:
            raise ValueError(f"{part.path}: section {part.section} crosses a split")

        message = f"{part.path}: {part.section}"
        writer._writeln(
            f'ASSERT(ALIGN(ABSOLUTE(.), {part.alignment}) == 0x{part.start:X}, "{message} start");'
        )
        writer._write_object_path_section(part.path, part.section)
        writer._writeln(f'ASSERT(ABSOLUTE(.) == 0x{part.end:X}, "{message} end");')

    return True
