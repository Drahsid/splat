from pathlib import Path
from typing import Dict, Optional, Tuple

from ..common.segment import CommonSegment
from ..segment import Segment
from ...platforms import win32
from ...util import log, options


def unit_for(key: Path) -> Optional["Win32Unit"]:
    # Wait until parents are assigned so unit paths include their directories
    if not win32.translation_units_by_name:
        for unit in win32.translation_units:
            unit_key = unit.dir / unit.name
            if unit_key in win32.translation_units_by_name:
                log.error(f"Duplicate code segment '{unit_key}'")
            win32.translation_units_by_name[unit_key] = unit
    return win32.translation_units_by_name.get(key)


def unit_source(segment: Segment) -> Path:
    key = segment.dir / segment.name
    unit = unit_for(key)
    if unit is None:
        log.error(f"No matching code segment for '{segment.type}' segment '{key}'")
    unit.record_contribution(segment)
    return unit.out_path()


class Win32Unit(CommonSegment):
    EXTENSION = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        win32.translation_units.append(self)
        win32.translation_units_by_name.clear()
        self.contributions: Dict[str, Tuple[int, int]] = {}

    @staticmethod
    def is_text() -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def record_contribution(self, segment: Segment):
        section = segment.get_linker_section_linksection()
        low, high = segment.vram_start, segment.vram_end
        assert low is not None and high is not None, (
            f"{segment.name}: missing vram bounds"
        )
        previous = self.contributions.get(section)
        if previous is not None:
            if low > previous[1] or high < previous[0]:
                log.error(
                    f"Segment '{self.dir / self.name}' has separate '{section}' ranges. "
                    "Use different linker_section names."
                )
            low, high = min(low, previous[0]), max(high, previous[1])
        self.contributions[section] = (low, high)

    def source_path(self) -> Path:
        return options.opts.src_path / self.dir / f"{self.name}.{self.EXTENSION}"

    def out_path(self) -> Path:
        unit_for(self.dir / self.name)
        self.record_contribution(self)
        return self.source_path()

    def should_split(self) -> bool:
        return False
