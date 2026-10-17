from pathlib import Path
from typing import Optional

from ..common.segment import CommonSegment
from ...util import options
from . import x86
from .unit import unit_source
from .output import write_assembly


class Win32SegText(CommonSegment):
    @staticmethod
    def is_text() -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def get_section_flags(self) -> Optional[str]:
        return "xr"

    def out_path(self) -> Path:
        if self.type.startswith("."):
            return unit_source(self)
        return options.opts.asm_path / self.dir / f"{self.name}.s"

    def should_split(self) -> bool:
        return self.extract and options.opts.is_mode_active("code")

    def split(self, rom_bytes: bytes):
        assert self.vram_start is not None, f"{self.name}: missing vram"
        assert self.vram_end is not None, f"{self.name}: missing code bounds"
        write_assembly(
            self.out_path(),
            x86.program().write_code,
            self.vram_start,
            self.vram_end,
            self.get_section_asm_line(),
        )
