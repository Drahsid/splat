from io import StringIO
from pathlib import Path
import struct
from typing import Optional

from ..common.segment import CommonSegment
from ..linker_entry import write_file_if_different
from ...platforms import win32
from ...util import options
from .unit import unit_source


class Win32SegPdata(CommonSegment):
    @staticmethod
    def is_rodata() -> bool:
        return True

    @property
    def exact_encoding(self) -> bool:
        return win32.resolve_exact_encoding(self.yaml, self.parent)

    def get_linker_section(self) -> str:
        return ".pdata"

    def get_section_flags(self) -> Optional[str]:
        return "dr"

    def out_path(self) -> Path:
        if self.type.startswith("."):
            return unit_source(self)
        return options.opts.data_path / self.dir / f"{self.name}.s"

    def should_split(self) -> bool:
        return (
            self.extract
            and options.opts.is_mode_active("code")
            and self.rom_start is not None
            and self.rom_end is not None
        )

    def split(self, rom_bytes: bytes):
        if (
            self.rom_start is None
            or self.rom_end is None
            or self.rom_start == self.rom_end
        ):
            return

        pe = win32.info
        data = rom_bytes[self.rom_start : self.rom_end]
        exact = self.exact_encoding

        def resolve_func_rva(rva: int) -> str:
            va = pe.image_base + rva
            sym = self.get_symbol(va)
            if sym is not None:
                return sym.name
            return f"func_{va:08X}"

        path = self.out_path()
        with StringIO() as f:
            preamble = options.opts.generated_s_preamble
            if preamble:
                f.write(preamble + "\n\n")
            f.write(self.get_section_asm_line() + "\n\n")
            f.write(f".global {self.name}\n")
            f.write(f"{self.name}:\n")
            f.write("    /* Begin, end, unwind info (RVAs) */\n")

            offset = 0
            data_size = len(data)
            while offset + 12 <= data_size:
                begin, end, unwind = struct.unpack_from("<III", data, offset)
                if begin == 0 and end == 0 and unwind == 0:
                    f.write("    .long 0, 0, 0\n")
                    offset += 12
                    if not exact and offset < data_size:
                        f.write(f"    .space 0x{data_size - offset:X}\n")
                        offset = data_size
                    break
                if exact:
                    values = f"0x{begin:X}, 0x{end:X}, 0x{unwind:X}"
                else:
                    base_uw = unwind & 0x7FFFFFFF
                    symbol = (
                        self.get_symbol(pe.image_base + base_uw) if base_uw else None
                    )
                    uw_expr = f"0x{unwind:X}"
                    if symbol is not None:
                        # Keep the chained-record flag when replacing the address.
                        uw_expr = f"({symbol.name} - 0x{pe.image_base:X})"
                        if unwind & 0x80000000:
                            uw_expr += " | 0x80000000"
                    values = (
                        f"{resolve_func_rva(begin)} - 0x{pe.image_base:X}"
                        f", {resolve_func_rva(end)} - 0x{pe.image_base:X}"
                        f", {uw_expr}"
                    )
                f.write(f"    .long {values}\n")
                offset += 12

            if offset < data_size:
                tail = data[offset:]
                hexed = ", ".join(f"0x{b:02X}" for b in tail)
                f.write(f"    .byte {hexed}\n")

            write_file_if_different(path, f.getvalue())

        self.log(f"Wrote {self.name} to {path}")
