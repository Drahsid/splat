from .unit import Win32Unit
from . import x86
from .output import write_assembly
from ..linker_entry import clean_up_path, write_file_if_different
from ...util import options


class Win32SegCpp(Win32Unit):
    EXTENSION = "cpp"

    def should_split(self) -> bool:
        return self.extract and options.opts.is_mode_active("code")

    def split(self, rom_bytes: bytes):
        assert self.vram_start is not None, f"{self.name}: missing vram"
        assert self.vram_end is not None, f"{self.name}: missing code bounds"
        program = x86.program()
        starts = sorted(
            {self.vram_start}
            | {
                address
                for address in program.functions
                if self.vram_start <= address < self.vram_end
                and program.is_instruction(address)
            }
        )
        includes = []
        for start, end in zip(starts, starts[1:] + [self.vram_end]):
            path = (
                options.opts.nonmatchings_path / self.dir / self.name / f"{start:08X}.s"
            )
            relative = clean_up_path(path).as_posix()
            write_assembly(
                path,
                program.write_code,
                start,
                end,
                f'.section ".text${relative}", "xr"',
            )
            includes.append(f'INCLUDE_ASM("{relative}");\n')
        source = self.source_path()
        if not source.exists():
            write_file_if_different(source, '#include "asm.h"\n\n' + "".join(includes))
