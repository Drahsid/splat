from importlib.metadata import PackageNotFoundError, version
from typing import Set

from .disassembler import Disassembler
from ..util import log


SCALAR_SIZES = {
    "u8": 1,
    "s8": 1,
    "char": 1,
    "u16": 2,
    "s16": 2,
    "u32": 4,
    "s32": 4,
    "f32": 4,
    "u64": 8,
    "s64": 8,
    "f64": 8,
}


class IcedX86Disassembler(Disassembler):
    def configure(self):
        pass

    def check_version(self, skip_version_check: bool, splat_version: str):
        try:
            installed = version("iced-x86")
        except PackageNotFoundError:
            log.error("The win32 platform requires iced-x86. Install 'splat64[win32]'.")
        if not skip_version_check:
            if tuple(int(part) for part in installed.split(".")[:2]) < (1, 21):
                log.error(
                    f"splat {splat_version} requires iced-x86 >=1.21.0; found {installed}"
                )
            log.write(f"splat {splat_version} (powered by iced-x86 {installed})")

    def known_types(self) -> Set[str]:
        return set(SCALAR_SIZES) | {"char*", "asciz"}
