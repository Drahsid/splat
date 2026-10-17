from typing import Optional

from .data import Win32SegData


class Win32SegRodata(Win32SegData):
    SECTION = ".rdata"

    @staticmethod
    def is_data() -> bool:
        return False

    @staticmethod
    def is_rodata() -> bool:
        return True

    def get_section_flags(self) -> Optional[str]:
        return "dr"
