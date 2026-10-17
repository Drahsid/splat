from typing import Optional

from ..segment import SegmentStatistics, SegmentStatisticsInfo
from .data import Win32SegData


class Win32SegBss(Win32SegData):
    SECTION = ".bss"

    def get_section_flags(self) -> Optional[str]:
        if self.get_linker_section_linksection() == ".bss":
            return None
        return "bw"

    @staticmethod
    def is_data() -> bool:
        return False

    @staticmethod
    def is_noload() -> bool:
        return True

    @property
    def size(self) -> Optional[int]:
        if self.bss_size is not None:
            return self.bss_size
        return self.parse_bss_size(self.yaml)

    @property
    def statistics(self) -> SegmentStatistics:
        return {self.statistics_type: SegmentStatisticsInfo(size=0, count=1)}
