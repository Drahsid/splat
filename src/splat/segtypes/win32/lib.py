from pathlib import Path

from ...util import log, options
from ..linker_entry import clean_up_path
from .unit import Win32Unit


class Win32SegLib(Win32Unit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if isinstance(self.yaml, dict):
            library = self.yaml.get("library")
            self.object = self.yaml.get("object")
            if "section" in self.yaml:
                log.error(
                    f"Segment '{self.name}': use 'linker_section' instead of 'section'"
                )
        else:
            library = self.args[0] if self.args else None
            self.object = self.args[1] if len(self.args) > 1 else None
            if len(self.args) > 2:
                log.error(
                    f"Segment '{self.name}': use dict syntax to set 'linker_section'"
                )
        if not library or not self.object:
            log.error(f"Segment '{self.name}' requires 'library' and 'object'")
        self.library = clean_up_path(options.opts.base_path / library)

    def get_linker_section(self) -> str:
        return (self.linker_section or ".text").split("$", 1)[0]

    def source_path(self) -> Path:
        return options.opts.build_path / "lib" / self.dir / f"{self.name}.obj"
