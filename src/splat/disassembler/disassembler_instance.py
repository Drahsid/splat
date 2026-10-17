from .disassembler import Disassembler
from .spimdisasm_disassembler import SpimdisasmDisassembler
from .iced_x86_disassembler import IcedX86Disassembler
from .null_disassembler import NullDisassembler

from ..util import options

__instance: Disassembler = NullDisassembler()
__initialized = False


def create_disassembler_instance(skip_version_check: bool, splat_version: str):
    global __instance
    global __initialized
    if options.opts.platform in ["n64", "psx", "ps2", "psp"]:
        __instance = SpimdisasmDisassembler()
    elif options.opts.platform == "win32":
        __instance = IcedX86Disassembler()
    else:
        raise NotImplementedError("No disassembler for requested platform")

    __initialized = True
    __instance.check_version(skip_version_check, splat_version)
    __instance.configure()


def get_instance() -> Disassembler:
    global __instance
    global __initialized
    if not __initialized:
        raise Exception("Disassembler instance not initialized")  # noqa: TRY002
    return __instance
