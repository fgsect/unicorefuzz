import time
import signal
import sys
from typing import List

from avatar2 import Architecture
from capstone import *
from unicorn import *

import unicorefuzz.unicorefuzz
from unicorefuzz import x64utils
from unicorefuzz import unicorefuzz

from uDdbg.utils import *

UNICORE_PATH = os.path.dirname(os.path.abspath(__file__))


def regs_from_unicorn(arch: Architecture) -> List[str]:
    """
    Get all (supported) registers of an arch from Unicorn constants
    """
    # noinspection PyUnresolvedReferences
    consts = arch.unicorn_consts
    regs = [
        k.split("_REG_")[1].lower()
        for k, v in consts.__dict__.items()
        if not k.startswith("__") and "_REG_" in k and not "INVALID" in k
    ]
    if arch == unicorefuzz.X64:
        # These two are not directly supported by unicorn.
        regs += ["gs_base", "fs_base"]
    return regs


def uc_reg_const(arch: Architecture, reg_name: str) -> int:
    """
    Returns an unicorn register constant to address the register by name.
    i.e.:
    `uc_reg_const("x64", "rip") #-> UC_X86_REG_RIP`
    """
    # noinspection PyUnresolvedReferences
    return getattr(arch.unicorn_consts, arch.unicorn_reg_tag + reg_name.upper())


def uc_get_pc(uc: Uc, arch: Architecture) -> int:
    """
    Gets the current program counter from a unicorn instance
    """
    # noinspection PyUnresolvedReferences
    return uc.reg_read(uc_reg_const(arch, arch.pc_name))


def get_base(page_size: int, address: int) -> int:
    """
    Calculates the base address (aligned to PAGE_SIZE) to an address
    All you base are belong to us.
    """
    return address - address % page_size



