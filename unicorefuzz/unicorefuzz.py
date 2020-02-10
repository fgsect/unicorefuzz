"""
The heart of all ucf actions.
Defines most functionality used by the harnesses.
"""
import os
import signal
import time
from typing import List, Dict, Optional

from avatar2 import X86_64, ARM_CORTEX_M3, ARMV7M, ARMBE
from avatar2.archs import Architecture
from avatar2.archs.arm import ARM
from avatar2.archs.x86 import X86
from capstone import Cs
from unicornafl import (
    UC_ERR_READ_UNMAPPED,
    UC_ERR_READ_PROT,
    UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_WRITE_PROT,
    UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNALIGNED,
    UC_ERR_INSN_INVALID,
    UC_ARCH_X86,
    UC_MODE_32,
    UC_MODE_64,
    arm_const,
    x86_const,
    Uc,
    UcError,
)

from unicorefuzz import x64utils, configspec

AFL_PATH = "AFLplusplus"
UNICORN_IN_AFL = os.path.join("unicorn_mode", "unicorn")

DEFAULT_PAGE_SIZE = 0x1000
PROBE_WRAPPER_WAIT_SECS = 0.5

X64 = X86_64  # type: Architecture
REQUEST_FOLDER = "requests"
STATE_FOLDER = "state"
REJECTED_ENDING = ".rejected"

# TODO:
# Fix avatar2 x86 mode upstream
# (ARM already contains unicorn_* and pc_name)
X86.pc_name = "eip"
X86.unicorn_arch = UC_ARCH_X86
X86.unicorn_mode = UC_MODE_32
X64.pc_name = "rip"
# unicorn_arch is the same/inherited from X86
X64.unicorn_mode = UC_MODE_64

ARM.unicorn_consts = arm_const
X86.unicorn_consts = x86_const

ARM.unicorn_reg_tag = "UC_ARM_REG_"
ARM.ignored_regs = []
ARM.insn_nop = b"\x00\x00\x00\x00"
X86.unicorn_reg_tag = "UC_X86_REG_"
X86.ignored_regs = ["cr0"]  # CR0 unicorn crash
X86.insn_nop = b"\x90"
X64.ignored_regs = X86.ignored_regs + ["fs", "gs"]  # crashes unicorn too

# base_base = X86.unicorn_consts.UC_X86_REG_MXCSR
# x86_const.UC_X86_REG_GS_BASE = base_base + 1
# x86_const.UC_X86_REG_FS_BASE = base_base + 2

# TODO: Add mips? ARM64? More archs?
archs = {
    "x86": X86,
    "x86_64": X64,
    "x64": X64,
    "arm": ARM,
    "arm_cortex_m3": ARM_CORTEX_M3,
    "arm_v7m": ARMV7M,
    "armbe": ARMBE,
}


# emulate from @begin, and stop when reaching address @until
# def uc_forkserver_start(uc: Uc, exits: List[int]) -> None:
# import ctypes
# from unicornafl import unicorn

# exit_count = len(exits)
# unicorn._uc.uc_afl_forkserver_start(
#    uc._uch, ctypes.c_size_t(exit_count), (ctypes.c_uint64 * exit_count)(*exits)
# )


def regs_from_unicorn(arch: Architecture) -> List[str]:
    """
    Get all (supported) registers of an arch from Unicorn constants
    """
    # noinspection PyUnresolvedReferences
    consts = arch.unicorn_consts
    regs = [
        k.split("_REG_")[1].lower()
        for k, v in consts.__dict__.items()
        if not k.startswith("__") and "_REG_" in k and "INVALID" not in k
    ]
    # if arch == X64:
    # These two are not directly supported by unicorn.
    # regs += ["gs_base", "fs_base"]
    return regs


def _init_all_reg_names():
    """
    Read all register names for an arch from Unicorn consts
    """
    for arch in archs.values():
        # noinspection PyTypeChecker
        arch.reg_names = regs_from_unicorn(arch)


_init_all_reg_names()


def uc_reg_const(arch: Architecture, reg_name: str) -> int:
    """
    Returns an unicorn register constant to address the register by name.
    i.e.:
    `uc_reg_const("x64", "rip") #-> UC_X86_REG_RIP`
    """
    # noinspection PyUnresolvedReferences
    return getattr(arch.unicorn_consts, arch.unicorn_reg_tag + reg_name.upper())


def get_arch(archname: str) -> Architecture:
    """
    Look up Avatar architecture, add Ucf extras and return it
    """
    return archs[archname.lower()]


class Unicorefuzz:
    def __init__(self, config: [str, "configspec"]) -> None:
        if isinstance(config, str):
            from unicorefuzz.configspec import load_config

            config = load_config(config)
        self.config = config  # type: configspec
        self.arch = get_arch(config.ARCH)  # type: Architecture

        self._mapped_page_cache = {}  # type: Dict[int, bytes]
        self.cs = Cs(self.arch.capstone_arch, self.arch.capstone_mode)  # type: Cs

        self.statedir = os.path.join(config.WORKDIR, "state")  # type: str
        self.requestdir = os.path.join(config.WORKDIR, "requests")  # type: str

        self.exits = None  # type: Optional[List[int]]
        # fore some things like the fuzz child we want to disable logging, In this case, we set should_log to False.
        self.should_log = True  # type: bool

    def wait_for_probe_wrapper(self) -> None:
        """
        Blocks until the request folder gets available
        """
        while not os.path.exists(self.requestdir):
            print("[*] Waiting for probewrapper to be available...")
            print("    ^-> UCF workdir is {}".format(self.config.WORKDIR))
            time.sleep(PROBE_WRAPPER_WAIT_SECS)

    def calculate_exits(self, entry: int) -> List[int]:
        config = self.config
        # add MODULE_EXITS to EXITS
        exits = config.EXITS + [x + entry for x in config.ENTRY_RELATIVE_EXITS]
        return exits

    def path_for_page(self, address: int) -> str:
        """
        Return the filename for a page
        """
        base_address = self.get_base(address)
        return os.path.join(
            self.config.WORKDIR, "state", "{:016x}".format(base_address)
        )

    def exit(self, exitcode: int = 1) -> None:
        """
        Exit it
        :param exitcode:
        """
        os._exit(exitcode)

    def force_crash(self, uc_error: UcError) -> None:
        """
        This function should be called to indicate to AFL that a crash occurred during emulation.
        Pass in the exception received from Uc.emu_start()
        :param uc_error: The unicorn Error
        """
        mem_errors = [
            UC_ERR_READ_UNMAPPED,
            UC_ERR_READ_PROT,
            UC_ERR_READ_UNALIGNED,
            UC_ERR_WRITE_UNMAPPED,
            UC_ERR_WRITE_PROT,
            UC_ERR_WRITE_UNALIGNED,
            UC_ERR_FETCH_UNMAPPED,
            UC_ERR_FETCH_PROT,
            UC_ERR_FETCH_UNALIGNED,
        ]
        if uc_error.errno in mem_errors:
            # Memory error - throw SIGSEGV
            os.kill(os.getpid(), signal.SIGSEGV)
        elif uc_error.errno == UC_ERR_INSN_INVALID:
            # Invalid instruction - throw SIGILL
            os.kill(os.getpid(), signal.SIGILL)
        else:
            # Not sure what happened - throw SIGABRT
            os.kill(os.getpid(), signal.SIGABRT)

    def serialize_spec(self) -> str:
        """
        Serializes the config spec.
        :return: The spec
        """
        return configspec.serialize_spec(self.config)

    def print_spec(self) -> None:
        """
        Prints the config spec
        """
        print(self.serialize_spec())

    def map_page(self, uc: Uc, addr: int) -> None:
        """
        Maps a page at addr in the harness, asking probe_wrapper.
        :param uc: The unicore
        :param addr: The address
        """
        page_size = self.config.PAGE_SIZE
        base_address = self.get_base(addr)
        if base_address not in self._mapped_page_cache.keys():
            input_file_name = os.path.join(self.requestdir, "{:016x}".format(addr))
            dump_file_name = os.path.join(self.statedir, "{:016x}".format(base_address))
            if os.path.isfile(dump_file_name + REJECTED_ENDING):
                print("CAN I HAZ EXPLOIT?")
                os.kill(os.getpid(), signal.SIGSEGV)
            if not os.path.isfile(dump_file_name):
                open(input_file_name, "a").close()
            if self.should_log:
                print("mapping {}".format(hex(base_address)))
            while 1:
                try:
                    if os.path.isfile(dump_file_name + REJECTED_ENDING):
                        print("CAN I HAZ EXPLOIT?")
                        os.kill(os.getpid(), signal.SIGSEGV)
                    with open(dump_file_name, "rb") as f:
                        content = f.read()
                        if len(content) < page_size:
                            time.sleep(0.001)
                            continue
                        self._mapped_page_cache[base_address] = content
                        uc.mem_map(base_address, len(content))
                        uc.mem_write(base_address, content)
                        return
                except IOError:
                    pass
                except UcError as ex:
                    return
                except Exception as ex:  # todo this should never happen if we don't map like idiots
                    print(
                        "map_page failed: base address=0x{:016x} ({})".format(
                            base_address, ex
                        )
                    )
                    # exit(1)

    @property
    def afl_path(self) -> str:
        """
        Calculate afl++ path
        :return: The folder AFLplusplus lives in
        """
        return os.path.abspath(os.path.join(self.config.UNICORE_PATH, AFL_PATH))

    @property
    def libunicorn_path(self) -> str:
        """
        Calculate the libunicorn path
        :return Whereever unicorn.so resides lives in the system
        """
        return os.path.abspath(os.path.join(self.afl_path, UNICORN_IN_AFL))

    def get_base(self, addr: int) -> int:
        """
        Calculates the base address (aligned to PAGE_SIZE) to an address, using default configured page size
        All you base are belong to us.
        :param addr: the address to get the base for
        :return: base addr
        """
        page_size = self.config.PAGE_SIZE
        return addr - addr % page_size
