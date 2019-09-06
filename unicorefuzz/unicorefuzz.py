import os
import signal
import time
from typing import List, Dict

from avatar2 import X86_64, ARM_CORTEX_M3, ARMV7M, ARMBE
from avatar2.archs import Architecture
from avatar2.archs.arm import ARM
from avatar2.archs.x86 import X86
from capstone import Cs
from unicorn import (
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

from unicorefuzz import x64utils

AFL_PATH = "AFLplusplus"
UDDBG_PATH = "uDdbg"

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
    if arch == X64:
        # These two are not directly supported by unicorn.
        regs += ["gs_base", "fs_base"]
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


def uc_get_pc(uc: Uc, arch: Architecture) -> int:
    """
    Gets the current program counter from a unicorn instance
    """
    # noinspection PyUnresolvedReferences
    return uc.reg_read(uc_reg_const(arch, arch.pc_name))


def get_arch(archname: str) -> Architecture:
    """
    Look up Avatar architecture, add Ucf extras and return it
    """
    return archs[archname.lower()]


class Unicorefuzz:
    def __init__(self, config: [str, "configspec"]):
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
        # if exits is still None when we map a page, store pages that we still need to patch later.
        self._deferred_exits = []  # type: List[int]

    def wait_for_probe_wrapper(self) -> None:
        """
        Blocks until the request folder gets available
        """
        while not os.path.exists(self.requestdir):
            print("[.] Waiting for probewrapper to be available...")
            time.sleep(PROBE_WRAPPER_WAIT_SECS)

    def calculate_exits(self, entry: int):
        config = self.config
        exits = []
        # add MODULE_EXITS to EXITS
        exits = config.EXITS + [x + entry for x in config.ENTRY_RELATIVE_EXITS]
        return exits

    def path_for_page(self, address: int) -> str:
        """
        Return the filename for a page
        """
        base_address = self.get_base(address)
        return os.path.join(
            self.config.workdir, "state", "{:016x}".format(base_address)
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

    def set_exits(self, uc: Uc, base_address: int, exits: List[int]):
        """
        We replace all hooks and exits with syscalls since they should be rare in kernel code.
        Then, when we encounter a syscall, we figure out if a syscall or exit occurred.
        This can also be used to add additional hooks in the future.
        :param uc: Unicorn instance
        :param exits: The exit counts
        :param base_address: the address we're mapping
        """
        arch = self.arch
        # TODO: This only works for X64!
        if exits is None:
            self._deferred_exits.append(base_address)
        else:
            if len(exits) <= 1:
                # No need to patch anything, uc supports a single exit.
                return
            if len(exits) > 1:
                if arch == X64:
                    for end_addr in exits:
                        if self.get_base(end_addr) == base_address:
                            print("[*] Setting exit 0x{:016x}".format(end_addr))
                            # Abusing the syscall opcode for exits.
                            # Just make sure the whole opcode will fit here by trying to map the end addr.
                            self.map_page(uc, end_addr + len(x64utils.SYSCALL_OPCODE))
                            uc.mem_write(end_addr, x64utils.SYSCALL_OPCODE)
                else:
                    raise (
                        ValueError(
                            "Multiple exits are not yet supported for arch {} - {}".format(
                                arch, exits
                            )
                        )
                    )

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
                        self.set_exits(uc, base_address, self.exits)
                        return
                except IOError:
                    pass
                except UcError as ex:
                    return
                except Exception as ex:  # todo this should never happen if we don't map like idiots
                    print(
                        "map_page_blocking failed: base address=0x{:016x} ({})".format(
                            base_address, ex
                        )
                    )
                    # exit(1)

    @property
    def afl_path(self):
        """
        Calculate afl++ path
        :return: The folder AFLplusplus lives in
        """
        return os.path.abspath(os.path.join(self.config.UNICORE_PATH, AFL_PATH))

    @property
    def uddbg_path(self):
        """
        Calculate uDdbg path
        :return: The folder uDdbg is cloned to
        """
        return os.path.abspath(os.path.join(self.config.UNICORE_PATH, UDDBG_PATH))

    def get_base(self, addr):
        """
        Calculates the base address (aligned to PAGE_SIZE) to an address, using default configured page size
        All you base are belong to us.
        :param addr: the address to get the base for
        :return: base addr
        """
        page_size = self.config.PAGE_SIZE
        return addr - addr % page_size
