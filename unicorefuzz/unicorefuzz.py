import os
import signal

from avatar2 import X86_64, X86, ARM, ARM_CORTEX_M3, ARMV7M, ARMBE
from capstone import Cs
from unicorn import UC_MEM_WRITE_UNMAPPED, UC_ERR_READ_UNMAPPED, UC_MEM_WRITE, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED, \
    UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED, UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, \
    UC_ERR_FETCH_UNALIGNED, UC_ERR_INSN_INVALID, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, arm_const, x86_const

from avatar2.archs import Architecture
from avatar2.archs.x86 import X86
from avatar2.archs.arm import ARM

from unicorefuzz import utils

DEFAULT_PAGE_SIZE = 0x1000

X64 = X86_64
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


def _init_all_reg_names():
    for name, arch in archs.items():
        arch.reg_names = utils.regs_from_unicorn(arch)


_init_all_reg_names()


def get_arch(archname):
    """
    Look up Avatar architecture, add Ucf extras and return it
    """
    return archs[archname.lower()]


def unicorn_debug_instruction(uc, address, size, user_data):
    cs = user_data
    try:
        mem = uc.mem_read(address, size)
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
                bytes(mem), size
        ):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))
    except Exception as e:
        print(hex(address))
        print("e: {}".format(e))
        print("size={}".format(size))
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
                bytes(uc.mem_read(address, 30)), 30
        ):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))


def unicorn_debug_block(uc, address, size, user_data):
    print("Basic Block: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))


def unicorn_debug_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))


def unicorn_debug_mem_invalid_access(uc, access, address, size, value, user_data):
    print(
        "unicorn_debug_mem_invalid_access(uc={}, access={}, addr=0x{:016x}, size={}, value={}, ud={})".format(
            uc, access, address, size, value, user_data
        )
    )
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            "        >>> INVALID Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print(
            "        >>> INVALID Read: addr=0x{0:016x} size={1}".format(address, size)
        )
    try:
        utils.map_page_blocking(uc, address)
    except KeyboardInterrupt:
        uc.emu_stop()
        return False
    return True


def force_crash(uc_error):
    # This function should be called to indicate to AFL that a crash occurred during emulation.
    # Pass in the exception received from Uc.emu_start()
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


CONFIG = [
    "putflag",
    "getflag",
    "putnoise",
    "getnoise",
    "havoc",
    "exploit"
]  # type: List[str]


class Unicorefuzz:

    def validate_config(self):
        pass

    def __init__(self, config, args):
        self.config = config
        self.args = args
        self.arch = get_arch(config.ARCH)

        self._mapped_page_cache = {}
        self.cs = Cs(arch.capstone_arch, arch.capstone_mode)

        self.statedir = os.path.join(config.WORKDIR, "state")
        self.requestdir = os.path.join(config.WORKDIR, "requests")

        self.fetched_regs = {}

        config.WORKDIR
        config.ARCH
        # TODO: config.

        UNICORE_PATH = os.path.dirname(os.path.abspath(__file__))

        # A place to put scratch memory to. Non-kernelspace address should be fine.
        SCRATCH_ADDR = 0x80000
        # How much scratch to add. We don't ask for much. Default should be fine.
        SCRATCH_SIZE = 0x1000

        # Set a supported architecture
        ARCH = "x64"

        # The gdb port to connect to
        GDB_HOST = "localhost"
        GDB_PORT = 1234

        # Either set this to load the module from the VM and break at module + offset...
        MODULE = "procfs1"
        BREAKOFFSET = 0x10

        # Or this to break at a fixed offset.
        BREAKADDR = None
        # You cannot set MODULE and BREAKOFFSET at the same time

        # Length of the function to fuzz (usually the return address)
        LENGTH = 0x19D - BREAKOFFSET

        # Additional exits here.
        # The Exit at entry + LENGTH will be added automatically.
        EXITS = []
        # Exits realtive to the initial rip (entrypoint + addr)
        ENTRY_RELATIVE_EXITS = []

        # The location used to store data and logs
        WORKDIR = os.path.join(UNICORE_PATH, "unicore_workdir")

        def init_func(uc):
            """
            An init function called before forking.
            This function may be used to set additional unicorn hooks and things.
            If you uc.run_emu here, you will trigger the forkserver. Try not to/do that in place_input. :)
            """
            pass

        # This function gets the current input and places it in the memory.
        # It will be called for each execution, so keep it lightweight.
        # This can be compared to a testcase in libfuzzer.
        # if you want to ignore an input, you can os._exit(0) here (anything else is a lot slower).
        def place_input_skb(uc, input):
            """
            Places the input in memory and alters the input.
            This is an example for sk_buff in openvsswitch
            """

            if len(input) > 1500:
                import os

                os._exit(0)  # too big!

            # read input to the correct position at param rdx here:
            rdx = uc.reg_read(UC_X86_REG_RDX)
            rdi = uc.reg_read(UC_X86_REG_RDI)
            utils.map_page_blocking(uc, rdx)  # ensure sk_buf is mapped
            bufferPtr = struct.unpack("<Q", uc.mem_read(rdx + 0xD8, 8))[0]
            utils.map_page_blocking(uc, bufferPtr)  # ensure the buffer is mapped
            uc.mem_write(rdi, input)  # insert afl input
            uc.mem_write(rdx + 0xC4, b"\xdc\x05")  # fix tail

        def place_input(uc, input):
            rax = uc.reg_read(UC_X86_REG_RAX)
            # make sure the parameter memory is mapped
            utils.map_page_blocking(uc, rax)

    def wait_for_probe_wrapper(self):
        pass

    def harness(self, wait=True):
        pass

    def _fetch_register(self, name):
        """
        Loads the value of a register from the dumped state.
        Used internally: later, rely on `ucf.regs[regname]`.
        :param name The name
        :returns the content of the register
        """
        with open(os.path.join(self.statedir, name), "r") as f:
            return int(f.read())
