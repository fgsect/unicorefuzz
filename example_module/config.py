# This is the main config file of Unicorefuzz.
# It should be adapted for each fuzzing run.
import os
import struct

from unicorn import Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDX, UC_X86_REG_RDI
from unicorefuzz.unicorefuzz import Unicorefuzz

# A place to put scratch memory to. Non-kernelspace address should be fine.
SCRATCH_ADDR = 0x80000
# How much scratch to add. We don't ask for much. Default should be fine.
SCRATCH_SIZE = 0x1000

# The page size used by the emulator. Optional.
PAGE_SIZE = 0x1000

# Set a supported architecture
ARCH = "x64"

# The gdb port to connect to
GDB_HOST = "localhost"
GDB_PORT = 1234

# Either set this to load the module from the VM and break at module + offset...
MODULE = "procfs1"
BREAK_OFFSET = 0x10

# Or this to break at a fixed offset.
BREAK_ADDR = None
# You cannot set MODULE and BREAKOFFSET at the same time

# Additional exits here.
# The Exit at entry + LENGTH will be added automatically.
EXITS = []
# Exits realtive to the initial rip (entrypoint + addr)
ENTRY_RELATIVE_EXITS = []

# The location used to store data and logs
WORKDIR = os.path.join(os.getcwd(), "unicore_workdir")

# Where AFL input should be read from
AFL_INPUTS = os.path.join(os.getcwd(), "afl_inputs")
# Where AFL output should be placed at
AFL_OUTPUTS = os.path.join(os.getcwd(), "afl_outputs")

# Optional AFL dictionary
AFL_DICT = None


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
def place_input_skb(ucf: Unicorefuzz, uc: Uc, input: bytes) -> None:
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
    ucf.map_page(uc, rdx)  # ensure sk_buf is mapped
    bufferPtr = struct.unpack("<Q", uc.mem_read(rdx + 0xD8, 8))[0]
    ucf.map_page(uc, bufferPtr)  # ensure the buffer is mapped
    uc.mem_write(rdi, input)  # insert afl input
    uc.mem_write(rdx + 0xC4, b"\xdc\x05")  # fix tail


def place_input(ucf: Unicorefuzz, uc: Uc, input: bytes) -> None:
    rax = uc.reg_read(UC_X86_REG_RAX)
    # make sure the parameter memory is mapped
    ucf.map_page(uc, rax)
    uc.mem_write(rax, input)  # insert afl input
