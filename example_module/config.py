# This is the main config file of Unicorefuzz.
# It should be adapted for each fuzzing run.
import os
UNICORE_PATH = os.path.dirname(os.path.abspath(__file__))

# A place to put scratch memory to. Non-kernelspace foo should be fine
SCRATCH_ADDR = 0x80000
# How much scratch to add. We don't ask for much.
SCRATCH_SIZE = 0x1000

# Either set this to load the module from the VM and break at module + offset...
MODULE = "procfs1"
BREAKOFFSET = 0x10

# Or this to break at a fixed offset.
BREAKADDR = None 
# You cannot set MODULE and BREAKOFFSET at the same time

# Length of the function to fuzz (usually the return address)
LENGTH = 0x19d - BREAKOFFSET

# Additional exits here. 
# The Exit at entry + LENGTH will be added automatically.
EXITS = [
]
# Exits realtive to the initial rip (entrypoint + addr)
ENTRY_RELATIVE_EXITS = [
]

# The location used to store data and logs
WORKDIR = os.path.join(UNICORE_PATH, "unicore_workdir")


def init_func(uc, rip): 
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
    import util
    import struct
    from unicorn.x86_const import UC_X86_REG_RDX, UC_X86_REG_RDI

    if len(input) > 1500:
        import os
        os._exit(0) # too big!

    # read input to the correct position at param rdx here:
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    util.map_page_blocking(uc, rdx) # ensure sk_buf is mapped
    bufferPtr = struct.unpack("<Q",uc.mem_read(rdx + 0xd8, 8))[0]
    util.map_page_blocking(uc, bufferPtr) # ensure the buffer is mapped
    uc.mem_write(rdi, input) # insert afl input
    uc.mem_write(rdx + 0xc4, b"\xdc\x05") # fix tail

def place_input(uc, input):
    import util
    from unicorn.x86_const import UC_X86_REG_RAX
    rax = uc.reg_read(UC_X86_REG_RAX)
    util.map_page_blocking(uc, rax) # make sure the parameter memory is mapped
    uc.mem_write(rax, input) # insert afl input
