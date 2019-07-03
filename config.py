# This is the main config file of Unicorefuzz.
# It should be adapted for each fuzzing run.

# A place to put scratch memory to. Non-kernelspace foo should be fine
SCRATCH_ADDR = 0x80000
# How much scratch to add. We don't ask for much.
SCRATCH_SIZE = 0x1000

# Length of the function to fuzz (usually the return address)
LENGTH = 0x119
# Additional exit here. The Exit at entry + length will be added automatically.
EXITS = {

}

# Add all CMPXCHG16B you find here. This has some random side effects since unicorn breaks. 
# See Github issue https://github.com/unicorn-engine/unicorn/issues/1095
CMPEXCHG16B_ADDRS = {
    0xffffffff81477fce: "RDI"
}

# Either set this to load the module from the VM and break at module + offset...
MODULE = None
BREAKOFFSET = None

# Or this to break at a fixed offset.
BREAKADDR = 0xffffffff8684cde
# You cannot set MODULE and BREAKOFFSET at the same time

# Tell us a bit about the environment AFL will run in.
INPUT_DIR = "../input"
OUTPUT_DIR = "../output"

# This function gets the current input and places it in the memory.
# It will be called for each execution, so keep it lightweight.
# This can be compared to a testcase in libfuzzer.
# if you want to ignore an input, you can os._exit(0) here (anything else is a lot slower).
def place_input(uc, input):
    """
    Places the input in memory and alters the input.
    This is an example for sk_buff in openvsswitch
    """
    import util

    if len(input) > 1500:
        import os
        os._exit(0) # too big!

    # read input to the correct position at param rdx here:
    rdx = uc.reg_read(UC_X86_REG_RDX)
    util.map_page_blocking(uc, rdx) # ensure sk_buf is mapped
    bufferPtr = struct.unpack("<Q",uc.mem_read(rdx + 0xd8, 8))[0]
    util.map_page_blocking(uc, bufferPtr) # ensure the buffer is mapped
    uc.mem_write(rdi, input) # insert afl input
    uc.mem_write(rdx + 0xc4, b"\xdc\x05") # fix tail
    return
