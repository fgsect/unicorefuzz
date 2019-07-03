#!/usr/bin/env python
import argparse
import os
import signal
import sys
import json
import time
import struct

from IPython import embed
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *

import util

import config 


cs = Cs(CS_ARCH_X86, CS_MODE_64)

def unicorn_debug_instruction(uc, address, size, user_data):
    try:
        mem = uc.mem_read(address, size)
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))
    except Exception as e:
        print(hex(address))
        print("e: {}".format(e))
        print("size={}".format(size))
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(uc.mem_read(address, 30)), 30):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))


def unicorn_debug_block(uc, address, size, user_data):
    print("Basic Block: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))

def unicorn_debug_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print("        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(address, size, value))
    else:
        print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))

def unicorn_debug_mem_invalid_access(uc, access, address, size, value, user_data):
    print("unicorn_debug_mem_invalid_access(uc, access, address, size, value, user_data)")
    if access == UC_MEM_WRITE_UNMAPPED:
        print("        >>> INVALID Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(address, size, value))
    else:
        print("        >>> INVALID Read: addr=0x{0:016x} size={1}".format(address, size))
    util.map_page_blocking(uc, address)
    return True

def hook_invalid_ins(uc, port, size, value, user_data):
    print("hook entered")


def force_crash(uc_error):
    # This function should be called to indicate to AFL that a crash occurred during emulation.
    # Pass in the exception received from Uc.emu_start()
    mem_errors = [
        UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED,
        UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
        UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED,
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


def main(input_file, debug=False):

    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    if debug:
        uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
        uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction)
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ | UC_HOOK_MEM_FETCH, unicorn_debug_mem_access)
    uc.hook_add(UC_HOOK_INSN, util.cpu_cmpxchg_double, None, 1, 0, UC_X86_INS_SYSCALL)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, unicorn_debug_mem_invalid_access)

    rip = uc.reg_read(UC_X86_REG_RIP)
    config.EXITS[rip+config.LENGTH] = 0
    util.map_known_mem(uc)

    util.load_registers(uc) # starts the afl forkserver

    #print(str(input_file))
    input_file = open(input_file, 'rb') # load afl's input
    input = input_file.read()
    input_file.close()

    try:
        config.place_input(uc, input)
    except Exception as ex:
        print("Error setting testcase for input {}: {}".format(input, ex))
        os._exit(1)

    if args.debug:
        print("hic sunt dracones!")
    try:
        uc.emu_start(rip, 0x0, timeout=0, count=0)
    except UcError as e:
        print("Execution failed with error: {} at address {:x}".format(e, uc.reg_read(UC_X86_REG_RIP)))
        force_crash(e)

    if args.debug:
        print("Done.")
    os._exit(0) # Exit without clean python vm shutdown: "The os._exit() function can be used if it is absolutely positively necessary to exit immediately (for example, in the child process after a call to os.fork())."

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test harness for our sample kernel module")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input to load")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Enables debug tracing")
    args = parser.parse_args()

    main(args.input_file, debug=args.debug)
