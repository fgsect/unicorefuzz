#!/usr/bin/env python
import argparse
import os
import signal
import sys
import json
import time
import struct

from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *

import utils
import x64utils

import config 

cs = utils.init_capstone(utils.get_arch(config.ARCH))


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
    print("unicorn_debug_mem_invalid_access(uc={}, access={}, addr=0x{:016x}, size={}, value={}, ud={})".format(uc, access, address, size, value, user_data))
    if access == UC_MEM_WRITE_UNMAPPED:
        print("        >>> INVALID Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(address, size, value))
    else:
        print("        >>> INVALID Read: addr=0x{0:016x} size={1}".format(address, size))
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


def main(input_file, debug=False, trace=False):

    arch = utils.get_arch(config.ARCH)
    uc = Uc(arch.unicorn_arch, arch.unicorn_mode)

    if debug:
        # Try to load udbg
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "uDdbg"))  
        try: 
            from udbg import UnicornDbg 
            print("[+] uDdbg debugger loaded.")
        except: 
            debug = False
            trace = True
            print("[!] Could not load uDdbg (install with ./setupdebug.sh), falling back to trace output.")
    if trace:
        print("[+] Settings trace hooks")
        uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
        uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction)
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ | UC_HOOK_MEM_FETCH, unicorn_debug_mem_access)

    # On error: map memory.
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, unicorn_debug_mem_invalid_access)

    rip = utils.fetch_register("rip")

    # if we only have a single exit, there is no need to potentially slow down execution with an insn hook.
    if len(config.EXITS) or len(config.ENTRY_RELATIVE_EXITS):

        # add MODULE_EXITS to EXITS
        config.EXITS += [x + rip for x in config.ENTRY_RELATIVE_EXITS]
        # add final exit to EXITS
        config.EXITS.append(rip+config.LENGTH)

        if arch == utils.X64:
            exit_hook = x64utils.init_syscall_hook(config.EXITS, os._exit)
            uc.hook_add(UC_HOOK_INSN, exit_hook, None, 1, 0, UC_X86_INS_SYSCALL)
        #TODO: Fast solution for X86, ARM, ...

    utils.map_known_mem(uc)

    if debug or trace:
        print("[*] Reading from file {}".format(input_file))

    # last chance for a change!
    config.init_func(uc, rip)

    # All done. Ready to fuzz.
    utils.uc_load_registers(uc) # starts the afl forkserver

    input_file = open(input_file, 'rb') # load afl's input
    input = input_file.read()
    input_file.close()

    try:
        config.place_input(uc, input)
    except Exception as ex:
        print("[!] Error setting testcase for input {}: {}".format(input, ex))
        os._exit(1)

    if not debug:
        try:
            uc.emu_start(rip, rip + config.LENGTH, timeout=0, count=0)
        except UcError as e:
            print("[!] Execution failed with error: {} at address {:x}".format(e, utils.uc_get_pc(uc, arch)))
            force_crash(e)
        # Exit without clean python vm shutdown: "The os._exit() function can be used if it is absolutely positively necessary to exit immediately"
        os._exit(0)
    else:
        print("[*] Starting debugger...")
        udbg = UnicornDbg()
        
        # TODO: Handle mappings differently? Update them at some point? + Proper exit after run?
        udbg.initialize(emu_instance=uc, entry_point=rip, exit_point=rip+config.LENGTH,
            hide_binary_loader=True, mappings=[(hex(x), x, utils.PAGE_SIZE) for x in utils.MAPPED_PAGES])
        def dbg_except(x,y ):
            raise Exception(y)
        os.kill = dbg_except
        udbg.start() 
        # TODO will never reach done, probably.
        print("[*] Done.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test harness for our sample kernel module")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input to load")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Starts the testcase in uUdbg (if installed)")
    parser.add_argument('-t', '--trace', default=False, action="store_true", help="Enables debug tracing")
    args = parser.parse_args()

    main(args.input_file, debug=args.debug, trace=args.trace)
