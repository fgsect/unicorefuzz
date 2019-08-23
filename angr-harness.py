#!/usr/bin/env python3

import angr
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

import config 


cs = Cs(CS_ARCH_X86, CS_MODE_64)


class PageForwardingExplorer(angr.ExplorationTechnique):
    def step(self, simgr):
        super().step(simgr)
        print(simgr)
        new_active = []
        for r in simgr.errored:
            s = r.state
            if (isinstance(r.error, angr.errors.SimEngineError) and "No bytes in memory" in repr(r.error)):
                addr = s.solver.eval_one(s.regs.rip)
            elif isinstance(r.error, angr.errors.SimSegfaultException):
                addr = r.error.addr 
            else:
                r.reraise()

            print("mapping addr: {}".format(addr))
            
            pageaddr, pagecontent = utils.fetch_page_blocking(addr)
            try:
                s.memory.map_region(pageaddr, len(pagecontent), 7)
            except Exception as ex:
                print("Could not map: {}".format(ex))

            s.memory.store(pageaddr, pagecontent)
            new_active.append(s)

        simgr.drop(stash="errored") # Todo: only remove fixed ones.
        simgr.active.extend(new_active)
        return simgr
            

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


def main(input_file):

    rip = utils.fetch_register("rip")
    pageaddr, pagecontent = utils.fetch_page_blocking(rip)
    pagepath = utils.path_for_page(pageaddr)

   
    p = angr.Project(pagepath, load_options={
        'main_opts': { 
            'backend': 'blob', 
            'base_addr': pageaddr, 
            'arch': 'x86_64' 
        } 
    })


    state = p.factory.blank_state(add_options=angr.options.unicorn|{angr.options.REPLACEMENT_SOLVER})
    utils.load_angr_registers(state)

    #s.solver.eval_one(s.regs.rdi)
    rdi = util.fetch_register("rdi")
    pageaddr, content = util.fetch_page_blocking(rdi)

    state.memory.map_region(pageaddr, len(content), 7)
    state.memory.store(pageaddr, content)

    input_file = open(input_file, 'rb') # load afl's input
    input = input_file.read()
    input_file.close()

    import claripy
    input_symbolic = claripy.BVS("input", len(input) * 8)

    state.preconstrainer.preconstrain(input, input_symbolic)
    state.regs.rsi = len(input)

    state.memory.store(rdi, input_symbolic)

    simgr = p.factory.simulation_manager(state)
    simgr.use_technique(PageForwardingExplorer())
    while simgr.active:
        print(simgr)
        simgr.step()

    return
    # Below is legacy code..

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Angr-Harness for unicorefuzz")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input to load")
    args = parser.parse_args()

    main(args.input_file)
