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

cs = utils.init_capstone()


class PageForwardingExplorer(angr.ExplorationTechnique):
    """
    Angr explorer forwarding all unmapped pages once they are hit
    """

    def step(self, simgr):
        super().step(simgr)
        print(simgr)
        new_active = []
        for r in simgr.errored:
            s = r.state
            if isinstance(
                    r.error, angr.errors.SimEngineError
            ) and "No bytes in memory" in repr(r.error):
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

        simgr.drop(stash="errored")  # Todo: only remove fixed ones.
        simgr.active.extend(new_active)
        return simgr


def main(input_file):
    rip = utils.fetch_register("rip")
    pageaddr, pagecontent = utils.fetch_page_blocking(rip)
    pagepath = utils.path_for_page(pageaddr)

    p = angr.Project(
        pagepath,
        load_options={
            "main_opts": {"backend": "blob", "base_addr": pageaddr, "arch": "x86_64"}
        },
    )

    state = p.factory.blank_state(
        add_options=angr.options.unicorn | {angr.options.REPLACEMENT_SOLVER}
    )
    utils.angr_load_registers(state)

    # s.solver.eval_one(s.regs.rdi)
    rdi = utils.fetch_register("rdi")
    pageaddr, content = utils.fetch_page_blocking(rdi)

    state.memory.map_region(pageaddr, len(content), 7)
    state.memory.store(pageaddr, content)

    input_file = open(input_file, "rb")  # load afl's input

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Angr-Harness for unicorefuzz")
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the file containing the mutated input to load",
    )
    args = parser.parse_args()

    main(args.input_file)
