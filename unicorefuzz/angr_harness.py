#!/usr/bin/env python3
"""
Harness to do Symbolic Execution.
"""

import argparse
from typing import Optional, Dict, Tuple, Callable, List

import angr
import claripy
from unicorn import Uc

from unicorefuzz.harness import Harness
from unicorefuzz.unicorefuzz import uc_reg_const

from avatar2.archs import X86, X86_64, ARM

X86.angr_arch = angr.archinfo.arch_x86
X86_64.angr_arch = angr.archinfo.arch_amd64
ARM.angr_arch = angr.archinfo.arch_arm
ARM.angr_arch = angr.archinfo.arch_arm


def mark_input_symbolic(ucf: "AngrHarness", uc: Uc, state: angr.SimState, input):
    """
    Marks the right place symbolic
    :param ucf: The angr harness
    :param uc: fully loaded unicorn instance
    :param state: fully loaded angr instance
    :param input: the input from file
    """
    raise Exception("TODO :)")


def angr_store_mem(state: angr.SimState, pageaddr: int, pagecontent: bytes) -> None:
    """
    Store some state, maybe mapping the mem region along the way.
    :param state: the state to store mem to
    :param pageaddr: the addr to store at
    :param pagecontent: the contents to store
    """
    try:
        state.memory.map_region(pageaddr, len(pagecontent), 7)
    except Exception as ex:
        print("Not mapping {:016x}: {}".format(pageaddr, ex))
    state.memory.store(pageaddr, pagecontent)


class PageForwardingExplorer(angr.ExplorationTechnique):
    """
    Angr explorer forwarding unmapped pages once they are hit
    """

    def __init__(self, page_fetcher: Callable[[int], Tuple[int, bytes]]) -> None:
        """
        :param page_fetcher: A function that takes an addr and returns a Tuple of (base_addr, content) of this page.
        """
        super().__init__()
        self.page_fetcher = page_fetcher  # type: Callable[[int], Tuple[int, bytes]]

    def step(self, simgr: angr.SimulationManager, **kwargs) -> angr.SimulationManager:
        super().step(simgr, **kwargs)
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
                # explicitly raise, just to make pycharm happy
                raise r.error.with_traceback(r.traceback)

            print("mapping addr: 0x{:016x}".format(addr))
            pageaddr, pagecontent = self.page_fetcher(addr)
            angr_store_mem(s, pageaddr, pagecontent)
            s.memory.store(pageaddr, pagecontent)
            new_active.append(s)

        simgr.drop(stash="errored")  # Todo: only remove fixed ones.
        simgr.active.extend(new_active)
        return simgr


class AngrHarness(Harness):
    def angr_load_registers(self, uc: Uc, state: angr.SimState) -> None:
        """
        Load registers to angr
        """
        # Not using the fetched registers -> the init func could have changed regs.
        #  regs = self.fetch_all_regs()
        # for reg in state.arch.register_names.values():
        angr_regs = state.arch.register_names.values()
        unicorn_regs = self.arch.reg_names
        angr_reg_set = set(angr_regs)

        for reg in unicorn_regs:
            if reg not in angr_reg_set:
                print("Unicorn reg not supported in angr(?): %s".format(reg))
            else:
                try:
                    state.registers.store(
                        reg, uc.reg_read(uc_reg_const(self.arch, reg))
                    )
                except Exception as ex:
                    print("Failed to retrieve register {}: {}".format(reg, ex))

    def __init__(self, config) -> None:
        """
        Initializes this angr harness
        :param config: the config to use
        """
        super().__init__(config)

    def angr_load_mapped_pages(self, uc: Uc, state: angr.SimState) -> None:
        """
        Loads all currently mapped unicorn mem regions into angr
        :param uc: The uc instance to load from
        :param state: the angr instance to load to
        """
        for begin, end, perms in uc.mem_regions():
            angr_store_mem(state, begin, uc.mem_read(begin, end - begin))

    def get_angry(self, input_file: str) -> None:
        """
        The core, running something in angr.
        :param input_file: input file. Not that needed since it'll be symbolic, but #shrug
        """
        # Instead of doing all the init routines again, we just init unicorn and fiddle out the contents from there.
        uc, pc, exits = self.uc_init(input_file, wait=True)  # type: Uc, int, List[int]

        self.fetch_page_blocking(pc)
        pagepath = self.path_for_page(pc)

        p = angr.Project(
            pagepath,
            load_options={
                "main_opts": {
                    "backend": "blob",
                    "base_addr": pagepath,
                    "arch": self.arch.angr_arch,
                }
            },
        )

        state = p.factory.blank_state(
            add_options=angr.options.unicorn | {angr.options.REPLACEMENT_SOLVER}
        )
        self.angr_load_registers(uc, state)
        self.angr_load_mapped_pages(uc, state)

        # s.solver.eval_one(s.regs.rdi)
        rdi = self.uc_reg_read("rdi")
        # pageaddr, content = utils.fetch_page_blocking(rdi)

        # state.memory.map_region(pageaddr, len(content), 7)
        # state.memory.store(pageaddr, content)

        # input_file = open(input_file, "rb")  # load afl's input

        input = input_file.read()
        input_file.close()

        input_symbolic = claripy.BVS("input", len(input) * 8)

        state.preconstrainer.preconstrain(input, input_symbolic)
        state.regs.rsi = len(input)

        state.memory.store(rdi, input_symbolic)

        simgr = p.factory.simulation_manager(state)
        simgr.use_technique(PageForwardingExplorer(self.fetch_page_blocking))
        simgr.use_technique(angr.exploration_techniques.DFS())
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
