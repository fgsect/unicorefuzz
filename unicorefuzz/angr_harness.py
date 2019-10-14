#!/usr/bin/env python3
"""
Harness to do Symbolic Execution.
"""

import argparse
from typing import Tuple, Callable, List

import angr
import claripy
from angr.concretization_strategies import SimConcretizationStrategy
from angr.engines.vex.ccall import amd64g_check_ldmxcsr
from angr.engines.vex.dirty import x86g_dirtyhelper_write_cr0
from avatar2.archs import X86, X86_64, ARM, ARM_CORTEX_M3
from claripy.ast import Base
from cle import Clemory
from unicorn import Uc

from unicorefuzz.harness import Harness
from unicorefuzz.unicorefuzz import uc_reg_const

X86.angr_arch = angr.archinfo.arch_x86.ArchX86
X86_64.angr_arch = angr.archinfo.arch_amd64.ArchAMD64
ARM.angr_arch = angr.archinfo.arch_arm.ArchARM
ARM_CORTEX_M3.angr_arch = angr.archinfo.arch_arm.ArchARMCortexM


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
    state.memory.store(pageaddr, pagecontent, size=len(pagecontent))
    if hasattr(state, "ucf_mapped_addrs"):
        state.ucf_mapped_addrs.add(pageaddr)


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
        fixed = []
        for r in simgr.errored:
            s = r.state
            # first, check if we (PageForwardingExplorer) already touched this state...
            if hasattr(s, "pfe_fixed") and not s.pfe_fixed:
                # Old news. This one is broken for good.
                continue
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
            try:
                pageaddr, pagecontent = self.page_fetcher(addr)
                angr_store_mem(s, pageaddr, pagecontent)
                s.memory.store(pageaddr, pagecontent)
                s.pfe_fixed = True
                fixed += [r]
            except Exception as ex:
                print("[*] Found erroring page 0x{:016x}: {}".format(addr, ex))
                s.pfe_error = ex
                s.pfe_fixed = False

        for r in fixed:
            simgr.errored.remove(r)
            simgr.active.append(r.state)

        # simgr.stash(lambda r: r.state.pfe_fixed, from_stash="errored", to_stash="active")
        # simgr.active.extend(new_active)
        return simgr


class AngrHarness(Harness):
    """
    Harness executing the stuff in Angr
    """

    def angr_load_registers(self, uc: Uc, state: angr.SimState) -> None:
        """
        Load registers to angr
        """
        # Not using the fetched registers -> the init func could have changed regs.
        #  regs = self.fetch_all_regs()
        # for reg in state.arch.register_names.values():
        angr_regs = dir(state.regs)  # state.regs. arch.register_names.values()
        unicorn_regs = self.arch.reg_names

        # These regs have either different names in angr or some special way to set them
        if self.arch == X86:
            angr_regs += ["cr0", "mxcsr"]
        elif self.arch == X86_64:
            angr_regs += ["cr0", "mxcsr", "fs_base", "gs_base"]
        supported_regs = set(angr_regs)

        for reg in unicorn_regs:
            if reg not in supported_regs:
                print("Unicorn reg not supported in angr(?): {}".format(reg))
            else:
                name = reg
                value = self.uc_reg_read(uc, reg)
                if name == "mxcsr":
                    # TODO: found this somewhere in angr's cgc sources. Probably wrong.
                    state.regs.sseround = (value & 0x600) >> 9
                    # alt solution, somewhere from deep inside angr's sources that looks good but crashes:
                    # state.regs.sseround = amd64g_check_ldmxcsr(state, value)
                elif name == "cr0":
                    # Found this also somewhere, sets the state's archinfo according to cr0. Might work.
                    # Other cr regs don't seem to be supported
                    x86g_dirtyhelper_write_cr0(state, value)
                else:
                    # `fs_base` and `gs_base` are called `fs_const` and `gs_const` in angr...
                    # Let's hope no other regs ever end on `_base` or this breaks ;)
                    name = name.replace("_base", "_const")
                    try:
                        state.registers.store(name, value)
                    except Exception as ex:
                        print("Failed to retrieve register {}: {}".format(reg, ex))

    def __init__(self, config) -> None:
        """
        Initializes this angr harness
        :param config: the config to use
        """
        super().__init__(config)

    def angr_fetch_and_load(
        self, state: angr.SimState, addr: int, length: Base = claripy.BVV(1, 32)
    ) -> None:
        """
        Fetches and maps a page, or raises an error
        :param state: the angr state
        :param addr: addr to load
        :param length: optional length if a larger range of mem should be fetched.
        """
        if not hasattr(state, "ucf_mapped_addrs"):
            # TODO: recreating this map for every new state copy is super useless/slow.
            # Maybe we can find another place to keep that data. Or even implement it somewhere else...
            state.ucf_mapped_addrs = set()
        try:
            len_concrete = state.solver.eval(length)
        except Exception as ex:
            print(
                "[!] Couldn't solve len for mem at 0x{:016x}: 0x{:0x16x} - falling back to len 1".format(
                    addr, ex
                )
            )
            len_concrete = 1
        for sub_addr in range(addr, addr + len_concrete, self.config.PAGE_SIZE):
            if self.get_base(sub_addr) in state.ucf_mapped_addrs:
                return
            print(
                "[+] Fetching page for addr 0x{:016x} from `ucf attach`".format(
                    sub_addr
                )
            )
            base_addr, content = self.fetch_page_blocking(sub_addr)
            angr_store_mem(state, base_addr, content)

    def angr_load_mapped_pages(
        self, uc: Uc, state: angr.SimState
    ) -> List[Tuple[int, int, int]]:
        """
        Loads all currently mapped unicorn mem regions into angr
        :param uc: The uc instance to load from
        :param state: the angr instance to load to
        :returns Lst of pages mapped
        """
        mapped = []
        for begin, end, perms in uc.mem_regions():
            mapped += (begin, end - begin + 1, perms)
            angr_store_mem(state, begin, bytes(uc.mem_read(begin, end - begin + 1)))
        return mapped

    def get_angry(self, input_file: str) -> None:
        """
        The core, running something in angr.
        :param input_file: input file. Not that needed since it'll be symbolic, but #shrug
        """
        # Instead of doing all the init routines again, we just init unicorn and fiddle out the contents from there.
        uc, pc, exits = self.uc_init(input_file, wait=True)  # type: Uc, int, List[int]
        print("Starting angrification at 0x{:016x}".format(pc))

        base_addr, content = self.fetch_page_blocking(pc)

        # p = angr.project.load_shellcode(
        #     content,
        #     self.arch.angr_arch,
        #     load_address=base_addr,
        #     start_offset=pc - base_addr,
        # )  # type: angr.Project

        # In case project.load_shellcode performs well enough, we can drop these lines altogether
        pagepath = self.path_for_page(pc)
        p = angr.Project(
            pagepath,
            load_options={
                "main_opts": {
                    "backend": "blob",
                    "base_addr": base_addr,
                    "arch": self.arch.angr_arch,
                    "page_size": self.config.PAGE_SIZE,
                }
            },
        )
        #  p.loader.memory._backers = []
        # state.mem.add_backer

        state = p.factory.blank_state(
            addr=pc,
            add_options=angr.options.unicorn
            | {angr.options.REPLACEMENT_SOLVER}
            | {angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
            # memory_backer=None
        )  # type: angr.SimState
        state.ucf_mapped_addrs = set()
        self.angr_load_mapped_pages(uc, state)
        self.angr_load_registers(uc, state)

        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            # state, state.inspect.address, state.inspect.mem_read_length
            action=lambda x: self.angr_fetch_and_load(
                x, x.inspect.mem_read_address, x.inspect.mem_read_length
            ),
        )
        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            action=lambda x: self.angr_fetch_and_load(
                x, x.inspect.mem_write_address, x.inspect.mem_write_length
            ),
        )

        # s.solver.eval_one(s.regs.rdi)
        rdi = self.uc_reg_read(uc, "rdi")
        base_addr, content = self.fetch_page_blocking(rdi)
        # pageaddr, content = utils.fetch_page_blocking(rdi)

        # state.memory.map_region(pageaddr, len(content), 7)
        # state.memory.store(pageaddr, content)

        with open(input_file, "rb") as f:  # load afl's input
            in_content = f.read()

        input_symbolic = claripy.BVS("input", len(in_content) * 8)

        state.preconstrainer.preconstrain(in_content, input_symbolic)
        state.regs.rsi = len(in_content)

        state.memory.store(rdi, input_symbolic)

        simgr = p.factory.simulation_manager(state)
        simgr.use_technique(PageForwardingExplorer(self.fetch_page_blocking))
        simgr.use_technique(angr.exploration_techniques.DFS())
        while simgr.active:
            print(simgr)
            print(simgr.active)
            print(simgr.errored)
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
