#!/usr/bin/env python
import argparse
import os
import sys
import time
from typing import Optional, Tuple, List, Dict

from capstone import Cs
from unicorn import *
from unicorn.x86_const import *

import unicorefuzz.unicorefuzz
from unicorefuzz.unicorefuzz import Unicorefuzz, REJECTED_ENDING, archs, X64, X86, ARM
from unicorefuzz import x64utils
from unicorefuzz.x64utils import syscall_exit_hook


def unicorn_debug_instruction(
    uc: Uc, address: int, size: int, user_data: "Unicorefuzz"
) -> None:
    cs = user_data.cs  # type: Cs
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


def unicorn_debug_block(uc: Uc, address: int, size: int, user_data: None) -> None:
    print("Basic Block: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))


def unicorn_debug_mem_access(
    uc: Uc, access: int, address: int, size: int, value: int, user_data: None
) -> None:
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))


def unicorn_debug_mem_invalid_access(
    uc: Uc, access: int, address: int, size: int, value: int, user_data: "Harness"
):
    harness = user_data  # type Unicorefuzz
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
        harness.map_page(uc, address)
    except KeyboardInterrupt:
        uc.emu_stop()
        return False
    return True


class Harness(Unicorefuzz):
    """
    The default harness, receiving memory from probe wrapper and running it in unicorn.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        self.fetched_regs = {}  # type: Dict[str, int]

    def harness(self, input_file: str, wait: bool, debug: bool, trace: bool) -> None:
        """
        The default harness, receiving memory from probe wrapper and running it in unicorn.
        :param input_file: the file to read
        :param wait: if we want to wait
        :param debug: run debugger or not
        :param trace: trace or not
        """
        uc, entry, exit = self.uc_init(input_file, wait, debug, trace)
        if debug:
            return self.uc_debug(uc, entry_point=entry, exit_point=exit)
        self.uc_run(uc, entry, exit)

    def uc_init(
        self, input_file, wait: bool = False, debug: bool = False, trace: bool = False
    ) -> Tuple[Uc, int, int]:
        config = self.config
        uc = Uc(self.arch.unicorn_arch, self.arch.unicorn_mode)

        if trace:
            print("[+] Settings trace hooks")
            uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
            uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction, self)
            uc.hook_add(
                UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ | UC_HOOK_MEM_FETCH,
                unicorn_debug_mem_access,
            )

        if wait:
            self.wait_for_probe_wrapper()

        if debug or trace:
            print("[*] Reading from file {}".format(input_file))

        # we leave out gs_base and fs_base on x64 since they start the forkserver
        self.uc_load_registers(uc)

        # let's see if the user wants a change.
        config.init_func(self, uc)

        # get pc from unicorn state since init_func may have altered it.
        pc = unicorefuzz.uc_get_pc(uc, self.arch)
        self.exits = self.calculate_exits(pc)
        self.map_known_mem(uc)
        if not self.exits:
            raise ValueError(
                "No exits founds. Would run forever... Please set an exit address in config.py."
            )
        entry_point = pc
        exit_point = self.exits[0]

        # On error: map memory, add exits.
        uc.hook_add(
            UC_HOOK_MEM_UNMAPPED, unicorn_debug_mem_invalid_access, (self, self.exits)
        )

        if len(self.exits) > 1:
            # unicorn supports a single exit only (using the length param).
            # We'll path the binary on load if we have need to support more.
            if self.arch == X64:
                uc.hook_add(
                    UC_HOOK_INSN,
                    syscall_exit_hook,
                    user_data=(self.exits, os._exit),
                    arg1=UC_X86_INS_SYSCALL,
                )
            else:
                # TODO: (Fast) solution for X86, ARM, ...
                raise Exception(
                    "Multiple exits not yet supported for arch {}".format(self.arch)
                )

        # starts the afl forkserver
        self.uc_start_forkserver(uc)

        input_file = open(input_file, "rb")  # load afl's input
        input = input_file.read()
        input_file.close()

        try:
            config.place_input(self, uc, input)
        except Exception as ex:
            raise Exception(
                "[!] Error setting testcase for input {}: {}".format(input, ex)
            )
        return uc, entry_point, exit_point

    def uc_debug(self, uc: Uc, entry_point: int, exit_point: int) -> None:
        """
        Start uDdbg debugger for the given unicorn instance
        :param uc: The unicorn instance
        :param entry_point: Where to start
        :param exit_point: Exit point
        """
        print("[*] Loading debugger...")
        sys.path.append(self.uddbg_path)
        # noinspection PyUnresolvedReferences
        from udbg import UnicornDbg

        udbg = UnicornDbg()

        # TODO: Handle mappings differently? Update them at some point? + Proper exit after run?
        udbg.initialize(
            emu_instance=uc,
            entry_point=entry_point,
            exit_point=exit_point,
            hide_binary_loader=True,
            mappings=[
                (hex(x), x, self.config.PAGE_SIZE) for x in self._mapped_page_cache
            ],
        )

        def dbg_except(x, y):
            raise Exception(y)

        os.kill = dbg_except
        udbg.start()
        # TODO will never reach done, probably.
        print("[*] Done.")

    def uc_run(self, uc: Uc, entry_point: int, exit_point: int) -> None:
        """
        Run initialized unicorn
        :param entry_point: The entry point
        :param exit_point: First final address. Hack something to get more exits
        :param uc: The unicorn instance to run
        """
        try:
            uc.emu_start(begin=entry_point, until=exit_point, timeout=0, count=0)
        except UcError as e:
            print(
                "[!] Execution failed with error: {} at address {:x}".format(
                    e, unicorefuzz.uc_get_pc(uc, self.arch)
                )
            )
            self.force_crash(e)
        # Exit without clean python vm shutdown:
        # "The os._exit() function can be used if it is absolutely positively necessary to exit immediately"
        # Many times faster!
        os._exit(0)

    def map_known_mem(self, uc: Uc):
        """
        Maps all memory known
        :param uc:
        :return:
        """
        workdir = self.config.WORKDIR
        for filename in os.listdir(self.statedir):
            if (
                not filename.endswith(REJECTED_ENDING)
                and filename not in self.fetched_regs
            ):
                try:
                    address = int(filename, 16)
                    self.map_page(uc, address)
                except:
                    pass

    def uc_start_forkserver(self, uc: Uc):
        """
        Starts the forkserver by executing an instruction on some scratch register
        :param uc: The unicorn to fork
        """
        scratch_addr = self.config.SCRATCH_ADDR
        scratch_size = self.config.SCRATCH_SIZE
        arch = self.arch

        sys.stdout.flush()  # otherwise children will inherit the unflushed buffer
        uc.mem_map(scratch_addr, scratch_size)

        if self.arch == X64:
            # prepare to do base register things
            self.fetch_all_regs()
            gs_base = self.fetched_regs["gs_base"]
            fs_base = self.fetched_regs["fs_base"]

            # This will execute code -> starts afl-unicorn forkserver!
            x64utils.set_gs_base(uc, scratch_addr, gs_base)
            # print("[d] setting gs_base to "+hex(gs))
            x64utils.set_fs_base(uc, scratch_addr, fs_base)
            # print("[d] setting fs_base to "+hex(gs))
        else:
            # We still need to start the forkserver somehow to be consistent.
            # Let's emulate a nop for this.
            uc.mem_map(scratch_addr, scratch_size)
            uc.mem_write(scratch_addr, arch.insn_nop)
            uc.emu_start(scratch_addr, until=0, count=1)

    def fetch_page_blocking(self, address: int, workdir: str) -> Tuple[int, bytes]:
        """
        Fetches a page at addr in the harness, asking probe wrapper, if necessary.
        returns base_address, content
        """
        base_address = unicorefuzz.get_base(self.config.PAGE_SIZE, address)
        input_file_name = os.path.join(self.requestdir, "{0:016x}".format(address))
        dump_file_name = os.path.join(self.statedir, "{0:016x}".format(base_address))
        if base_address in self._mapped_page_cache.keys():
            return base_address, self._mapped_page_cache[base_address]
        else:
            if os.path.isfile(dump_file_name + REJECTED_ENDING):
                # TODO: Exception class?
                raise Exception("Page can not be loaded from Target")
                # os.kill(os.getpid(), signal.SIGSEGV)
            if not os.path.isfile(dump_file_name):
                open(input_file_name, "a").close()
            print("mapping {}".format(hex(base_address)))
            while 1:
                try:
                    if os.path.isfile(dump_file_name + REJECTED_ENDING):
                        # TODO: Exception class?
                        raise Exception("Page can not be loaded from Target")
                    with open(dump_file_name, "rb") as f:
                        content = f.read()
                        if len(content) < self.config.PAGE_SIZE:
                            time.sleep(0.001)
                            continue
                        self._mapped_page_cache[base_address] = content
                        return base_address, content
                except IOError:
                    pass
                except Exception as e:  # todo this shouldn't happen if we don't map like idiots
                    print(e)
                    print(
                        "map_page_blocking failed: base address={0:016x}".format(
                            base_address
                        )
                    )
                    # exit(1)

    def _fetch_register(self, name: str) -> int:
        """
        Loads the value of a register from the dumped state.
        Used internally: later, rely on `ucf.regs[regname]`.
        :param name The name
        :returns the content of the register
        """
        with open(os.path.join(self.statedir, name), "r") as f:
            return int(f.read())

    def uc_load_registers(self, uc: Uc) -> None:
        """
        Loads all registers to unicorn, called in the harness.
        """
        regs = self.fetch_all_regs()
        for key, value in regs.items():
            if key in self.arch.ignored_regs:
                # print("[d] Ignoring reg: {} (Ignored)".format(r))
                continue
            try:
                uc.reg_write(unicorefuzz.uc_reg_const(self.arch, r), value)
            except Exception as ex:
                # print("[d] Faild to load reg: {} ({})".format(r, ex))
                pass

    def fetch_all_regs(self) -> Dict[str, int]:
        if self.fetched_regs is None:
            self.fetched_regs = {}
            for reg_name in self.arch.reg_names:
                try:
                    self.fetched_regs[reg_name] = self._fetch_register(reg_name)
                except Exception as ex:
                    print("Failed to retrieve register {}: {}".format(reg_name, ex))
        return self.fetched_regs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test harness for our sample kernel module"
    )
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the file containing the mutated input to load",
    )
    parser.add_argument(
        "-c", "--config", type=str, default="config.py", help="The config file to use."
    )
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        action="store_true",
        help="Starts the testcase in uUdbg (if installed)",
    )
    parser.add_argument(
        "-t",
        "--trace",
        default=False,
        action="store_true",
        help="Enables debug tracing",
    )
    parser.add_argument(
        "-w",
        "--wait",
        default=False,
        action="store_true",
        help="Wait for the state directory to be present",
    )
    args = parser.parse_args()

    Harness(args.config)
    Harness.harness(args.input_file, debug=args.debug, trace=args.trace, wait=args.wait)
