import os
import signal
import sys
import time
from typing import Optional, List, Dict

from avatar2 import X86_64, X86, ARM, ARM_CORTEX_M3, ARMV7M, ARMBE
from capstone import Cs
from unicorn import (
    UC_MEM_WRITE_UNMAPPED,
    UC_ERR_READ_UNMAPPED,
    UC_MEM_WRITE,
    UC_ERR_READ_PROT,
    UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_WRITE_PROT,
    UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNALIGNED,
    UC_ERR_INSN_INVALID,
    UC_ARCH_X86,
    UC_MODE_32,
    UC_MODE_64,
    arm_const,
    x86_const,
    Uc, UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_MEM_FETCH, UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_INSN, UcError)

from avatar2.archs import Architecture
from avatar2.archs.x86 import X86
from avatar2.archs.arm import ARM
from unicorn.x86_const import UC_X86_INS_SYSCALL

from unicorefuzz import utils, x64utils

DEFAULT_PAGE_SIZE = 0x1000

X64 = X86_64  # type: Architecture
REQUEST_FOLDER = "requests"
STATE_FOLDER = "state"
REJECTED_ENDING = ".rejected"

# TODO:
# Fix avatar2 x86 mode upstream
# (ARM already contains unicorn_* and pc_name)
X86.pc_name = "eip"
X86.unicorn_arch = UC_ARCH_X86
X86.unicorn_mode = UC_MODE_32
X64.pc_name = "rip"
# unicorn_arch is the same/inherited from X86
X64.unicorn_mode = UC_MODE_64

ARM.unicorn_consts = arm_const
X86.unicorn_consts = x86_const

ARM.unicorn_reg_tag = "UC_ARM_REG_"
ARM.ignored_regs = []
ARM.insn_nop = b"\x00\x00\x00\x00"
X86.unicorn_reg_tag = "UC_X86_REG_"
X86.ignored_regs = ["cr0"]  # CR0 unicorn crash
X86.insn_nop = b"\x90"
X64.ignored_regs = X86.ignored_regs + ["fs", "gs"]  # crashes unicorn too

# TODO: Add mips? ARM64? More archs?
archs = {
    "x86": X86,
    "x86_64": X64,
    "x64": X64,
    "arm": ARM,
    "arm_cortex_m3": ARM_CORTEX_M3,
    "arm_v7m": ARMV7M,
    "armbe": ARMBE,
}


def _init_all_reg_names():
    for arch in archs.values():
        # noinspection PyTypeChecker
        arch.reg_names = utils.regs_from_unicorn(arch)


_init_all_reg_names()


def get_arch(archname) -> Architecture:
    """
    Look up Avatar architecture, add Ucf extras and return it
    """
    return archs[archname.lower()]


def unicorn_debug_instruction(uc: Uc, address: int, size: int, user_data: "Unicorefuzz") -> None:
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


def unicorn_debug_mem_access(uc: Uc, access: int, address: int, size: int, value: int, user_data) -> None:
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))


def unicorn_debug_mem_invalid_access(uc: Uc, access: int, address: int, size: int, value: int, user_data: "Unicorefuzz"):
    ucf = user_data  # type Unicorefuzz
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
        ucf.map_page_blocking(uc, address)
    except KeyboardInterrupt:
        uc.emu_stop()
        return False
    return True


def force_crash(uc_error: UcError) -> None:
    """
    This function should be called to indicate to AFL that a crash occurred during emulation.
    Pass in the exception received from Uc.emu_start()
    :param uc_error: The unicorn Error
    """
    mem_errors = [
        UC_ERR_READ_UNMAPPED,
        UC_ERR_READ_PROT,
        UC_ERR_READ_UNALIGNED,
        UC_ERR_WRITE_UNMAPPED,
        UC_ERR_WRITE_PROT,
        UC_ERR_WRITE_UNALIGNED,
        UC_ERR_FETCH_UNMAPPED,
        UC_ERR_FETCH_PROT,
        UC_ERR_FETCH_UNALIGNED,
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


class Unicorefuzz:

    def __init__(self, config, args):
        self.config = config
        self.args = args
        self.arch = get_arch(config.ARCH)

        self._mapped_page_cache = {}
        self.cs = Cs(self.arch.capstone_arch, self.arch.capstone_mode)

        self.statedir = os.path.join(config.WORKDIR, "state")
        self.requestdir = os.path.join(config.WORKDIR, "requests")

        self.fetched_regs = {}

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
                uc.reg_write(utils.uc_reg_const(self.arch, r), value)
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


    def uc_start_forkserver(self, uc, arch, scratch_addr, scratch_size):
        """
        Starts the forkserver by executing an instruction on some scratch register
        :param scratch_addr: The scratch address
        :param scratch_size: Size of the scratch space
        """

        sys.stdout.flush()  # otherwise children will inherit the unflushed buffer
        uc.mem_map(scratch_addr, scratch_size)

        if arch == X64:
            # prepare to do base register things
            gs_base = self.fetched_regs("gs_base")
            fs_base = self.fetched_regs("fs_base")

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
            uc.emu_start(scratch_addr, count=1)

    def angr_load_registers(self, ucf, state):
        """
        Load registers to angr
        """
        for reg in state.arch.register_names.values():
            try:
                state.registers.store(reg, ucf.fetch_reg(reg))
            except Exception as ex:
                print("Failed to retrieve register {}: {}".format(reg, ex))

    def map_page_blocking(self, uc, address):
        """
        Maps a page at addr in the harness, asking probe_wrapper.
        """
        workdir = self.config.WORKDIR
        page_size = self.config.PAGE_SIZE
        base_address = utils.get_base(page_size, address)
        input_file_name = os.path.join(
            workdir, REQUEST_FOLDER, "{0:016x}".format(address)
        )
        dump_file_name = os.path.join(
            workdir, STATE_FOLDER, "{0:016x}".format(base_address)
        )
        if base_address not in self._mapped_page_cache.keys():
            if os.path.isfile(dump_file_name + REJECTED_ENDING):
                print("CAN I HAZ EXPLOIT?")
                os.kill(os.getpid(), signal.SIGSEGV)
            if not os.path.isfile(dump_file_name):
                open(input_file_name, "a").close()
            print("mapping {}".format(hex(base_address)))
            while 1:
                try:
                    if os.path.isfile(dump_file_name + REJECTED_ENDING):
                        print("CAN I HAZ EXPLOIT?")
                        os.kill(os.getpid(), signal.SIGSEGV)
                    with open(dump_file_name, "rb") as f:
                        content = f.read()
                        if len(content) < page_size:
                            time.sleep(0.001)
                            continue
                        uc.mem_map(base_address, len(content))
                        uc.mem_write(base_address, content)
                        self._mapped_page_cache[
                            base_address
                        ] = content
                        self.set_exits(uc, base_address)
                        return
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

    def map_known_mem(self, uc):
        workdir = self.config.WORKDIR
        for filename in os.listdir(os.path.join(workdir, STATE_FOLDER)):
            if not filename.endswith(REJECTED_ENDING) and filename not in self.fetched_regs:
                try:
                    address = int(filename, 16)
                    self.map_page_blocking(uc, address)
                except:
                    pass

    def wait_for_probe_wrapper(self, workdir):
        while not os.path.exists(os.path.join(workdir, REQUEST_FOLDER)):
            print("[.] Waiting for probewrapper to be available...")
            time.sleep(0.5)

    def set_exits(self, uc, base_address):
        """
        We replace all hooks and exits with syscalls since they should be rare in kernel code.
        Then, when we encounter a syscall, we figure out if a syscall or exit occurred.
        This can also be used to add additional hooks in the future.
        :param uc: Unicorn instance
        :param arch: The arch
        :param base_address: the address we're mapping
        """
        arch = self.arch
        exits = self.exits
        # TODO: This only works for X64!
        for end_addr in exits:
            if utils.get_base(self.config.PAGE_SIZE, end_addr) == base_address:
                print("Setting exit {0:x}".format(end_addr))
                uc.mem_write(end_addr, x64utils.SYSCALL_OPCODE)

    def fetch_page_blocking(self, address, workdir):
        """
        Fetches a page at addr in the harness, asking probe_wrapper, if necessary.
        returns base_address, content
        """
        base_address = utils.get_base(self.config.PAGE_SIZE, address)
        input_file_name = os.path.join(workdir, REQUEST_FOLDER, "{0:016x}".format(address))
        dump_file_name = os.path.join(
            workdir, STATE_FOLDER, "{0:016x}".format(base_address)
        )
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

    def path_for_page(self, address: int) -> str:
        """
        Return the filename for a page
        """
        base_address = utils.get_base(self.config.PAGE_SIZE, address)
        return os.path.join(self.config.workdir, "state", "{0:016x}".format(base_address))

    def init_unicorn(self, tracing=False, debug=False) -> Uc:

        arch = self.arch
        config = self.config
        uc = Uc(arch.unicorn_arch, arch.unicorn_mode)

        if debug:
            # Try to load udbg
            sys.path.append(
                os.path.join(os.path.dirname(os.path.realpath(__file__)), "uDdbg")
            )
            from uDdbg.udbg import UnicornDbg
        if tracing:
            print("[+] Settings trace hooks")
            uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
            uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction, user_data=self)
            uc.hook_add(
                UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ | UC_HOOK_MEM_FETCH,
                unicorn_debug_mem_access,
                user_data=self
            )

        # if we only have a single exit, there is no need to potentially slow down execution with an insn hook.
        if len(config.EXITS) or len(config.ENTRY_RELATIVE_EXITS):

            # add MODULE_EXITS to EXITS
            config.EXITS += [x + pc for x in config.ENTRY_RELATIVE_EXITS]
            # add final exit to EXITS
            config.EXITS.append(pc + config.LENGTH)

            if arch == X64:
                exit_hook = x64utils.init_syscall_hook(config.EXITS, os._exit)
                uc.hook_add(UC_HOOK_INSN, exit_hook, None, 1, 0, UC_X86_INS_SYSCALL)
            else:
                # TODO: (Fast) solution for X86, ARM, ...
                raise Exception("Multiple exits not yet suppored for arch {}".format(arch))

        # On error: map memory.
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, unicorn_debug_mem_invalid_access)

        self.map_known_mem(uc)

        if debug or tracing:
            print("[*] Reading from file {}".format(input_file))

        # we leave out gs_base and fs_base on x64 since they start the forkserver
        self.uc_load_registers(uc)

        # let's see if the user wants a change.
        config.init_func(uc)

        # get pc from unicorn state since init_func may have altered it.
        pc = utils.uc_get_pc(uc, arch)

        # if we only have a single exit, there is no need to potentially slow down execution with an insn hook.
        if len(config.EXITS) or len(config.ENTRY_RELATIVE_EXITS):

            # add MODULE_EXITS to EXITS
            config.EXITS += [x + pc for x in config.ENTRY_RELATIVE_EXITS]
            # add final exit to EXITS
            config.EXITS.append(pc + config.LENGTH)

            if arch == X64:
                exit_hook = x64utils.init_syscall_hook(config.EXITS, os._exit)
                uc.hook_add(UC_HOOK_INSN, exit_hook, None, 1, 0, UC_X86_INS_SYSCALL)
            else:
                # TODO: (Fast) solution for X86, ARM, ...
                raise Exception("Multiple exits not yet suppored for arch {}".format(arch))

        # starts the afl forkserver
        utils.uc_start_forkserver(uc)

        input_file = open(input_file, "rb")  # load afl's input
        input = input_file.read()
        input_file.close()

        try:
            config.place_input(uc, input)
        except Exception as ex:
            print("[!] Error setting testcase for input {}: {}".format(input, ex))
            os._exit(1)

        if not debug:
            try:
                uc.emu_start(pc, pc + config.LENGTH, timeout=0, count=0)
            except UcError as e:
                print(
                    "[!] Execution failed with error: {} at address {:x}".format(
                        e, utils.uc_get_pc(uc, arch)
                    )
                )
                force_crash(e)
            # Exit without clean python vm shutdown: "The os._exit() function can be used if it is absolutely positively necessary to exit immediately"
            os._exit(0)
        else:
            print("[*] Starting debugger...")
            udbg = UnicornDbg()

            # TODO: Handle mappings differently? Update them at some point? + Proper exit after run?
            udbg.initialize(
                emu_instance=uc,
                entry_point=pc,
                exit_point=pc + config.LENGTH,
                hide_binary_loader=True,
                mappings=[
                    (hex(x), x, unicorefuzz.unicorefuzz.PAGE_SIZE)
                    for x in unicorefuzz.unicorefuzz._mapped_page_cache
                ],
            )

            def dbg_except(x, y):
                raise Exception(y)

            os.kill = dbg_except
            udbg.start()
            # TODO will never reach done, probably.
            print("[*] Done.")

        return Uc
