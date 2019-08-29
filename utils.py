import time
import os
import signal
import sys

import unicorn

from unicorn import UC_HOOK_INSN
from unicorn import UC_HOOK_CODE

from avatar2.archs import Architecture
from avatar2.archs.x86 import X86, X86_64
from avatar2.archs.arm import ARM, ARM_CORTEX_M3, ARMV7M, ARMBE

# TODO: Add mips? ARM64? More archs?

from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
from unicorn import *

import struct
import avatar2

import x64utils

import config

try:
    from uDdbg.utils import *
except Exception as ex:
    print("Error loading uDdbg: {}".format(ex))
    print("Install using ./setupdebug.sh")


X64 = X86_64
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

REQUEST_FOLDER = "requests"
STATE_FOLDER = "state"
REJECTED_ENDING = ".rejected"

MAPPED_PAGES = {}
PAGE_SIZE = 0x1000

_regs_name_cache = None


SYSCALL_OPCODE = b"\x0f\x05"

# TODO: arm64, mips, etc.
archs = {
    "x86": X86,
    "x86_64": X64,
    "x64": X64,
    "arm": ARM,
    "arm_cortex_m3": ARM_CORTEX_M3,
    "arm_v7m": ARMV7M,
    "armbe": ARMBE,
}


def get_arch(archname):
    """
    Look up Angr architecture and return it
    """
    if isinstance(archname, Architecture):
        return archname
    return archs[archname.lower()]


def init_capstone(arch):
    if not hasattr(arch, "capstone"):
        arch.capstone = Cs(arch.capstone_arch, arch.capstone_mode)
    return arch.capstone


def all_regs(arch=get_arch(config.ARCH)):
    """
    Get all (supported) registers of an arch
    """
    global _regs_name_cache
    if not _regs_name_cache:
        if isinstance(arch, str):
            arch = get_arch(arch)
        consts = arch.unicorn_consts
        regs = [
            k.split("_REG_")[1].lower()
            for k, v in consts.__dict__.items()
            if not k.startswith("__") and "_REG_" in k and not "INVALID" in k
        ]
        if arch == X64:
            # These two are not directly supported by unicorn.
            regs += ["gs_base", "fs_base"]
        _regs_name_cache = regs
    return _regs_name_cache


def uc_reg_const(arch, reg_name):
    """
    Returns an unicorn register constant to address the register by name.
    i.e.:
    `uc_reg_const("x64", "rip") #-> UC_X86_REG_RIP`
    """
    return getattr(arch.unicorn_consts, arch.unicorn_reg_tag + reg_name.upper())


def uc_get_pc(uc, arch):
    """
    Gets the current program counter from a unicorn instance
    """
    return uc.reg_read(uc_reg_const(arch, arch.pc_name))


def uc_load_registers(uc, arch=get_arch(config.ARCH)):
    """
    Loads all registers to unicorn, called in the harness.
    """
    regs = all_regs(arch)
    for r in regs:
        if r in arch.ignored_regs:
            # print("[d] Ignoring reg: {} (Ignored)".format(r))
            continue
        try:
            uc.reg_write(uc_reg_const(arch, r), fetch_register(r))
        except Exception as ex:
            # print("[d] Faild to load reg: {} ({})".format(r, ex))
            pass


def uc_start_forkserver(uc, arch=get_arch(config.ARCH)):
    """
    Starts the forkserver by executing an instruction on some scratch register
    """

    sys.stdout.flush()  # otherwise children will inherit the unflushed buffer
    scratch = config.SCRATCH_ADDR
    scratch_size = config.SCRATCH_SIZE
    uc.mem_map(config.SCRATCH_ADDR, config.SCRATCH_SIZE)

    if arch == X64:
        # prepare to do base register things
        gs_base = fetch_register("gs_base")
        fs_base = fetch_register("fs_base")

        # This will execute code -> starts afl-unicorn forkserver!
        x64utils.set_gs_base(uc, scratch, gs_base)
        # print("[d] setting gs_base to "+hex(gs))
        x64utils.set_fs_base(uc, scratch, fs_base)
        # print("[d] setting fs_base to "+hex(gs))
    else:
        # We still need to start the forkserver somehow to be consistent.
        # Let's emulate a nop for this.
        uc.mem_map(scratch, scratch_size)
        uc.mem_write(scratch, arch.insn_nop)
        uc.emu_start(scratch, count=1)


def angr_load_registers(state):
    """
    """
    for reg in state.arch.register_names.values():
        try:
            state.registers.store(reg, fetch_register(reg))
        except Exception as ex:
            print("Failed to retrieve register {}: {}".format(reg, ex))


def fetch_register(name):
    """
    Loads the value of a register from the dumped state
    """
    with open(os.path.join(config.WORKDIR, "state", name), "r") as f:
        return int(f.read())


def get_base(address):
    """
    Calculates the base address (aligned to PAGE_SIZE) to an address
    All you base are belong to us.
    """
    return address - address % PAGE_SIZE


def set_exits(uc, base_address):
    """
    We replace all hooks and exits with syscalls since they should be rare in kernel code.
    Then, when we encounter a syscall, we figure out if a syscall or exit occurred.
    This can also be used to add additional hooks in the future.
    """
    # TODO: This only works for X64!
    for end_addr in config.EXITS:
        if get_base(end_addr) == base_address:
            print("Setting exit {0:x}".format(end_addr))
            uc.mem_write(end_addr, SYSCALL_OPCODE)


def fetch_page_blocking(address, workdir=config.WORKDIR):
    """
    Fetches a page at addr in the harness, asking probe_wrapper, if necessary.
    """
    base_address = get_base(address)
    input_file_name = os.path.join(workdir, REQUEST_FOLDER, "{0:016x}".format(address))
    dump_file_name = os.path.join(
        workdir, STATE_FOLDER, "{0:016x}".format(base_address)
    )
    global MAPPED_PAGES
    if base_address in MAPPED_PAGES.keys():
        return base_address, MAPPED_PAGES[base_address]
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
                    if len(content) < PAGE_SIZE:
                        time.sleep(0.001)
                        continue
                    MAPPED_PAGES[base_address] = content
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


def path_for_page(address, workdir=config.WORKDIR):
    """
    Return the filename for a page
    """
    base_address = get_base(address)
    return os.path.join(workdir, "state", "{0:016x}".format(base_address))


def map_page_blocking(uc, address, workdir=config.WORKDIR):
    """
    Maps a page at addr in the harness, asking probe_wrapper.
    """
    base_address = get_base(address)
    input_file_name = os.path.join(workdir, REQUEST_FOLDER, "{0:016x}".format(address))
    dump_file_name = os.path.join(
        workdir, STATE_FOLDER, "{0:016x}".format(base_address)
    )
    global MAPPED_PAGES
    if base_address not in MAPPED_PAGES.keys():
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
                    if len(content) < PAGE_SIZE:
                        time.sleep(0.001)
                        continue
                    uc.mem_map(base_address, len(content))
                    uc.mem_write(base_address, content)
                    MAPPED_PAGES[base_address] = content
                    set_exits(uc, base_address)
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


def map_known_mem(uc, workdir=config.WORKDIR):
    for filename in os.listdir(os.path.join(workdir, STATE_FOLDER)):
        if not filename.endswith(REJECTED_ENDING) and not filename in all_regs():
            try:
                address = int(filename, 16)
                map_page_blocking(uc, address)
            except:
                pass


def wait_for_probe_wrapper():
    while not os.path.exists(os.path.join(config.WORKDIR, REQUEST_FOLDER)):
        print("[.] Waiting for probewrapper to be available...")
        time.sleep(5)
