import time
import os
import signal
import sys

import unicorn

from unicorn import UC_HOOK_INSN
from unicorn import UC_HOOK_CODE

from avatar2.archs import Architecture
from avatar2.archs.x86 import X86, X86_64
from avatar2.archs.arm import ARM, ARM_CORTEX_M3, ARMBE
#TODO: Add mips? More archs?

from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *

import struct
import avatar2

import config

# TODO: fix avatar2 x86 mode
X64 = X86_64
X86.unicorn_arch = unicorn.UC_ARCH_X86
X86.unicorn_mode = unicorn.UC_MODE_32
X64.unicorn_mode = unicorn.UC_MODE_64

ARM.unicorn_consts = unicorn.arm_const
X86.unicorn_consts = unicorn.x86_const

ARM.unicorn_reg_tag = "UC_ARM_REG_"
ARM.ignored_regs = []
X86.unicorn_reg_tag = "UC_X86_REG_"
X86.ignored_regs = ["cr0","cr2","cr3","cr4","cr8"] # these make unicorn crash
#TODO: arm64, mips, etc.


FSMSR = 0xC0000100
GSMSR = 0xC0000101

MAPPED_PAGES = {}
PAGE_SIZE = 0x1000

SYSCALL_OPCODE = b'\x0f\x05'


archs = {
        "x86": X86,
        "x86_64": X64,
        "x64": X64,
        "arm": ARM,
        "arm_cortex_m3": ARM,
        "armbe": ARMBE
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


def set_gs_base(uc, addr):
    '''
    set the GS.base hidden descriptor-register field to the given address.
    this enables referencing the gs segment on x86-64.
    '''
    return set_msr(uc, GSMSR, addr)

def get_gs_base(uc):
    '''
    fetch the GS.base hidden descriptor-register field.
    '''
    return get_msr(uc, GSMSR)

def set_fs_base(uc, addr):
    '''
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    '''
    return set_msr(uc, FSMSR, addr)

def get_fs_base(uc):
    '''
    fetch the FS.base hidden descriptor-register field.
    '''
    return get_msr(uc, FSMSR)

def set_msr(uc, msr, value, scratch=config.SCRATCH_ADDR):
    '''
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given scratch address, as it emits some code.
    '''
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: wrmsr
    buf = b'\x0f\x30'
    uc.mem_write(scratch, buf)
    uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)

def get_msr(uc, msr, scratch=config.SCRATCH_ADDR):
    '''
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given scratch address, as it emits some code.
    '''
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: rdmsr
    buf = b'\x0f\x32'
    uc.mem_write(scratch, buf)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)
    eax = uc.reg_read(UC_X86_REG_EAX)
    edx = uc.reg_read(UC_X86_REG_EDX)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)

    return (edx << 32) | (eax & 0xFFFFFFFF)


def load_angr_registers(state):
    for reg in state.arch.register_names.values():
        try:
            state.registers.store(reg, fetch_register(reg))
        except Exception as ex:
            print("Failed to retrieve register {}: {}".format(reg, ex))

def all_regs(arch=get_arch(config.ARCH)):
    if isinstance(arch, str):
        arch = get_arch(arch)
    consts = arch.unicorn_consts
    regs = [k.split("_REG_")[1].lower() for k, v in consts.__dict__.items() if
            not k.startswith("__") and "_REG_" in k and not "INVALID" in k]
    if arch == X64:
        # These two are not directly supported by unicorn.
        regs += ["gs_base", "fs_base"]
    return regs

def uc_reg(arch, reg_name):
    return getattr(arch.unicorn_consts, arch.unicorn_reg_tag + reg_name.upper())

def get_pc(uc, arch):
    u_consts = arch.unicorn_consts
    if arch == X64:
        reg = u_consts.UC_X86_REG_RIP
    elif arch == X86:
        reg = u_consts.UC_X86_REG_EIP
    elif isinstance(arch, ARM): # also includes subtypes
        reg = u_consts.UC_ARM_REG_PC
        # TODO:
        # UC_ARM64_REG_PC 
        # UC_MIPS_REG_PC
        # UC_SPARC_REG_PC
        # UC_M68K_REG_PC
    else:
        raise Exception("Unsupported Arch")
    return uc.reg_read(reg)

def load_registers(uc, arch=get_arch(config.ARCH)):
    regs = all_regs(arch)
    for r in regs:
        if r in arch.ignored_regs:
            print("Ignoring reg: {} (Ignored)".format(r)) # -> Ignored UC_X86_REG_MSR
            continue
        try:
            uc.reg_write(uc_reg(arch, r), fetch_register(r))
        except Exception as ex:
            print("Ignoring reg: {} ({})".format(r, ex)) # -> Ignored UC_X86_REG_MSR
            #pass 

    sys.stdout.flush() # otherwise children will inherit the unflushed buffer

    if arch == X64:
        # prepare to do base register things
        uc.mem_map(config.SCRATCH_ADDR, config.SCRATCH_SIZE)
        gs_base = fetch_register("gs_base")
        fs_base = fetch_register("fs_base")

        # This will execute code -> starts afl-unicorn forkserver!
        set_gs_base(uc, gs_base)
        #print("setting gs_base to "+hex(gs))
        set_fs_base(uc, fs_base)
        #print("setting fs_base to "+hex(gs))


def fetch_register(name):
    with open(os.path.join(config.WORKDIR, "state", name), "r") as f:
        return int(f.read())

def _base_address(address):
    return address - address % PAGE_SIZE

def syscall_hook(uc, user_data):
    """
    Syscalls rarely happen, so we use them as speedy-ish hook hack for additional exits.
    """
    address = uc.reg_read(UC_X86_REG_RIP)
    if address in config.EXITS:
        # print("Run over at {0:x}".format(address))
        uc.emu_stop()
        os._exit(0)
        return
    # could add other hooks here
    print("No handler for syscall insn at {0:x}".format(address))

def set_exits(uc, base_address):
    """
    We replace all hooks and exits with syscalls since they should be rare in kernel code.
    Then, when we encounter a syscall, we figure out if a syscall or exit occurred.
    This can also be used to add additional hooks in the future.
    """
    for end_addr in config.EXITS:
        if _base_address(end_addr) == base_address:
            print("Setting exit {0:x}".format(end_addr))
            uc.mem_write(end_addr, SYSCALL_OPCODE)


def fetch_page_blocking(address, workdir=config.WORKDIR):
    """
    Fetches a page at addr in the harness, asking probe_wrapper, if necessary.
    """
    base_address = _base_address(address)
    input_file_name = os.path.join(workdir, "requests", "{0:016x}".format(address))
    dump_file_name = os.path.join(workdir, "state", "{0:016x}".format(base_address))
    global MAPPED_PAGES
    if base_address in MAPPED_PAGES.keys():
        return base_address, MAPPED_PAGES[base_address]
    else:
        if os.path.isfile(dump_file_name + ".rejected"):
            raise Exception("Page can not be loaded from Target") # TODO: Exception class?
            #os.kill(os.getpid(), signal.SIGSEGV)
        if not os.path.isfile(dump_file_name):
            open(input_file_name, 'a').close()
        print("mapping {}".format(hex(base_address)))
        while 1:
            try:
                if os.path.isfile(dump_file_name + ".rejected"):
                    raise Exception("Page can not be loaded from Target") # TODO: Exception class?
                with open(dump_file_name, "rb") as f:
                    content = f.read()
                    if len(content) < PAGE_SIZE:
                        time.sleep(0.001)
                        continue
                    MAPPED_PAGES[base_address] = content
                    return base_address, content
            except IOError:
                pass
            except Exception as e: #todo this shouldn't happen if we don't map like idiots
                print(e)
                print("map_page_blocking failed: base address={0:016x}".format(base_address))
                #exit(1)


def path_for_page(address, workdir=config.WORKDIR):
    """
    Return the filename for a page
    """
    base_address = _base_address(address)
    return os.path.join(workdir, "state", "{0:016x}".format(base_address))


def map_page_blocking(uc, address, workdir=config.WORKDIR):
    """
    Maps a page at addr in the harness, asking probe_wrapper.
    """
    base_address = _base_address(address)
    input_file_name = os.path.join(workdir, "requests", "{0:016x}".format(address))
    dump_file_name = os.path.join(workdir, "state", "{0:016x}".format(base_address))
    global MAPPED_PAGES
    if base_address not in MAPPED_PAGES.keys():
        if os.path.isfile(dump_file_name + ".rejected"):
            print("CAN I HAZ EXPLOIT?")
            os.kill(os.getpid(), signal.SIGSEGV)
        if not os.path.isfile(dump_file_name):
            open(input_file_name, 'a').close()
        print("mapping {}".format(hex(base_address)))
        while 1:
            try:
                if os.path.isfile(dump_file_name + ".rejected"):
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
            except Exception as e: #todo this shouldn't happen if we don't map like idiots
                print(e)
                print("map_page_blocking failed: base address={0:016x}".format(base_address))
                #exit(1)

def map_known_mem(uc, workdir=config.WORKDIR):
    for filename in os.listdir(os.path.join(workdir, "state")):
        if not filename.endswith(".rejected"):
            try:
                address = int(filename, 16)
                map_page_blocking(uc, address)
            except:
                pass
