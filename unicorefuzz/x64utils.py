"""
Special stuff for the x64 architecture
Mostly using x64 for x86_64 since everybody knows what we mean and it's more concise, btw.
"""
from typing import Tuple, List, Callable

from unicornafl import Uc
from unicornafl.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EDX,
    UC_X86_REG_RAX,
    UC_X86_REG_RDX,
    UC_X86_REG_RCX,
    UC_X86_REG_RIP,
)

INSN_WRMSR = b"\x0f\x30"

MSR_FSBASE = 0xC0000100
MSR_GSBASE = 0xC0000101

SYSCALL_OPCODE = b"\x0f\x05"


def set_msr(uc: Uc, scratch: int, msr: int, val: int) -> None:
    """
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given scratch address, as it emits some code.
    """
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: wrmsr
    uc.mem_write(scratch, INSN_WRMSR)
    uc.reg_write(UC_X86_REG_RAX, val & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RDX, (val >> 32) & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch + len(INSN_WRMSR), count=1)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)


def get_msr(uc: Uc, scratch: int, msr: int) -> int:
    """
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given scratch address, as it emits some code.
    """
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: rdmsr
    buf = b"\x0f\x32"
    uc.mem_write(scratch, buf)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch + len(buf), count=1)
    eax = uc.reg_read(UC_X86_REG_EAX)
    edx = uc.reg_read(UC_X86_REG_EDX)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)

    return (edx << 32) | (eax & 0xFFFFFFFF)


def set_gs_base(uc: Uc, scratch: int, val: int) -> None:
    """
    Set the GS.base hidden descriptor-register field to the given address.
    this enables referencing the gs segment on x86-64.
    """
    return set_msr(uc, scratch, MSR_GSBASE, val)


def get_gs_base(uc: Uc, scratch: int) -> int:
    """
    fetch the GS.base hidden descriptor-register field.
    """
    return get_msr(uc, scratch, MSR_GSBASE)


def set_fs_base(uc: Uc, scratch: int, val: int) -> None:
    """
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    """
    return set_msr(uc, scratch, MSR_FSBASE, val)


def get_fs_base(uc: Uc, scratch: int) -> int:
    """
    fetch the FS.base hidden descriptor-register field.
    """
    return get_msr(uc, scratch, MSR_FSBASE)


def syscall_exit_hook(
    uc: Uc, user_data: Tuple[List[int], Callable[[int], None]]
) -> None:
    """ Syscalls rarely happen, so we use them as speedy-ish hook hack for additional exits. """
    exits, abort_func = user_data
    address = uc.reg_read(UC_X86_REG_RIP)
    print("Run over at {0:x}".format(address))
    if address in exits:
        # print("Run over at {0:x}".format(address))
        uc.emu_stop()
        abort_func(0)
        return
    # could add other hooks here
    print("No handler for syscall insn at {0:x}".format(address))


def set_exit(uc: Uc, addr: int) -> None:
    """
    We use syscalls for this as unicorn offers hooks. 
    Could also throw an UB2 instead and catch.
    """
    uc.mem_write(addr, SYSCALL_OPCODE)
