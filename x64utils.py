from unicorn.x86_const import *

INSN_WRMSR = b'\x0f\x30' 

MSR_FSBASE = 0xC0000100
MSR_GSBASE = 0xC0000101

def set_msr(uc, scratch, msr, val):
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
    uc.mem_write(scratch, INSN_WRMSR)
    uc.reg_write(UC_X86_REG_RAX, val & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RDX, (val >> 32) & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(INSN_WRMSR), count=1)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)

def get_msr(uc, scratch, msr):
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

def set_gs_base(uc, scratch, val):
    '''
    Set the GS.base hidden descriptor-register field to the given address.
    this enables referencing the gs segment on x86-64.
    '''
    return set_msr(uc, scratch, MSR_GSBASE, val)

def get_gs_base(uc, scratch):
    '''
    fetch the GS.base hidden descriptor-register field.
    '''
    return get_msr(uc, scratch, MSR_GSBASE)

def set_fs_base(uc, scratch, val):
    '''
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    '''
    return set_msr(uc, scratch, MSR_FSBASE, val)

def get_fs_base(uc, scratch):
    '''
    fetch the FS.base hidden descriptor-register field.
    '''
    return get_msr(uc, scratch, MSR_FSBASE)

def init_syscall_hook(exits, abort_func):
    def syscall_hook(uc, user_data): 
        """ Syscalls rarely happen, so we use them as speedy-ish hook hack for additional exits. """ 
        address = uc.reg_read(UC_X86_REG_RIP)
        print("Run over at {0:x}".format(address))
        if address in exits:
            # print("Run over at {0:x}".format(address))
            uc.emu_stop()
            abort_func(0)
            return
        # could add other hooks here
        print("No handler for syscall insn at {0:x}".format(address))
    return syscall_hook

