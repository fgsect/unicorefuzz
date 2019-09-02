import time
import signal
import sys

from avatar2 import Architecture
from capstone import *
from unicorn import *

import unicorefuzz.unicorefuzz
from unicorefuzz import x64utils
from unicorefuzz import unicorefuzz

try:
    from unicorefuzz.uDdbg.utils import *
except Exception as ex:
    print("Error loading uDdbg: {}".format(ex))
    print("Install using ./setupdebug.sh")


# TODO: arm64, mips, etc.


def regs_from_unicorn(arch):
    """
    Get all (supported) registers of an arch from Unicorn constants
    """
    consts = arch.unicorn_consts
    regs = [
        k.split("_REG_")[1].lower()
        for k, v in consts.__dict__.items()
        if not k.startswith("__") and "_REG_" in k and not "INVALID" in k
    ]
    if arch == unicorefuzz.X64:
        # These two are not directly supported by unicorn.
        regs += ["gs_base", "fs_base"]
    return regs


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


def uc_load_registers(uc, arch, workdir):
    """
    Loads all registers to unicorn, called in the harness.
    """
    for r in arch.reg_names:
        if r in arch.ignored_regs:
            # print("[d] Ignoring reg: {} (Ignored)".format(r))
            continue
        try:
            uc.reg_write(uc_reg_const(arch, r), fetch_register(r, workdir))
        except Exception as ex:
            # print("[d] Faild to load reg: {} ({})".format(r, ex))
            pass


def uc_start_forkserver(uc, arch, scratch_addr, scratch_size):
    """
    Starts the forkserver by executing an instruction on some scratch register
    :param scratch_addr: The scratch address
    :param scratch_size: Size of the scratch space
    """

    sys.stdout.flush()  # otherwise children will inherit the unflushed buffer
    uc.mem_map(scratch_addr, scratch_size)

    if arch == unicorefuzz.X64:
        # prepare to do base register things
        gs_base = fetch_register("gs_base")
        fs_base = fetch_register("fs_base")

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


def angr_load_registers(ucf, state):
    """
    Load registers to angr
    """
    for reg in state.arch.register_names.values():
        try:
            state.registers.store(reg, ucf.fetch_reg(reg))
        except Exception as ex:
            print("Failed to retrieve register {}: {}".format(reg, ex))




def get_base(address):
    """
    Calculates the base address (aligned to PAGE_SIZE) to an address
    All you base are belong to us.
    """
    return address - address % PAGE_SIZE


def set_exits(uc, arch, base_address, exits):
    """
    We replace all hooks and exits with syscalls since they should be rare in kernel code.
    Then, when we encounter a syscall, we figure out if a syscall or exit occurred.
    This can also be used to add additional hooks in the future.
    :param uc: Unicorn instance
    :param arch: The arch
    :param base_address: the address we're mapping
    """
    # TODO: This only works for X64!
    for end_addr in exits:
        if get_base(end_addr) == base_address:
            print("Setting exit {0:x}".format(end_addr))
            uc.mem_write(end_addr, x64utils.SYSCALL_OPCODE)


def fetch_page_blocking(address, workdir):
    """
    Fetches a page at addr in the harness, asking probe_wrapper, if necessary.
    returns base_address, content
    """
    base_address = get_base(address)
    input_file_name = os.path.join(workdir, REQUEST_FOLDER, "{0:016x}".format(address))
    dump_file_name = os.path.join(
        workdir, STATE_FOLDER, "{0:016x}".format(base_address)
    )
    if base_address in unicorefuzz.unicorefuzz._mapped_page_cache.keys():
        return base_address, unicorefuzz.unicorefuzz._mapped_page_cache[base_address]
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
                    unicorefuzz.unicorefuzz._mapped_page_cache[base_address] = content
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


def path_for_page(address, workdir):
    """
    Return the filename for a page
    """
    base_address = get_base(address)
    return os.path.join(workdir, "state", "{0:016x}".format(base_address))


def map_page_blocking(uc, address, workdir):
    """
    Maps a page at addr in the harness, asking probe_wrapper.
    """
    base_address = get_base(address)
    input_file_name = os.path.join(workdir, REQUEST_FOLDER, "{0:016x}".format(address))
    dump_file_name = os.path.join(
        workdir, STATE_FOLDER, "{0:016x}".format(base_address)
    )
    if base_address not in unicorefuzz.unicorefuzz._mapped_page_cache.keys():
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
                    unicorefuzz.unicorefuzz._mapped_page_cache[base_address] = content
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


def map_known_mem(uc, workdir):
    for filename in os.listdir(os.path.join(workdir, STATE_FOLDER)):
        if not filename.endswith(REJECTED_ENDING) and not filename in all_regs():
            try:
                address = int(filename, 16)
                map_page_blocking(uc, address)
            except:
                pass


def wait_for_probe_wrapper(workdir):
    while not os.path.exists(os.path.join(workdir, REQUEST_FOLDER)):
        print("[.] Waiting for probewrapper to be available...")
        time.sleep(5)
