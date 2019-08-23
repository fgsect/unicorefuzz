#!/usr/bin/env python3
import os
import socket
import re
import sys
import time
import shutil
import inotify.adapters
from avatar2 import archs, Avatar, GDBTarget
from sh import which
from utils import get_base, get_arch, all_regs, REQUEST_FOLDER, STATE_FOLDER, REJECTED_ENDING

GDB_PATH = which("gdb")


def dump(workdir, target, base_address):
    print("dumping addr=0x{0:016x}".format(base_address))
    mem = target.read_memory(base_address, 0x1000, raw=True)
    with open(os.path.join(workdir, STATE_FOLDER, "{0:016x}".format(base_address)), "wb") as f:
        f.write(mem)


def forward_requests(target, workdir, requests_path, output_path):
    filenames = os.listdir(requests_path)
    while len(filenames):
        for filename in filenames:
            base_address = get_base(int(filename, 16))
            try:
                print("Reading {0:016x}".format(base_address))
                if not os.path.isfile(os.path.join(output_path, str(base_address))):
                    dump(workdir, target, base_address)
                    # we should restart afl now
            except KeyboardInterrupt as ex:
                print("cya")
                exit(0)
            except Exception as e:
                print("Could not get memory region at {}: {} (Found mem corruption?)".format(hex(base_address), repr(e)))
                with open(os.path.join(output_path, "{:016x}{}".format(base_address, REJECTED_ENDING)), 'a') as f:
                    f.write(repr(e))
            os.remove(os.path.join(requests_path, filename))
        filenames = os.listdir(requests_path)


def main(workdir, module=None, breakoffset=None, breakaddress=None, reset_state=True, arch="x64", gdb_port=1234):
    request_path = os.path.join(workdir, REQUEST_FOLDER)
    output_path = os.path.join(workdir, STATE_FOLDER)

    if arch != "x64":
        raise("Unsupported arch")
    if reset_state:
        try:
            shutil.rmtree(output_path)
        except:
            pass
    try:
        os.makedirs(output_path, exist_ok=True)
    except:
        pass

    if module:
        if breakaddress is not None:
            raise("Breakaddress and module supplied. They are not compatible.")
        if breakoffset is None:
            raise("Module but no breakoffset specified. Don't know where to break.")

        mem_addr = os.popen("./get_mod_addr.sh " + module).readlines()
        try:
            mem_addr = int(mem_addr[0], 16)
        except ValueError as ex:
            print("Error decoding module addr. Either module {} has not been loaded or something went wrong with ssh ({})".format(module, ex))
            exit(-1)
        print("Module " + module + " is at memory address " + hex(mem_addr))
        breakaddress = hex(mem_addr + breakoffset)
    else:
        breakaddress = hex(breakaddress)

    avatar = Avatar(arch=get_arch(arch), output_directory=os.path.join(workdir, "avatar"))
    target = avatar.add_target(GDBTarget, gdb_port=gdb_port, gdb_executable=GDB_PATH)
    target.init()

    target.set_breakpoint("*{}".format(breakaddress))
    print("[*] Breakpoint set at {}".format(breakaddress))
    print("[+] waiting for bp hit...")
    target.cont()
    target.wait()

    print("[+] hit! dumping registers and memory")

    # dump registers
    for reg in all_regs(get_arch(arch)):
        written = True
        reg_file = os.path.join(output_path, reg)
        with open(reg_file, "w") as f:
            try:
                val = target.read_register(reg)
                if isinstance(val, list):
                    # Avatar special registers (xmm, ...)
                    i32list = val
                    val = 0
                    for shift, i32 in enumerate(i32list):
                        val += (i32 << (shift * 32))
                f.write(str(val))
            except Exception as ex:
                #print("Ignoring {}: {}".format(reg, ex))
                written = False
        if not written:
            os.unlink(reg_file)

    try:
        os.mkdir(request_path)
    except:
        pass

    forward_requests(target, workdir, request_path, output_path)
    print("[*] Initial dump complete. Listening for requests from ./harness.py.")

    i = inotify.adapters.Inotify()
    i.add_watch(request_path, mask=inotify.constants.IN_CLOSE_WRITE) # only readily written files
    for event in i.event_gen(yield_nones=False):
        #print("Request: ", event)
        forward_requests(target, workdir, request_path, output_path)

    print("[*] Exiting probe_wrapper (keyboard interrupt)")
    

if __name__ == "__main__":
    import config
    main(
        module=config.MODULE, 
        breakoffset=config.BREAKOFFSET, 
        breakaddress=config.BREAKADDR, 
        workdir=config.WORKDIR, 
        arch=config.ARCH,
        gdb_port=config.GDB_PORT
    ) 
