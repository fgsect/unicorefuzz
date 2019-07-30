#!/usr/bin/python
import os
import socket
import re
import sys
import time
from avatar2 import archs, Avatar, GDBTarget
from IPython import embed
import shutil
from sh import which
from util import _base_address

GDB_PORT = 1234
GDB_PATH = which("gdb")

def dump(workdir, target, base_address):
    print("dumping addr=0x{0:016x}".format(base_address))
    mem = target.read_memory(base_address, 0x1000, raw=True)
    with open(os.path.join(workdir, "state", "{0:016x}".format(base_address)), "wb") as f:
        f.write(mem)


def main(workdir, module=None, breakoffset=None, breakaddress=None, reset_state=True, arch="x64"):
    requests = os.path.join(workdir, "requests")
    output = os.path.join(workdir, "state")


    if arch != "x64":
        raise("Unsupported arch")
    if reset_state:
        try:
            shutil.rmtree(output)
        except:
            pass
    try:
        os.makedirs(output, exist_ok=True)
    except:
        pass

    if module:
        if breakaddress is not None:
            raise("Breakaddress and module supplied. They are not compatible.")
        if breakoffset is None:
            raise("Module but no breakoffset specified. Don't know where to break.")

        mem_addr = os.popen("./get_mod_addr.sh " + module).readlines()
        if len(mem_addr) != 1:
            print("either module " + module + " has not been loaded or something went wrong with ssh")
            exit()
        mem_addr = int(mem_addr[0], 16)
        print("Module " + module + " is at memory address " + hex(mem_addr))
        breakaddress = hex(mem_addr + breakoffset)
    else:
        breakaddress = hex(breakaddress)

    avatar = Avatar(arch=archs.x86.X86_64, output_directory=os.path.join(workdir, "avatar"))
    target = avatar.add_target(GDBTarget, gdb_port=GDB_PORT, gdb_executable=GDB_PATH)
    target.init()

    target.set_breakpoint("*{}".format(breakaddress))
    print("Breakpoint set at {}".format(breakaddress))
    print("waiting for bp hit...")
    target.cont()
    target.wait()

    print("hit! dumping registers and memory")

    # dump registers
    for reg in list(archs.x86.X86_64.registers.keys()) + ["fs_base", "gs_base"]:
        with open(os.path.join(output, reg), "w") as f:
            f.write(str(target.read_register(reg)))
    for reg in archs.x86.X86_64.special_registers.keys():
        with open(os.path.join(output, reg), "w") as f:
            f.write(str(archs.x86.X86_64.special_registers[reg]))

    while True:
        try:
            os.mkdir(requests)
        except:
            pass

        for filename in os.listdir(requests):
            base_address = _base_address(int(filename, 16))
            try:
                print("Reading {0:016x}".format(base_address))
                if not os.path.isfile(os.path.join(output, str(base_address))):
                    dump(workdir, target, base_address)
                    # we should restart afl now
            except KeyboardInterrupt as ex:
                print("cya")
                exit(0)
            except Exception as e:
                print(e)
                open(os.path.join(output, "{0:016x}.rejected".format(base_address)), 'a').close()
            os.remove(os.path.join(requests, filename))
        time.sleep(1)


if __name__ == "__main__":
    import config
    main(module=config.MODULE, breakoffset=config.BREAKOFFSET, breakaddress=config.BREAKADDR, workdir=config.WORKDIR) #main(module="procfs1", breakoffset=0x10, input=config.INPUT_DIR, output=config.OUTPUT_DIR)
