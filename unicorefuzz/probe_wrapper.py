#!/usr/bin/env python3
"""
This thing connects to avatar and listens to requests for new pages (and dumps them)
Used for `ucf attach`
"""
import os
import shutil
import sys
from datetime import datetime

import inotify.adapters
from avatar2 import Avatar, Target

from unicorefuzz import configspec
from unicorefuzz.unicorefuzz import REJECTED_ENDING, Unicorefuzz


class ProbeWrapper(Unicorefuzz):
    def dump(self, target: Target, base_address: int) -> None:
        """
        Reads the memory at base_addres from avatar and dumps it to the state dir
        :param target: The avatar target
        :param base_address: The addr
        """
        mem = target.read_memory(base_address, self.config.PAGE_SIZE, raw=True)
        with open(
            os.path.join(self.statedir, "{:016x}".format(base_address)), "wb"
        ) as f:
            f.write(mem)
        print("[*] {}: Dumped 0x{:016x}".format(datetime.now(), base_address))

    def forward_requests(
        self, target: Target, requests_path: str, output_path: str
    ) -> None:
        """
        Forward current requests
        :param target: the avatar target to forward from
        :param requests_path: the path to listen for requests in
        :param output_path: the path to output pages to
        """
        filenames = os.listdir(requests_path)
        ignored = []  # type: List[str]
        while len(filenames):
            for filename in filenames:
                if filename.startswith(".") or filename in ignored:
                    # we don't want to fetch hidden or broken files.
                    continue
                try:
                    base_address = self.get_base(int(filename, 16))
                except ValueError as ex:
                    print(
                        "[+] {}: Illegal request file found: {}".format(
                            datetime.now(), filename
                        )
                    )
                try:
                    print(
                        "[+] {}: Received request for 0x{:016x}".format(
                            datetime.now(), base_address
                        )
                    )
                    if not os.path.isfile(os.path.join(output_path, str(base_address))):
                        self.dump(target, base_address)
                        # we should restart afl now
                except KeyboardInterrupt as ex:
                    print("cya")
                    exit(0)
                except Exception as e:
                    print(
                        "Could not get memory region at {}: {} (Found mem corruption?)".format(
                            hex(base_address), repr(e)
                        )
                    )
                    with open(
                        os.path.join(
                            output_path,
                            "{:016x}{}".format(base_address, REJECTED_ENDING),
                        ),
                        "a",
                    ) as f:
                        f.write(repr(e))
                os.remove(os.path.join(requests_path, filename))
            filenames = os.listdir(requests_path)

    def wrap_gdb_target(self, clear_state: bool = True) -> None:
        """
        Attach to a GDB target, set breakpoint, forward Memory
        :param clear_state: If the state folder should be cleared
        """
        request_path = self.requestdir
        output_path = self.statedir
        workdir = self.config.WORKDIR
        module = self.config.MODULE
        breakoffset = self.config.BREAK_OFFSET
        breakaddress = self.config.BREAK_ADDR
        arch = self.arch

        if clear_state:
            try:
                shutil.rmtree(output_path)
            except Exception:
                pass
        try:
            os.makedirs(output_path, exist_ok=True)
        except Exception:
            pass

        if module:
            if breakaddress is not None:
                raise ValueError(
                    "Breakaddress and module supplied. They are not compatible."
                )
            if breakoffset is None:
                raise ValueError(
                    "Module but no breakoffset specified. Don't know where to break."
                )

            mem_addr = os.popen(
                os.path.join(self.config.UNICORE_PATH, "get_mod_addr.sh ") + module
            ).readlines()
            try:
                mem_addr = int(mem_addr[0], 16)
            except ValueError as ex:
                print(
                    "Error decoding module addr. Either module {} has not been loaded or ssh is not configured ({})".format(
                        module, ex
                    )
                )
                exit(-1)
            print("Module " + module + " is at memory address " + hex(mem_addr))
            breakaddress = hex(mem_addr + breakoffset)
        else:
            if breakaddress is None:
                raise ValueError(
                    "Neither BREAK_ADDR nor MODULE + BREAK_OFFSET specified in config.py"
                )
            breakaddress = hex(breakaddress)

        avatar = Avatar(arch=arch, output_directory=os.path.join(workdir, "avatar"))

        print("[*] Initializing Avatar2")
        target = self.config.init_avatar_target(self, avatar)  # type: Target

        target.set_breakpoint("*{}".format(breakaddress))
        print("[+] Breakpoint set at {}".format(breakaddress))
        print("[*] Waiting for bp hit...")
        target.cont()
        target.wait()

        print("[+] Breakpoint hit! dumping registers and memory")

        # dump registers
        for reg in arch.reg_names:
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
                            val += i32 << (shift * 32)
                    f.write(str(val))
                except Exception as ex:
                    # print("Ignoring {}: {}".format(reg, ex))
                    written = False
            if not written:
                os.unlink(reg_file)

        if not os.path.isdir(request_path):
            print("[+] Creating request folder")
            os.mkdir(request_path)

        self.forward_requests(target, request_path, output_path)
        print("[*] Initial dump complete. Listening for requests from ucf emu.")

        i = inotify.adapters.Inotify()
        # noinspection PyUnresolvedReferences
        i.add_watch(request_path, mask=inotify.constants.IN_CLOSE_WRITE)
        for event in i.event_gen(yield_nones=False):
            # print("Request: ", event)
            self.forward_requests(target, request_path, output_path)

        print("[*] Exiting probe wrapper (keyboard interrupt)")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        config_path = sys.argv[1]
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            raise Exception(
                "Probe wrapper for Unicorefuz.\nOnly expected (optional) parameter: config.py"
            )
    elif len(sys.argv) > 2:
        raise Exception(
            "Too many arguments. Only expected (optional) parameter: config.py"
        )
    else:
        config_path = os.getcwd()
    config = configspec.load_config(config_path)

    ProbeWrapper(config).wrap_gdb_target()
