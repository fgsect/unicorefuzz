# Unicorefuzz

[![Build Status](https://travis-ci.com/fgsect/unicorefuzz.svg?branch=master)](https://travis-ci.com/fgsect/unicorefuzz)
![code-style: black](https://img.shields.io/badge/code%20style-black-000000.svg)


Fuzzing the Kernel using UnicornAFL and AFL++.
For details, skim through [the WOOT paper](https://www.usenix.org/system/files/woot19-paper_maier.pdf) or watch [this talk at CCCamp19](https://media.ccc.de/v/thms-32--emulate-fuzz-break-kernels).

## Is it any good?

[yes](https://news.ycombinator.com/item?id=3067434).

![AFL Screenshot](unicorefuzzing.png)

## Unicorefuzz Setup
* Install python2 & python3 (ucf uses python3, however qemu/unicorn needs python2 to build)
* Run `./setup.sh`, preferrably inside a Virtualenv (else python deps will be installed using `--user`).
During install, [afl++](https://github.com/vanhauser-thc/AFLplusplus) and [uDdbg](https://github.com/iGio90/uDdbg) as well as python deps will be pulled and installed.
* Enjoy `ucf`

## Upgrading

When upgrading from an early version of ucf:

* Unicorefuzz will notify you of config changes and new options automatically.
* Alternatively, run ` ucf spec` to output a commented `config.py` spec-like element.
* `probe_wrapper.py` is now `ucf attach`.
* `harness.py` is now named `ucf emu`.
* The song remains the same.

## Debug Kernel Setup (Skip this if you know how this works)

* Create a qemu-img and install your preferred OS on there through qemu
* An easy way to get a working userspace up and running in QEMU is to follow the steps described by syzkaller, namely [create-image.sh](https://github.com/google/syzkaller/blob/90c8f82ae8f12735e0e06d422dfea80758aaf0a5/tools/create-image.sh) 
* For kernel customization you might want to clone your preferred kernel version and compile it on the host. This way you can also compile your own kernel modules (e.g. example\_module).
* In order to find out the address of a loaded module in the guest OS you can use `cat /proc/modules` to find out the base address of the module location. Use this as the offset for the function where you want to break. If you specify `MODULE` and `BREAK_OFFSET` in the `config.py`, it should use `./get_mod_addr.sh` to start it automated.
* You can compile the kernel with debug info. When you have compiled the linux kernel you can start gdb from the kernel folder with `gdb vmlinux`. After having loaded other modules you can use the `lx-symbols` command in gdb to load the symbols for the other modules (make sure the .ko files of the modules are in your kernel folder). This way you can just use something like `break function_to_break` to set breakpoints for the required functions.
* In order to compile a custom kernel for Arch, download the current Arch kernel and set the .config to the Arch default. Then set `DEBUG_KERNEL=y`, `DEBUG_INFO=y`, `GDB_SCRIPTS=y` (for convenience), `KASAN=y`, `KASAN_EXTRA=y`. For convenience, we added a working [example\_config](example_module/example_config) that can be place to the linux dir.
* To only get necessary kernel modules boot the current system and execute `lsmod > mylsmod` and copy the mylsmod file to your host system into the linux kernel folder that you downloaded. Then you can use `make LSMOD=mylsmod localmodconfig` to only make the kernel modules that are actually needed by the guest system. Then you can compile the kernel like normal with `make`. Then mount the guest file system to `/mnt` and use `make modules_install INSTALL_MOD_PATH=/mnt`. At last you have to create a new initramfs, which apparently has to be done on the guest system. Here use `mkinitcpio -k <folder in /lib/modules/...> -g <where to put initramfs>`. Then you just need to copy that back to the host and let qemu know where your kernel and the initramfs are located.
* Setting breakpoints anywhere else is possible. For this, set `BREAKADDR` in the `config.py` instead.
* For fancy debugging, ucf uses [uDdbg](https://github.com/iGio90/uDdbg)
* Before fuzzing, run `sudo ./setaflops.sh` to initialize your system for fuzzing.

## Run

- ensure a target gdbserver is reachable, for example via `./startvm.sh`
- adapt `config.py`:
    - provide the target's gdbserver network address in the config to the probe wrapper
    - provide the target's target function to the probe wrapper and harness
    - make the harness put AFL's input to the desired memory location by adopting the `place_input` func `config.py`
    - add all EXITs
- start `ucf attach`, it will (try to) connect to gdb.
- make the target execute the target function (by using it inside the vm)
- after the breakpoint was hit, run `ucf fuzz`. Make sure afl++ is in the PATH. (Use `./resumeafl.sh` to resume using the same input folder)

Putting afl's input to the correct location must be coded invididually for most targets.
However with modern binary analysis frameworks like IDA or Ghidra it's possible to find the desired location's address.

The following `place_input` method places at the data section of `sk_buff` in `key_extract`:

```python
    # read input into param xyz here:
    rdx = uc.reg_read(UC_X86_REG_RDX)
    utils.map_page(uc, rdx) # ensure sk_buf is mapped
    bufferPtr = struct.unpack("<Q",uc.mem_read(rdx + 0xd8, 8))[0]
    utils.map_page(uc, bufferPtr) # ensure the buffer is mapped
    uc.mem_write(rdx, input) # insert afl input
    uc.mem_write(rdx + 0xc4, b"\xdc\x05") # fix tail
```

## QEMUing the Kernel
A few general pointers.
When using `./startvm.sh`, the VM can be debugged via gdb.
Use
```bash
$gdb
>file ./linux/vmlinux
>target remote :1234
```
This dynamic method makes it rather easy to find out breakpoints and that can then be fed to `config.py`.
On top, `startvm.sh` will forward port 22 (ssh) to 8022 - you can use it to ssh into the VM.
This makes it easier to interact with it.

## Debugging
You can step through the code, starting at the breakpoint, with any given input.
The fancy debugging makes use of [uDdbg](https://github.com/iGio90/uDdbg).
To do so, run `ucf emu -d $inputfile`.
Possible inputs to the harness (the thing wrapping afl-unicorn) that help debugging:

`-d` flag loads the target inside the unicorn debugger ([uDdbg](https://github.com/iGio90/uDdbg))
`-t` flag enables the afl-unicorn tracer. It prints every emulated instruction, as well as displays memory accesses.

## Gotchas
A few things to consider.

### FS\_BASE and GS\_BASE

Unicorn did not offer a way to directly set model specific registers directly.
The forked unicornafl version of AFL++ finally supports it. Most ugly code of earlier versions was scrapped.

### Improve Fuzzing Speed

Right now, the Unicorefuzz `ucf attach` harness might need to be manually restarted after an amount of pages has been allocated. 
Allocated pages should propagate back to the forkserver parent automatically but might still get reloaded from disk for each iteration.

### IO/Printthings

It's generally a good idea to nop out kprintf or kernel printing functionality if possible, when the program is loaded into the emulator.

## Troubleshooting

If you got trouble running unicorefuzz, follow these rulse, worst case feel free to reach out to us, for example to @domenuk on twitter. For some notes on debugging and developing ucf and afl-unicorn further, read [DEVELOPMENT.md](./DEVELOPMENT.md)

### Just won't start

Run the harness without afl (`ucf emu -t ./sometestcase`).
Make sure you are not in a virtualenv or in the correct one.
If this works but it still crashes in AFL, set `AFL_DEBUG_CHILD_OUTPUT=1` to see some harness output while fuzzing.

### All testcases time out

Make sure `ucf attach` is running, in the same folder, and breakpoint has been triggered.
