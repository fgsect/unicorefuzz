# Unicorefuzz

![Travis (.org)](https://img.shields.io/travis/fgsect/unicorefuzz)
![code-style: black](https://img.shields.io/badge/code%20style-black-000000.svg)


Fuzzing the Kernel using AFL Unicorn.
For details, skim through [the WOOT paper](https://www.usenix.org/system/files/woot19-paper_maier.pdf) or watch [this talk at CCCamp19](https://media.ccc.de/v/thms-32--emulate-fuzz-break-kernels).

## Unicorefuzz Setup
* Install Python
* Clone [afl++](https://github.com/vanhauser-thc/AFLplusplus) and follow instructions to install `./unicorn_mode` (or run `./setupaflpp.sh`)
* `pip install -r requirements.txt`

## Debug Kernel Setup (Skip this if you know how this works)

* Create a qemu-img and install your preferred OS on there through qemu
* An easy way to get a working userspace up and running in QEMU is to follow the steps described by syzkaller, namely [create-image.sh](https://github.com/google/syzkaller/blob/90c8f82ae8f12735e0e06d422dfea80758aaf0a5/tools/create-image.sh) 
* For kernel customization you might want to clone your preferred kernel version and compile it on the host. This way you can also compile your own kernel modules (e.g. example_module).
* In order to find out the address of a loaded module in the guest OS you can use `cat /proc/modules` to find out the base address of the module location. Use this as the offset for the function where you want to break. If you specify MODULE and BREAKOFFSET in the `config.py`, it should use `./get_mod_addr.sh` to start it automated.
* You can compile the kernel with debug info. When you have compiled the linux kernel you can start gdb from the kernel folder with `gdb vmlinux`. After having loaded other modules you can use the `lx-symbols` command in gdb to load the symbols for the other modules (make sure the .ko files of the modules are in your kernel folder). This way you can just use something like `break function_to_break` to set breakpoints for the required functions.
* In order to compile a custom kernel for Arch, download the current Arch kernel and set the .config to the Arch default. Then set `DEBUG_KERNEL=y`, `DEBUG_INFO=y`, `GDB_SCRIPTS=y` (for convenience), `KASAN=y`, `KASAN_EXTRA=y`. For convenience, we added a working [example_config](./example_config) that can be place to the linux dir.
* To only get necessary kernel modules boot the current system and execute `lsmod > mylsmod` and copy the mylsmod file to your host system into the linux kernel folder that you downloaded. Then you can use `make LSMOD=mylsmod localmodconfig` to only make the kernel modules that are actually needed by the guest system. Then you can compile the kernel like normal with `make`. Then mount the guest file system to `/mnt` and use `make modules_install INSTALL_MOD_PATH=/mnt`. At last you have to create a new initramfs, which apparently has to be done on the guest system. Here use `mkinitcpio -k <folder in /lib/modules/...> -g <where to put initramfs>`. Then you just need to copy that back to the host and let qemu know where your kernel and the initramfs are located.
* Setting breakpoints anywhere else is possible. For this, set `BREAKADDR` in the `config.py` instead.
* If you want fancy debugging, install [uDdbg](https://github.com/iGio90/uDdbg) with `./setupdebug.sh`
* Before fuzzing, run `sudo ./setaflops.sh` to initialize your system for fuzzing.

## Run

- ensure a target gdbserver is reachable, for example via `./startvm.sh`
- adapt `config.py`:
    - provide the target's gdbserver network address in the config to the probe wrapper
    - provide the target's target function to the probe wrapper and harness
    - make the harness put AFL's input to the desired memory location by adopting the `place_input` func `config.py`
    - add all EXITs
- start `./probe_wrapper.py`, it will (try to) connect to gdb.
- make the target execute the target function (by using it inside the vm)
- after the breakpoint was hit, run `./startafl.sh`. Make sure afl++ is in the PATH. (Use `./resumeafl.sh` to resume using the same input folder)

Putting afl's input to the correct location must be coded invididually for most targets.
However with modern binary analysis frameworks like IDA or Ghidra it's possible to find the desired location's address.

The following `place_input` method places at the data section of `sk_buff` in `key_extract`:

```python
    # read input into param xyz here:
    rdx = uc.reg_read(UC_X86_REG_RDX)
    utils.map_page_blocking(uc, rdx) # ensure sk_buf is mapped
    bufferPtr = struct.unpack("<Q",uc.mem_read(rdx + 0xd8, 8))[0]
    utils.map_page_blocking(uc, bufferPtr) # ensure the buffer is mapped
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
This dynamic method makes it rahter easy to find out breakpoints and that can then be fed to `config.py`.
On top, `startafl.sh` will forward port 22 (ssh) to 8022 - you can use it to ssh into the VM.
This makes it easier to interact with it.

## Debugging
You can step through the code, starting at the breakpoint, with any given input.
To do so, run `./harness.py -d $inputfile`.
Possible inputs to the harness:

`-d` flag starts the unicorn debugger ([uDdbg](https://github.com/iGio90/uDdbg)) that has to be installed using `./setupdebug.sh` first.
`-t` flag enables the afl-unicorn tracer. It prints every emulated instruction, as well as displays memory accesses.

## Gotchas
A few things to consider.

### FS\_BASE and GS\_BASE

Unicorn does not offer a way to directly set model specific registers. Since kernels use them to store pointers to process- or cpu-specific memory, Unicorefuzz makes unicorn execute `wrmsr` to set the `fs` and `gs` registers to the appropriate values.
To do this, you'll have to provide a non-used `SCRATCH_ADDR` in the `config.py`.

### Improve Fuzzing Speed

Right now, the Unicorefuzz `probe_wrapper.py` needs to be manually restarted after an amount of pages has been allocated. Allocated pages don't propagate back to the forkserver parent automatically and would need be reloaded from disk for each iteration.

### CMPXCHNG16b
~~Unicorn does not [handle CMPXCHNG16b correctly](https://github.com/unicorn-engine/unicorn/issues/1095).
Until that is addressed, we needed to hook each cmpxchng16b with a python reimplementation.
This is super hacky and should only be used if really needed.
Instead, try to start fuzzing after the instruction or do anything else.
If you do need it, add all occurrences you want to replace to the `config.py`~~

This issue seems to be resolved in the latest unicorn master branch. Unicornmode in AFL++ is based on a recent enough branch to work.

### EXITS
Exits on X64 use `syscall`, which is a 2 bytes instruction.
Using it to overwrite `ret` might break the line after the return instruction, since `ret` is only a single byte.
Instead, consider hooking the op before ret.
Exits on X86 and ARM are not yet supported. We'll get there :)

### IO/Printthings
It's generally a good idea to nop out kprintf or kernel printing functionality if possible, when the program is loaded into the emulator.

## Troubleshooting

If you got trouble running unicorefuzz, follow these rulse, worst case feel free to reach out to us, for example to @domenuk on twitter.

### No instrumentation

You probably have a installation of unicorn without AFL instumentation. You might have installed it via `pip` at some point.
Make sure when running `./harness.py`, the loaded `libunicorn.so` matches the one in the unicorn folder inside aflplusplus.
A common issue may be running the wrong python version... AFL++ installs AFL Unicorn for the system python by default.
Unicorefuzz should(tm) work inside a virtualenv, in case nothing else helps.

### Stil won't start

Run the harness without afl (`./harness.py -t ./sometestcase`).
If this works but it still crashes in AFL, set `AFL_DEBUG_CHILD_OUTPUT=1` to see some harness output while fuzzing.
