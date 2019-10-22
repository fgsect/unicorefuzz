# UCF Development

In this markdown file, we collect some tips about debugging and developing ucf further.

## Typing

For good measure, try to add type hints wherever you are.
We currently develop with backwards compatible python3 in mind.
Functions may be annotated inline `dev like(this: str) -> None:`.
However to annotate types, we prefer to add type comments (PEP something) `like = this # type: str`.

## Profiling

For speed, ucf kills the python vm with the internal `os._exit` instead of doing a clean `exit`.
This, however, trips profiling tools.

In case you want to run a profiler (or other biz), run ucf with `UCF_DEBUG_CLEAN_SHUTDOWN=1`.

## Debugging

There are different layers to be debugged.
The python code and afl++/unicorn code. 

### Python Debugging

Debugging the python stuff should be easy. Use your favorite pdb interface or pycharm to step thorugh the code, or simply sprinkle printfs around.

### Unicorn Debugging

Debugging bugs in unicorn is a different beast.
Sometimes it's necessary to debug `libunicorn.so` with the real AFL forkserver attached.
A possible best way is via GDB.

#### Building Unicorn With Debug Symbols

This is not super straight forward, but easy enough. We do it by following these steps.
For this, it's adviced to build unicorn with debug symbols.
Change dir to unicorn.
```cd ./AFLplusplus/unicorn_mode/unicorn```
There, edit `config.mk` and change `UNICORN_DEBUG` to `UNICORN_DEBUG ?= yes`.

Afterwards, rebuild Unicorn using something like
```make clean -j8; make -j8```

#### Starting the debugger:

With libunicorn.so built with symbols, let's start ucf in a debugger.
```bash
UCF_DEBUG_SLEEP_BEFORE_FORK=10 UCF_DEBUG_START_GDB=1 ucf fuzz -P -c ./unicorefuzz_cifs/config.py
```
`UCF_DEBUG_START_GDB=1` will load ucf inside afl-fuzz inside gdb.
`UCF_DEBUG_SLEEP_BEFORE_FORK=10` will add a sleep of 10 seconds right before the afl-unicorn forkserver starts. This will be important in the next step

### Debugging unicorn, as child of afl

Inside the gdb shell, make sure you follow the child AFL will spawn for the fork server:

```
set follow-fork-mode child
```

And break whenever afl execs python3/ucf:
```
catch exec
```

Then run afl using `r`.

After the catchpoint triggers, make sure you don't follow random python or avatar threads:
```
set follow-fork-mode parent
```
and continue (`c`) until you see output like 
```
[d] Sleeping. Forkserver will start in 10 seconds.
```
Immediately hit `ctrl+c` to break.

Now start setting your desired breakpoints, for example `b uc_emu_start` or `b afl_forkserver` and then continue (`c`).

Using `set follow-fork-mode child` again at the right time (i.e. right before the `fork()` in `afl-unicorn-cpu-inl.h`) allows debugging the actual unicorn execution.

Another, kinda tedious, way, to debug, is to keep the parent process around using (gdb non-stop mode)[https://www-zeuthen.desy.de/unix/unixguide/infohtml/gdb/Non_002dStop-Mode.html] and setting `set detach-on-fork off`, for example:

```bash
gef➤  set target-async 1
gef➤  set pagination off 
gef➤  set non-stop on
gef➤  set detach-on-fork off
gef➤  catch ex
gef➤  catch exec 
gef➤  r
gef➤  c -a
gef➤  info threads
gef➤  thread xyz
...
```

Happy debugging.