#!/bin/bash
AFL_PATH=$(ucf afl-path) || exit 1
export PATH=$AFL_PATH:$PATH

# Make sure we instrument comparisons
export AFL_COMPCOV_LEVEL=2

ucf await || exit 1

if [ -z "$1" ]; then
	echo "[*] Unicorefuzz running AFL master node. Supply an id to spawn additional workers."
	afl-fuzz -U -m none -i afl_inputs -o afl_outputs -t 4000+ -M master -- python3 ucf emu @@ || exit 1
else 
	echo "[*] Unicorefuzz running AFL worker with id $1"
	afl-fuzz -U -m none -i afl_inputs -o afl_outputs -t 4000+ -S fuzzer$1 -- python3 ucf emu @@ || exit 1
fi
