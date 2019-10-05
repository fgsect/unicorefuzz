#!/bin/bash
AFL_PATH=$(ucf afl-path) || exit 1
UCF_SCRIPT=$(realpath "$AFL_PATH/../ucf") || exit 1
export PATH=$AFL_PATH:$PATH

# Make sure we instrument comparisons
export AFL_COMPCOV_LEVEL=2

pwd

ucf await || exit 1

if [ -z "$1" ]; then
	echo "[*] Unicorefuzz running AFL master node. Supply an id to spawn additional workers."
	afl-fuzz -U -m none -i afl_inputs -o afl_outputs -t 4000+ -M master -- python3 "$UCF_SCRIPT" emu @@ || exit 1
else 
	echo "[*] Unicorefuzz running AFL worker with id $1"
	afl-fuzz -U -m none -i afl_inputs -o afl_outputs -t 4000+ -S fuzzer$1 -- python3 "$UCF_SCRIPT" emu @@ || exit 1
fi
