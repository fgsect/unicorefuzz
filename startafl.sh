#!/bin/bash
if [ -z "$1" ]; then
	echo "[*] Unicorefuzz running AFL master node. Supply an id to spawn additional workers."
	afl-fuzz -U -m none -i afl_inputs -o afl_outputs -t 60000+ -M master -- python harness.py @@ || exit 1
else 
	echo "[*] Unicorefuzz running AFL worker with id $1"
	afl-fuzz -U -m none -i afl_inputs -o afl_outputs -t 60000+ -S fuzzer$1 -- python harness.py @@ || exit 1
fi
