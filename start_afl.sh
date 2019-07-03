#!/bin/sh
afl-fuzz -U -m none -i afl_inputs -o afl_outputs -t 30000 -- python harness.py @@

