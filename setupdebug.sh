#!/bin/sh

echo "[+] cloning uDdbg"
git clone https://github.com/iGio90/uDdbg.git 
cd uDdbg || exit 1
git checkout 7881cf8207a94f6fa88c3d07b9c629037a2a850e || exit 1

echo "[+] Installing dependencies"
#sed -i.bak '/unicorn/d' ./requirements.txt || exit 1 # we really don't want to overwrite the afl unicorn lib!
#pip install --user -r requirements.txt || exit 1
# Got some issues with the requirements anyway. let's get the latest versions manually. Fingers crossed.
pip install --user prompt-toolkit inquirer termcolor capstone keystone hexdump keystone_engine tabulate





echo "[+] Done. Harness.py -d will now use uDdbg. Have a nice day."
