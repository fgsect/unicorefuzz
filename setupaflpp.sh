#!/bin/sh

echo "[+] cloning AFL++"
git clone https://github.com/vanhauser-thc/AFLplusplus.git
cd AFLplusplus || exit 1
git checkout 2.53c || exit 1

echo "[+] Running make for AFL"
make || exit 1

echo "[+] Building unicorn_mode"
cd unicorn_mode || exit 1
./build_unicorn_support.sh || exit 1

echo "[*] To use AFL outside of unicorefuzz,"
echo '    export PATH=$PATH' ":$(pwd)/AFLplusplus"
echo "[+] Done."
