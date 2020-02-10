#!/bin/bash

echo "================================================="
echo "Unicorefuzz Installation script"
echo "================================================="
echo
echo "[*] Performing basic sanity checks..."

if [ ! "$(uname -s)" = "Linux" ]; then
  echo "[-] Info: Only tested on Linux... Continue at your own risk."
fi

if [ ! -f "requirements.txt" -o ! -f "setup.sh" ]; then
  echo "[-] Error: key files not found - wrong working directory?"
  exit 1
fi

# python2 is necessary to build QEMU, everything else is python3
for i in wget python2 python3 automake autoconf sha384sum cmake; do
  T=$(which "$i" 2>/dev/null)
  if [ "$T" = "" ]; then
    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i'."
    exit 1
  fi
done

python3 -m pip --version 1>/dev/null
if [ ! $? -eq 0 ]; then
  echo "[-] Error: Could not find pip3. Run 'sudo apt-get install python3-pip'"
  exit 1
fi
 
if echo "$CC" | grep -qF /afl-; then
  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  exit 1
fi

echo "[+] Installing python requirements" 
if [ -z "$VIRTUAL_ENV" ]; then
  echo "[*] Info: Installing unicorefuzz to system python using --user"
  python3 -m pip install --user -r requirements.txt || exit 1
else
  echo "[*] Info: Installing python requirements to virtualenv: $VIRTUAL_ENV"
  pip install -r requirements.txt || exit 1
fi
echo "[*] All python deps have been installed."

echo "[+] Cloning Submodules"
git submodule init
git submodule update || exit 1

echo "[+] Running make for AFL++"
cd AFLplusplus || exit 1
make || exit 1

echo "[+] Building unicorn_mode"
cd unicorn_mode || exit 1
chmod +x ./build_unicorn_support.sh || exit 1
./build_unicorn_support.sh || exit 1
if [[ "$VIRTUAL_ENV" == "" ]]
then
  echo "[+] Doublechecking we have AFL Unicorn in py3"
  cd unicornafl/bindings/python || exit 1
  python3 setup.py install --user || exit 1
  cd ../../../ || exit 1
fi
cd ../../
echo "[*] Unicorn mode built." 

echo "[+] PIP installing uDdbg Deps"
cd uDdbg || exit 1

# got some issues with uddbg requirements.txt - let's get the latest versions manually. fingers crossed.
if [[ "$VIRTUAL_ENV" != "" ]]
then
  echo "[+] installing dependencies in virtualenv"
  pip install . || exit 1
else
  echo "[+] installing dependencies as user"
  python3 -m pip install --user . || exit 1
fi

cd .. || exit 1

echo "[*] Dependencies installed successfully."
echo ""
echo "[*] To use AFL++ outside of unicorefuzz,"
echo '    export PATH=$PATH'":$(pwd)/AFLplusplus"
echo "[+] To use 'ucf' from any folder:"
echo -e "\e[32m"'    export PATH=$PATH'":$(pwd)"
echo -e "\e[39m"
echo -e "\e[5m        .----------------------------------------."
echo -e "\e[5m        |--- Unicore setup complete. Enjoy :) ---|"
echo -e "\e[5m        '----------------------------------------'\e[25m"
