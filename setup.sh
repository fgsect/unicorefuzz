#!/bin/bash
AFLPP_VERSION=2.53c
UDDBG_VERSION=7881cf8207a94f6fa88c3d07b9c629037a2a850e 

echo "================================================="
echo "Unicorefuzz Installation script"
echo "================================================="
echo
echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then
  echo "[-] Info: Only tested on Linux... Continue at your own risk."
fi

if [ ! -f "startvm.sh" -o ! -f "startafl.sh" ]; then
  echo "[-] Error: key files not found - wrong working directory?"
  exit 1
fi

# python2 is necessary to build QEMU, everything else is python3
for i in wget python2 python3 automake autoconf sha384sum cmake; do
  T=`which "$i" 2>/dev/null`
  if [ "$T" = "" ]; then
    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i'."
    exit 1
  fi
done

T=`which pip3 2>/dev/null`
if [ "$T" = "" ]; then
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
  pip3 install --user -r requirements.txt || exit 1
  print "[*] Uninstalling the 'normal' unicorn first, if installed."
  pip3 uninstall -y unicorn
  pip3 uninstall -y unicorn
else
  echo "[*] Info: Installing python unicorn to virtualenv: $VIRTUAL_ENV"
  pip install -r requirements.txt || exit 1
  print "[*] Uninstalling the 'normal' unicorn first, if installed."
  pip uninstall -y unicorn
  pip uninstall -y unicorn
fi
echo "[*] All python deps have been installed."

echo "[+] Cloning AFL++"
git clone https://github.com/vanhauser-thc/AFLplusplus.git
cd AFLplusplus || exit 1
git checkout $AFLPP_VERSION || exit 1

echo "[+] Running make for AFL"
make || exit 1

echo "[+] Building unicorn_mode"
cd unicorn_mode || exit 1
chmod +x ./build_unicorn_support.sh || exit 1
./build_unicorn_support.sh || exit 1
echo "[*] Unicorn mode built." 

echo "[+] Cloning uddbg"
git clone https://github.com/igio90/uddbg.git 
cd uddbg || exit 1
git checkout 7881cf8207a94f6fa88c3d07b9c629037a2a850e || exit 1

# got some issues with uddbg requirements.txt - let's get the latest versions manually. fingers crossed.
if [[ "$virtual_env" != "" ]]
then
  echo "[+] installing dependencies in virtualenv"
  pip install prompt-toolkit inquirer termcolor capstone keystone hexdump keystone_engine tabulate
else
  echo "[+] installing dependencies as user"
  pip install --user prompt-toolkit inquirer termcolor capstone keystone hexdump keystone_engine tabulate
fi
echo "[+] done. harness.py -d will now work."
echo "[*] To use AFL outside of unicorefuzz,"
echo '    export PATH=$PATH' ":$(pwd)/AFLplusplus"

echo "[+] Unicore setup complete. Enjoy :)."
