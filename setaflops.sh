#!/bin/sh
echo "[+] Setting all those afl performance and coredump modes"
cd "$(ucf afl-path)" || exit 1
echo "[*] Every day I'm sudoing..."
sudo ./afl-system-config
echo "[+] Done. Let's start to fuzz!"
