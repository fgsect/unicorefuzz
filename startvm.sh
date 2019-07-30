#!/bin/sh
qemu-system-x86_64 -kernel linux/arch/x86_64/boot/vmlinux


	echo -drive format=raw,file=./debootstrap/stretch.img \
	-enable-kvm \
	-net nic -net user,hostfwd=tcp::8022-:22 \
	-m 4096 \
	-smp 4 \
	-s \
	-nographic \
	-kernel linux/arch/x86_64/boot/vmlinux \
	-append "root=/dev/vda2 debug console=ttyS0 nokaslr" \
	-monitor telnet:127.0.0.1:1235,server,nowait \
	-initrd /boot/initramfs-linux.img 

# -s makes qemu listen on 1234
