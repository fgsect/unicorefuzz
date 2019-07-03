#!/bin/sh
qemu-system-x86_64 -drive file=../ARCH.qcow2,if=virtio \
	-enable-kvm \
	-net nic -net user,hostfwd=tcp::8022-:22 \
	-m 4096 \
	-smp 4 \
	-s \
	-nographic \
	-kernel linux/arch/x86_64/boot/bzImage \
	-initrd linux/arch/x86_64/boot/initramfs.img \
	-append "root=/dev/vda2 debug console=ttyS0 nokaslr" \
	-monitor telnet:127.0.0.1:1235,server,nowait

# -s makes qemu listen on 1234
