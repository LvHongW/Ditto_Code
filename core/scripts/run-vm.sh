#!/bin/bash

set -ex

if [ $# -lt 3 ]; then
  echo "Usage ./run-vm.sh image_path linux_path ssh_port [arch]"
  exit 1
fi

IMAGE=$1
LINUX=$2
PORT=$3
ARCH=${4:-amd64}

if [ "$ARCH" = "arm64" ]; then
  qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a57 \
    -m 2G \
    -smp 2 \
    -netdev user,id=net0,host=10.0.2.10,hostfwd=tcp::$PORT-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial stdio -no-reboot \
    -drive file=$IMAGE,format=raw \
    -kernel $LINUX/arch/arm64/boot/Image \
    -append "console=ttyAMA0 net.ifnames=0 root=/dev/vda earlycon=pl011,mmio32,0x09000000"
else
  qemu-system-x86_64 \
    -m 2G \
    -smp 2 \
    -netdev user,id=net0,host=10.0.2.10,hostfwd=tcp::$PORT-:22 \
    -device e1000,netdev=net0 \
    -enable-kvm -cpu host \
    -display none -serial stdio -no-reboot \
    -hda $IMAGE \
    -kernel $LINUX/arch/x86_64/boot/bzImage \
    -append "console=ttyS0 net.ifnames=0 root=/dev/sda printk.synchronous=1"
fi
