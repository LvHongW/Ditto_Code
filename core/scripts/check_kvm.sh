#!/bin/bash
set -e

function add_user_to_kvm_group() {
    echo "$(whoami) is not in kvm group"
    echo "Adding $(whoami) to kvm group"
    set -x
    sudo usermod -a -G kvm $(whoami)
    set +x
    echo "Re-login and run ditto again"
    exit 1
}

if [ ! -e "/dev/kvm" ]; then
  echo "[WARNING] This machine does not support KVM. ARM64/TCG mode will work without KVM."
  echo "[WARNING] x86 fuzzing with KVM will not be available."
  exit 0
fi

groups $(whoami) | grep kvm || add_user_to_kvm_group
echo "KVM is ready to go"
exit 0
