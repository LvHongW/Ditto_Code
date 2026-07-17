import re
import logging

logger = logging.getLogger(__name__)

ARCH_CONFIG = {
    "amd64": {
        # syzkaller
        "syz_target": "linux/amd64",
        "syz_targetarch": "amd64",
        "syz_targetvmarch": "amd64",

        # QEMU
        "qemu_binary": "qemu-system-x86_64",
        "qemu_machine": None,
        "qemu_cpu": "host,migratable=off",
        "qemu_enable_kvm": True,
        "qemu_nic": "e1000",
        "qemu_root_dev": "/dev/sda",
        "qemu_console": "ttyS0",
        "qemu_use_drive": False,
        "max_qemu": 4,

        # kernel
        "kernel_path": "arch/x86_64/boot/bzImage",
        "kernel_make_arch": None,
        "kernel_cross_compile": None,
        "kernel_cross_compile_gcc": None,
        "kernel_boot_params": [
            "kasan_multi_shot=1", "earlyprintk=serial", "oops=panic",
            "nmi_watchdog=panic", "panic=1", "ftrace_dump_on_oops=orig_cpu",
            "rodata=n", "vsyscall=native", "net.ifnames=0",
            "biosdevname=0", "kvm-intel.nested=1",
            "kvm-intel.unrestricted_guest=1", "kvm-intel.vmm_exclusive=1",
            "kvm-intel.fasteoi=1", "kvm-intel.ept=1", "kvm-intel.flexpriority=1",
            "kvm-intel.vpid=1", "kvm-intel.emulate_invalid_guest_state=1",
            "kvm-intel.eptad=1", "kvm-intel.enable_shadow_vmcs=1", "kvm-intel.pml=1",
            "kvm-intel.enable_apicv=1",
        ],
        "kernel_config_enable": [
            "CONFIG_HAVE_ARCH_KASAN",
            "CONFIG_KASAN",
            "CONFIG_KASAN_OUTLINE",
            "CONFIG_DEBUG_INFO",
            "CONFIG_FRAME_POINTER",
            "CONFIG_UNWINDER_FRAME_POINTER",
            "CONFIG_KCOV",
            "CONFIG_KCOV_INSTRUMENT_ALL",
            "CONFIG_KCOV_ENABLE_COMPARISONS",
            "CONFIG_DEBUG_FS",
            "CONFIG_DEBUG_KMEMLEAK",
            "CONFIG_DEBUG_INFO",
            "CONFIG_KALLSYMS",
            "CONFIG_KALLSYMS_ALL",
        ],
        "kernel_config_disable": [
            "CONFIG_BUG_ON_DATA_CORRUPTION",
            "CONFIG_KASAN_INLINE",
            "CONFIG_RANDOMIZE_BASE",
            "CONFIG_PANIC_ON_OOPS",
            "CONFIG_X86_SMAP",
            "CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC",
            "CONFIG_BOOTPARAM_HARDLOCKUP_PANIC",
            "CONFIG_BOOTPARAM_HUNG_TASK_PANIC",
        ],

        # image
        "image_filename": "stretch.img",
        "image_key_filename": "stretch.img.key",

        # VM boot detection
        "startup_regex": r'Debian GNU\/Linux \d+ syzkaller ttyS\d+',

        # crash / call trace
        "call_trace_ends": ["entry_SYSENTER", "entry_SYSCALL", "ret_from_fork", "bpf_prog_", "Allocated by"],
        "crash_rip_prefix": "RIP: 0010:",

        # GDB/pwndbg
        "need_gdb": True,

        # timeouts
        "qemu_boot_timeout": 6,
        "ssh_ready_retries": 60,  # 60 × 10s = 10 min
        "ssh_connect_timeout": 10,  # SSH -o ConnectTimeout
        "ssh_subprocess_timeout": 30,  # subprocess call() timeout
    },
    "arm64": {
        # syzkaller
        "syz_target": "linux/arm64",
        "syz_targetarch": "arm64",
        "syz_targetvmarch": "amd64",

        # QEMU
        "qemu_binary": "qemu-system-aarch64",
        "qemu_machine": "virt",
        "qemu_cpu": "cortex-a57",
        "qemu_enable_kvm": False,
        "qemu_nic": "virtio-net-pci",
        "qemu_root_dev": "/dev/vda",
        "qemu_console": "ttyAMA0",
        "qemu_use_drive": True,
        "qemu_args": "-machine virt -cpu cortex-a57",
        "max_qemu": 1,  # TCG emulation is slow, limit to 1 VM

        # kernel
        "kernel_path": "arch/arm64/boot/Image",
        "kernel_make_arch": "arm64",
        "kernel_cross_compile": "aarch64-linux-gnu-",
        "kernel_cross_compile_gcc": "aarch64-linux-gnu-gcc-12",
        "kernel_boot_params": [
            "kasan_multi_shot=1", "earlyprintk=serial", "oops=panic",
            "panic=1", "ftrace_dump_on_oops=orig_cpu",
            "net.ifnames=0", "biosdevname=0",
            "earlycon=pl011,mmio32,0x09000000",
            "rcupdate.rcu_cpu_stall_suppress=1",
            "systemd.default_timeout_start_sec=1800",
            "systemd.default_device_timeout_sec=30",
        ],
        "kernel_config_enable": [
            "CONFIG_HAVE_ARCH_KASAN",
            "CONFIG_KASAN",
            "CONFIG_KASAN_GENERIC",
            "CONFIG_KASAN_INLINE",
            "CONFIG_DEBUG_INFO",
            "CONFIG_FRAME_POINTER",
            "CONFIG_CC_HAS_SANCOV_TRACE_PC",
            "CONFIG_KCOV",
            "CONFIG_KCOV_INSTRUMENT_ALL",
            "CONFIG_KCOV_ENABLE_COMPARISONS",
            "CONFIG_DEBUG_FS",
            "CONFIG_DEBUG_KMEMLEAK",
            "CONFIG_KALLSYMS",
            "CONFIG_KALLSYMS_ALL",
            "CONFIG_VIRTIO_BLK",
            "CONFIG_VIRTIO_NET",
            "CONFIG_VIRTIO_PCI",
        ],
        "kernel_config_disable": [
            "CONFIG_BUG_ON_DATA_CORRUPTION",
            "CONFIG_RANDOMIZE_BASE",
            "CONFIG_PANIC_ON_OOPS",
        ],

        # image
        "image_filename": "arm64-trixie.img",
        "image_key_filename": "arm64-trixie.img.key",

        # VM boot detection
        "startup_regex": r'Debian GNU/Linux.*(?:trixie|syzkaller ttyAMA)|syzkaller login:',

        # crash / call trace
        "call_trace_ends": ["el0_sync", "el1_sync", "el0_svc", "ret_from_fork", "bpf_prog_", "Allocated by"],
        "crash_rip_prefix": None,

        # GDB/pwndbg
        "need_gdb": False,

        # timeouts (TCG is much slower: boot ~3min, SSH retries ~25min, compile ~2min, SCP 65MB ~15min)
        "qemu_boot_timeout": 480,  # 480 × 10s = 4800s = 80 min total QEMU timeout
        "ssh_ready_retries": 180,  # 180 × 10s = 30 min, udev-trigger coldplug is very slow under TCG
        "ssh_connect_timeout": 30,  # SSH -o ConnectTimeout (TCG handshake is slow)
        "ssh_subprocess_timeout": 120,  # subprocess call() timeout (TCG crypto is slow)
    },
    "riscv64": {
        # syzkaller
        "syz_target": "linux/riscv64",
        "syz_targetarch": "riscv64",
        "syz_targetvmarch": "amd64",

        # QEMU
        "qemu_binary": "qemu-system-riscv64",
        "qemu_machine": "virt",
        "qemu_cpu": "rv64",
        "qemu_enable_kvm": False,  # TCG only on x86 host; set True on riscv64 host
        "qemu_nic": "virtio-net-pci",
        "qemu_root_dev": "/dev/vda",
        "qemu_console": "ttyS0",
        "qemu_use_drive": True,
        "qemu_args": "-machine virt -cpu rv64",
        "max_qemu": 1,  # TCG emulation is slow, limit to 1 VM

        # kernel (pre-built images downloaded from syzbot storage)
        "kernel_path": "arch/riscv/boot/Image",
        "kernel_make_arch": "riscv",
        "kernel_cross_compile": "riscv64-linux-gnu-",
        "kernel_cross_compile_gcc": "riscv64-linux-gnu-gcc-12",
        "kernel_boot_params": [
            "kasan_multi_shot=1", "earlyprintk=serial", "oops=panic",
            "panic=1", "ftrace_dump_on_oops=orig_cpu",
            "net.ifnames=0", "biosdevname=0",
            "earlycon=sbi",
            "rcupdate.rcu_cpu_stall_suppress=1",
        ],
        "kernel_config_enable": [
            "CONFIG_HAVE_ARCH_KASAN",
            "CONFIG_KASAN",
            "CONFIG_KASAN_GENERIC",
            "CONFIG_KASAN_INLINE",
            "CONFIG_DEBUG_INFO",
            "CONFIG_FRAME_POINTER",
            "CONFIG_CC_HAS_SANCOV_TRACE_PC",
            "CONFIG_KCOV",
            "CONFIG_KCOV_INSTRUMENT_ALL",
            "CONFIG_KCOV_ENABLE_COMPARISONS",
            "CONFIG_DEBUG_FS",
            "CONFIG_DEBUG_KMEMLEAK",
            "CONFIG_KALLSYMS",
            "CONFIG_KALLSYMS_ALL",
            "CONFIG_VIRTIO_BLK",
            "CONFIG_VIRTIO_NET",
            "CONFIG_VIRTIO_PCI",
        ],
        "kernel_config_disable": [
            "CONFIG_BUG_ON_DATA_CORRUPTION",
            "CONFIG_RANDOMIZE_BASE",
            "CONFIG_PANIC_ON_OOPS",
        ],

        # image (downloaded from syzbot storage)
        "image_filename": "riscv64-disk.raw",
        "image_key_filename": "riscv64-disk.raw.key",

        # VM boot detection (syzbot riscv64 images may not show full Debian banner)
        "startup_regex": r'(?:Debian GNU/Linux.*(?:syzkaller ttyS)|syzkaller login:|Starting sshd)',

        # crash / call trace (same "Call Trace:" format as x86, no RIP prefix)
        "call_trace_ends": ["__riscv_sys_", "ret_from_fork", "bpf_prog_", "Allocated by"],
        "crash_rip_prefix": None,  # RISC-V has no RIP register

        # GDB/pwndbg (skip for riscv64)
        "need_gdb": False,

        # timeouts (TCG is slow similar to ARM64)
        "qemu_boot_timeout": 480,
        "ssh_ready_retries": 180,
        "ssh_connect_timeout": 30,
        "ssh_subprocess_timeout": 120,
        "poc_crash_wait_timeout": 120,  # max wait for crash after PoC execution
    },
    "386": None,  # will be copied from amd64 with overrides
}

# 386 inherits from amd64 with minimal overrides
_386_config = ARCH_CONFIG["amd64"].copy()
_386_override = {
    "syz_targetarch": "386",
    "syz_targetvmarch": "amd64",
}
_386_config.update(_386_override)
ARCH_CONFIG["386"] = _386_config


def detect_arch(manager_field):
    """Detect architecture from syzbot manager field.

    Examples:
        "ci-upstream-gce" -> "amd64"
        "ci-upstream-gce-386" -> "386"
        "ci-upstream-gce-arm64" -> "arm64"
        "ci-qemu2-riscv64" -> "riscv64"
    """
    if not manager_field:
        logger.debug("[arch_config] manager field is empty, defaulting to amd64")
        return "amd64"

    manager = manager_field.lower()

    # Check arm64 first (before 386, since "arm64" doesn't contain "386")
    if re.search(r'\barm64\b|\baarch64\b', manager):
        logger.debug("[arch_config] detected arm64 from manager: %s", manager_field)
        return "arm64"

    # Check riscv64 (before 386, similar reason)
    if re.search(r'\briscv64\b|\briscv\b', manager):
        logger.debug("[arch_config] detected riscv64 from manager: %s", manager_field)
        return "riscv64"

    # Check 386
    if re.search(r'\b386\b|\bi386\b', manager):
        logger.debug("[arch_config] detected 386 from manager: %s", manager_field)
        return "386"

    logger.debug("[arch_config] defaulting to amd64 from manager: %s", manager_field)
    return "amd64"


def get_arch_config(arch):
    """Return architecture configuration dictionary.

    Args:
        arch: Architecture string ("amd64", "arm64", "386", "riscv64")

    Returns:
        Dictionary with architecture-specific configuration values.

    Raises:
        ValueError: If architecture is not supported.
    """
    if arch not in ARCH_CONFIG:
        raise ValueError("Unsupported architecture: {}. Supported: {}".format(
            arch, list(ARCH_CONFIG.keys())))
    return ARCH_CONFIG[arch]
