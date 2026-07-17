# RISCV64 架构支持实现计划

## Context

Ditto 目前支持 amd64 和 arm64。需要新增 riscv64 架构支持，不影响现有架构功能。与 arm64 的关键区别：**不从源码编译内核，而是从 syzbot storage 直接下载预构建的内核镜像和磁盘镜像**，从而避免复杂的 RISC-V 交叉编译。

## 新增架构 vs 现有架构关键差异总览

| 维度 | amd64 | arm64 | **riscv64** |
|------|-------|-------|-------------|
| 内核获取 | 本地编译 | 本地交叉编译 | **从 syzbot 下载** |
| QEMU | qemu-system-x86_64 | qemu-system-aarch64 | **qemu-system-riscv64** |
| KVM | 支持 | 支持（当前环境无） | **支持（开关可切换）** |
| 内核仓库 | torvalds/linux.git | torvalds/linux.git | **riscv/linux.git** |
| 内核路径 | arch/x86_64/boot/bzImage | arch/arm64/boot/Image | **arch/riscv/boot/Image** |
| 磁盘镜像 | stretch.img | arm64-trixie.img | **从 syzbot 下载** |
| Syzkaller | 本地编译+Ditto补丁 | 本地交叉编译+Ditto补丁 | **本地交叉编译+Ditto补丁** |
| Crash格式 | Call Trace: + RIP | Call trace: 无RIP | **Call Trace: 无RIP** |
| 入口函数 | entry_SYSCALL | el0_sync/el0_svc | **__riscv_sys_*** |

---

## Phase 1: arch_config.py — 架构配置

**文件**: `core/interface/arch_config.py`

在 `ARCH_CONFIG` 字典中添加 `riscv64` 条目：

```python
"riscv64": {
    # syzkaller
    "syz_target": "linux/riscv64",
    "syz_targetarch": "riscv64",
    "syz_targetvmarch": "amd64",

    # QEMU
    "qemu_binary": "qemu-system-riscv64",
    "qemu_machine": "virt",
    "qemu_cpu": "rv64",
    "qemu_enable_kvm": False,  # 默认TCG，可切换
    "qemu_nic": "virtio-net-pci",
    "qemu_root_dev": "/dev/vda",
    "qemu_console": "ttyS0",
    "qemu_use_drive": True,
    "qemu_args": "-machine virt -cpu rv64",
    "max_qemu": 1,  # TCG模式限制

    # kernel (从syzbot下载，路径指向下载文件)
    "kernel_path": "arch/riscv/boot/Image",
    "kernel_make_arch": None,  # 不编译，仅记录
    "kernel_cross_compile": "riscv64-linux-gnu-",
    "kernel_cross_compile_gcc": "riscv64-linux-gnu-gcc",
    "kernel_boot_params": [
        "kasan_multi_shot=1", "earlyprintk=serial", "oops=panic",
        "panic=1", "ftrace_dump_on_oops=orig_cpu",
        "net.ifnames=0", "biosdevname=0",
        "earlycon=sbi",
        "rcupdate.rcu_cpu_stall_suppress=1",
    ],
    "kernel_config_enable": [],  # 不编译内核，配置项仅作参考
    "kernel_config_disable": [],

    # image (从syzbot下载)
    "image_filename": "riscv64-disk.raw",
    "image_key_filename": "riscv64-disk.raw.key",

    # VM启动检测
    "startup_regex": r'Debian GNU/Linux.*(?:riscv64|syzkaller ttyS)|syzkaller login:',

    # crash / call trace
    "call_trace_ends": ["__riscv_sys_", "ret_from_fork", "bpf_prog_", "Allocated by"],
    "crash_rip_prefix": None,  # RISC-V无RIP寄存器

    # GDB/pwndbg
    "need_gdb": False,

    # timeouts (TCG较慢)
    "qemu_boot_timeout": 480,
    "ssh_ready_retries": 180,
    "ssh_connect_timeout": 30,
    "ssh_subprocess_timeout": 120,
}
```

同时更新 `detect_arch()` 函数，新增 riscv64 检测：
```python
if re.search(r'\briscv64\b|\briscv\b', manager):
    return "riscv64"
```

并在 `__main__.py` 的 `--arch` choices 中添加 `'riscv64'`。

---

## Phase 2: syzbotCrawler.py — 爬取器扩展

**文件**: `core/modules/syzbotCrawler.py`

### 2.1 提取 syzbot storage 资产 URL

在 `request_detail()` 中扩展获取的字段，新增从 Assets 列提取存储 URL：
- `disk_image_url`: 磁盘镜像（non_bootable_disk-*.raw.xz）
- `vmlinux_url`: vmlinux 文件
- `kernel_image_url`: Image 文件

在 case 数据存储时新增这些字段（向后兼容，现有代码会忽略不需要的字段）。

### 2.2 创建 crawl_riscv_cases.py

参考 `core/modules/crawl_arm_cases.py`，修改：
- `--arch-regex` 默认值改为 `r"riscv64|\\briscv\\b"`
- `--output` 默认值改为 `work/Syzbot_RISCV_cases_get-basic-info.json`

---

## Phase 3: deploy.sh — 部署流程

**文件**: `core/scripts/deploy.sh`

新增 riscv64 分支（在 arm64 分支之后）：

### 3.1 内核获取（下载替代编译）
```bash
if [ "$ARCH" = "riscv64" ]; then
    # 从syzbot storage下载预构建内核
    # 需要从case数据中获取asset URL
    # 下载 Image、vmlinux 到 kernel_path
    KERNEL_IMAGE_URL="$ASSET_KERNEL_IMAGE_URL"  # 从Python传入
    DISK_IMAGE_URL="$ASSET_DISK_IMAGE_URL"
    
    # 下载和解压
    wget -q "$KERNEL_IMAGE_URL" -O Image.xz
    xz -d Image.xz
    cp Image arch/riscv/boot/Image
    
    wget -q "$DISK_IMAGE_URL" -O disk.raw.xz
    xz -d disk.raw.xz
    # 磁盘镜像放到img目录
fi
```

### 3.2 磁盘镜像处理
riscv64 无需本地构建镜像，直接从 syzbot 下载：
```bash
if [ "$ARCH" = "riscv64" ]; then
    # 建立与下载镜像的软链接
    ln -sf "$DISK_IMAGE_PATH" "$CASE_PATH/img/riscv64-disk.raw"
fi
```

### 3.3 Syzkaller 交叉编译
参考 arm64 模式，添加 riscv64 编译参数：
```bash
# riscv64时需要交叉编译器
COMPILER_RISCV64="tools/riscv64-gcc/bin/riscv64-linux-gnu-gcc"
# Syzkaller编译: TARGETARCH=riscv64 TARGETVMARCH=amd64
```

---

## Phase 4: worker.py — Crash 解析

**文件**: `core/modules/deploy/worker.py`

### 4.1 新增 riscv64 crash 模式

RISC-V 的 KASAN crash 格式与 x86 一致（"Call Trace:" 大写T），但无 RIP 前缀：

```python
# RISC-V crash patterns (与x86相同的KASAN模式，但call_trace_ends不同)
# kasan_pattern 复用x86的模式 (Call Trace:\n...)
# 警告模式需要调整（RISCV无RIP/RSP寄存器）
riscv64_warn = "([\s\S]*?)Call Trace:\n([\s\S]*?)(Kernel Offset|Modules linked in)"
```

### 4.2 更新 get_calls() 分发

```python
def get_calls(self, report, arch='amd64'):
    if arch == 'arm64':
        return self._get_calls_arm64(report)
    if arch == 'riscv64':
        return self._get_calls_riscv64(report)
    return self._get_calls_x86(report)
```

`_get_calls_riscv64()` 方法：复用 x86 的 KASAN 模式（两者都用 "Call Trace:"），但 WARNING/BUG 模式需要 riscv64 专用正则（因为无 RIP/RSP 寄存器）。

---

## Phase 5: deploy.py — 配置生成

**文件**: `core/modules/deploy/deploy.py`

### 5.1 架构检测和配置

在 `deploy()` 中：
- `detect_arch()` 已支持 riscv64（Phase 1）
- 磁盘镜像选取：riscv64 从 syzbot 下载的镜像文件名

### 5.2 内核下载逻辑

新增方法 `__download_kernel_assets()`：
- 从 case 数据中读取 asset URLs
- 下载 Image + vmlinux + disk image
- 解压 xz 文件
- 放置到正确路径

### 5.3 系统调用过滤

riscv64 也需要过滤 `$auto` syscalls（x86 特定）：
```python
if self.arch in ("arm64", "riscv64"):
    new_syscalls = [s for s in new_syscalls if "$auto" not in s]
```

---

## Phase 6: crash.py + utilities.py — 崩溃检测重构

### 6.1 crash.py

**文件**: `core/modules/crash.py`

- `CrashChecker.__init__`: `arch` 参数支持 `'riscv64'`
- `trigger_ori_crash`: 传递 `arch` 给 VM
- `upload_exp`: 传递 arch 参数给上传脚本
- `make_commands`: 已在 arm64 改造时通用化，直接使用 `arch_config`

### 6.2 utilities.py

**文件**: `core/interface/utilities.py`

- `extrace_call_trace()`: `call_trace_ends` 从 arch_config 获取，riscv64 使用 `__riscv_sys_` 及其变体

---

## Phase 7: 其他 Shell 脚本

### deploy_linux.sh
对于 riscv64，跳过内核编译步骤（因为从 syzbot 下载），仅处理 syzkaller 编译。

### upload-exp.sh
- 添加 `$ARCH` 参数支持（当前已支持 arm64）
- riscv64 SSH key 使用从 syzbot 下载的 key 文件
- syz-executor 交叉编译：`TARGETARCH=riscv64 TARGETVMARCH=amd64`

### requirements.sh
```bash
# 安装 riscv64 QEMU 和交叉编译器
apt-get install -y qemu-system-riscv64 gcc-riscv64-linux-gnu g++-riscv64-linux-gnu

# 创建交叉编译器符号链接
mkdir -p tools/riscv64-gcc/bin
ln -sf $(which riscv64-linux-gnu-gcc) tools/riscv64-gcc/bin/riscv64-linux-gnu-gcc
ln -sf $(which riscv64-linux-gnu-g++) tools/riscv64-gcc/bin/riscv64-linux-gnu-g++
```

### check_kvm.sh
已有 KVM 不可用时的警告处理，无需修改。

### run-vm.sh
添加 riscv64 的 QEMU 命令行分支：
```bash
if [ "$ARCH" = "riscv64" ]; then
    qemu-system-riscv64 -machine virt -cpu rv64 \
        -m 2G -smp 2 \
        -kernel arch/riscv/boot/Image \
        -drive file=$IMAGE,format=raw \
        -append "...console=ttyS0 root=/dev/vda ..."
fi
```

### syz-compile.sh
添加 riscv64 的 TARGETARCH 处理。

### run-script.sh
添加 riscv64 的 SSH key 选择。

---

## Phase 8: VM instance.py

**文件**: `core/interface/vm/instance.py`

无需额外修改，已通过 `arch_config` 动态获取 QEMU 参数。确认 riscv64 配置足以生成正确的 QEMU 命令行。

---

## Phase 9: 验证

1. **回归测试**: 用现有 amd64 test_case.json 运行，确认无回归
2. **爬取验证**: 运行 `crawl_riscv_cases.py` 确认能爬取到 riscv64 案例
3. **QEMU 启动**: 手动下载 Image + disk，用 run-vm.sh riscv64 启动，验证 SSH 连接
4. **Crash 解析**: 用 syzbot 上的 riscv64 KASAN crash report 测试 `get_cg()` 输出
5. **端到端**: 完整的 riscv64 case Download → Build Syzkaller → Reproduce PoC → Fuzz

---

## 不修改的文件

| 文件 | 原因 |
|------|------|
| `core/patches/syzkaller-9b1f3e6-ditto.patch` | 通过 config JSON target 字段覆盖架构 |
| `core/interface/vm/kernel.py` | angr/capstone 仅 x86 调试用 |
| `core/interface/vm/gdb.py` | GDB 调试仅 amd64 使用 |
| `core/interface/vm/monitor.py` | 同上 |
| `core/interface/vm/state.py` | 同上 |
| `core/criticalsys/Get_Critical_Syscall_Seq.py` | 架构无关 |
| `core/interface/crash_log2json.py` | 架构无关（文本解析） |
