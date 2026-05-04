# Ditto ARM64 架构支持 —— 详细实现方案（优化版）

## 1. 背景与目标

Ditto 目前仅支持 x86/amd64/i386 架构。目标：增加 ARM64 fuzzing 能力，不影响现有 x86 功能。

运行环境：x86_64 主机 → QEMU TCG 模拟 ARM64（无 KVM）→ 最终打包到 x86 Docker。

---

## 2. 核心设计

### 2.1 集中式架构配置

新建 `core/interface/arch_config.py`，定义 `ARCH_CONFIG` 字典，将所有架构硬编码值集中管理：

```python
ARCH_CONFIG = {
    "amd64": { ... },   # 现有 x86_64 值，保证与当前硬编码完全一致
    "arm64": { ... },   # ARM64 对应值
    "386":  { ... },    # 继承 amd64，仅覆盖差异项
}
```

关键函数：
- `detect_arch(manager_field)` — 从 syzbot manager 字段检测架构
- `get_arch_config(arch)` — 返回对应架构配置字典

### 2.2 架构关键字段对照表

| 配置键 | amd64 | arm64 | 说明 |
|--------|-------|-------|------|
| `syz_target` | `linux/amd64` | `linux/arm64` | syzkaller config target 字段 |
| `syz_targetarch` | `amd64` | `arm64` | syz-execprog -arch 参数 |
| `syz_targetvmarch` | `amd64` | `amd64` | 主机架构，syz-execprog 运行在 amd64 |
| `qemu_binary` | `qemu-system-x86_64` | `qemu-system-aarch64` | QEMU 可执行文件 |
| `qemu_machine` | `None` | `virt` | -machine 参数，x86 不需要 |
| `qemu_cpu` | `host,migratable=off` | `cortex-a57` | -cpu 参数 |
| `qemu_enable_kvm` | `True` | `False` | ARM64 在 x86 主机无 KVM |
| `qemu_nic` | `e1000` | `virtio-net-pci` | 网卡型号，virt 不支持 e1000 |
| `qemu_root_dev` | `/dev/sda` | `/dev/vda` | ARM64 virt 用 virtio-blk |
| `qemu_console` | `ttyS0` | `ttyAMA0` | 串口控制台 |
| `qemu_use_drive` | `False` | `True` | arm64 用 -drive 而非 -hda |
| `kernel_path` | `arch/x86_64/boot/bzImage` | `arch/arm64/boot/Image` | 内核映像路径 |
| `kernel_make_arch` | `None` | `arm64` | make ARCH= 参数 |
| `kernel_cross_compile` | `None` | `aarch64-linux-gnu-` | make CROSS_COMPILE= 参数 |
| `kernel_cross_compile_gcc` | `None` | `aarch64-linux-gnu-gcc` | 交叉编译器路径 |
| `kernel_boot_params` | kvm-intel.*等23项 | earlycon等9项 | 内核启动参数 |
| `kernel_config_enable` | 含 CONFIG_KASAN_OUTLINE | 含 CONFIG_KASAN_GENERIC/INLINE | KASAN 配置 |
| `kernel_config_disable` | 含 CONFIG_X86_SMAP | 无 CONFIG_X86_SMAP | 禁用的内核选项 |
| `image_filename` | `stretch.img` | `arm64-trixie.img` | 磁盘镜像文件名 |
| `image_key_filename` | `stretch.img.key` | `arm64-trixie.img.key` | SSH 私钥文件名 |
| `startup_regex` | `ttyS\d+` | `ttyAMA\d+` | VM 启动检测正则 |
| `call_trace_ends` | `entry_SYSENTER, entry_SYSCALL, ret_from_fork` | `el0_sync, el1_sync, el0_svc, ret_from_fork` | 调用链终止标记 |
| `crash_rip_prefix` | `RIP: 0010:` | `None` | ARM64 无 RIP 寄存器 |
| `need_gdb` | `True` | `False` | ARM64 跳过 GDB/pwndbg |
| `qemu_boot_timeout` | `6` | `30` | TCG 启动慢，需更长超时 |

### 2.3 镜像文件名统一方案

**问题**：syzkaller 的 `create-image.sh -a arm64` 生成 `trixie.id_rsa` 作为 SSH key，但现有代码到处写 `stretch.img.key`。

**方案**：在 `requirements.sh` 中调用 `create-image.sh` 后，将生成的文件重命名为统一格式：

```bash
# create-image.sh -a arm64 生成 trixie.img 和 trixie.id_rsa
# 统一重命名为 arm64-trixie.img 和 arm64-trixie.img.key
mv trixie.img arm64-trixie.img
mv trixie.id_rsa arm64-trixie.img.key
chmod 400 arm64-trixie.img.key
```

这样 `arch_config.py` 中的 `image_key_filename` 直接对应实际文件名，所有代码统一从配置中读取。

### 2.4 编译器选择策略

**问题**：`utilities.py:set_compiler_version()` 返回 x86 编译器名如 `"gcc-7"`，解析为 `tools/gcc-7/bin/gcc`。ARM64 需要交叉编译器。

**方案**：
- ARM64 交叉编译器下载到 `tools/aarch64-gcc/` 目录
- `deploy.sh` 和 `deploy_linux.sh` 中：当 `ARCH=arm64` 时，`COMPILER` 指向 `tools/aarch64-gcc/bin/aarch64-linux-gnu-gcc`，而非 `tools/$COMPILER_VERSION/bin/gcc`
- 新增一个 `get_cross_compiler_path()` 辅助函数或在 `deploy.sh` 内部判断
- `make` 命令添加 `ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-` 参数

### 2.5 syzkaller 配置模板改造

**问题**：`deploy.py` 的 `syz_config_template` 使用 `.format()` 位置参数 `{0}`~`{18}`，其中：
- `{8}` 只替换 `"linux/amd64/"` 后的架构部分，ARM64 会变成错误的 `"linux/amd64/arm64"`
- 内核路径 `{1}/arch/x86/boot/bzImage` 硬编码
- 镜像/密钥路径硬编码

**方案**：改为命名参数 `.format_map()` 或在 `.format()` 调用时传入命名关键字参数：

```
"target": "{syz_target}",
"image": "{image_path}",
"sshkey": "{sshkey_path}",
"kernel": "{kernel_img_path}",
```

在 `__write_config()` 中：
```python
syz_config = syz_config_template.format(
    syzkaller_path=..., kernel_path=..., ...,
    syz_target=self.arch_config["syz_target"],
    image_path=os.path.join(self.image_path, self.arch_config["image_filename"]),
    sshkey_path=os.path.join(self.image_path, self.arch_config["image_key_filename"]),
    kernel_img_path=os.path.join(self.kernel_path, self.arch_config["kernel_path"]),
    ...
)
```

这样更安全、更可读，避免位置参数错位问题。

### 2.6 ARM64 crash 解析

**问题**：`worker.py` 的 crash 正则全部基于 x86 寄存器格式（`RIP: 0010:`、`RSP`、`R13`），ARM64 完全不同。

**方案**：在 `worker.py` 中新增 ARM64 专用正则模式：

```python
# ARM64 crash patterns
arm64_kasan_pattern = "Call trace:\n([\s\S]*?)\n(Allocated by task|===)"
arm64_warn = "([\s\S]*?)Call trace:\n([\s\S]*?)(Kernel Offset|Modules linked in)"
```

`get_calls()` 方法根据 arch 参数选择匹配模式：
- x86：沿用现有 `warn`/`kasan_pattern`/`kernel_bug` 等
- arm64：使用 `arm64_warn`/`arm64_kasan_pattern` 等

**关键点**：KASAN 标题行格式（`BUG: KASAN: use-after-free in ...`、`Write of size N at addr X`）跨架构一致，因此 `crash.py` 中的 KASAN 检测逻辑不需要修改。

---

## 3. 逐文件修改清单

### 3.1 新建文件

| 文件 | 说明 |
|------|------|
| `core/interface/arch_config.py` | 架构配置字典 + detect_arch() + get_arch_config() |

### 3.2 修改文件

#### `core/interface/vm/instance.py` — QEMU 启动参数

| 行号 | 当前代码 | 修改为 |
|------|----------|--------|
| 13 | `__init__(self, hash_tag, proj_path, log_name, ...)` | 添加 `arch='amd64'` 参数 |
| 30-37 | `self.def_opts = ["kasan_multi_shot=1", ...kvm-intel.*...]` | 初始化为空，在 `setup()` 中从 `arch_config` 填充 |
| 60 | `"root=/dev/sda", "console=ttyS0"` | `arch_config["qemu_root_dev"]`, `arch_config["qemu_console"]` |
| 67 | `"qemu-system-x86_64"` | `arch_config["qemu_binary"]` |
| 73 | `"-net", "nic,model=e1000", "-net", "user,..."` | `-netdev user,id=net0,...` + `-device {qemu_nic},netdev=net0` |
| 74 | `"-enable-kvm", "-cpu", "host,migratable=off"` | 根据 `qemu_enable_kvm` 和 `qemu_cpu` 条件生成；arm64 加 `-machine virt` |
| 75-76 | `"-hda", "stretch.img"`, `"-kernel", "arch/x86_64/boot/bzImage"` | arm64 用 `-drive file=...,format=raw` + `arch_config["kernel_path"]` |
| 155 | `r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'` | `self.arch_config["startup_regex"]` |

#### `core/interface/vm/__init__.py` — VM 类

| 行号 | 修改 |
|------|------|
| 5 | `arch='amd64'` 默认参数，传递给 VMInstance |
| 9 | 当 `need_gdb==False` 时跳过 VMState.__init__，设 gdb/mon/kernel=None |
| 11-17 | `kill()` 方法增加 None 检查 |

#### `core/modules/deploy/deploy.py` — 部署流程

| 行号 | 修改 |
|------|------|
| 18-56 | `syz_config_template` 改为命名参数（target, image, sshkey, kernel） |
| 85-87 | 架构检测改用 `detect_arch(case["manager"])`，存储 `self.arch_config` |
| 137 | `self.calltrace_path` 之后传递 arch_config 给后续流程 |
| 159-161 | `i386` 变量替换为 `self.arch` 传递 |
| 481-574 | `__write_config()` 两处 `.format()` 改为命名参数，从 `arch_config` 取值 |

#### `core/modules/deploy/worker.py` — Crash 解析

| 行号 | 修改 |
|------|------|
| 19-31 | 新增 ARM64 专用正则模式（arm64_kasan_pattern, arm64_warn 等） |
| 47 | `get_calls()` 新增 `arch='amd64'` 参数，根据 arch 选择匹配模式 |
| 78 | `get_cg()` 新增 `arch='amd64'` 参数，使用 `arch_config["call_trace_ends"]` |
| 82 | `call_trace_ends` 列表从 `arch_config` 获取 |
| 100 | `RIP: 0010:` 解析：当 `crash_rip_prefix` 为 None 时跳过 |

#### `core/modules/crash.py` — Crash 复现

| 行号 | 修改 |
|------|------|
| 16 | `startup_regx` 改为动态获取（或直接使用 arch_config） |
| 38 | `CrashChecker.__init__` 新增 `arch='amd64'` 参数 |
| 378 | `VM(...)` 调用传入 `arch=self.arch` |
| 480,523,534,542 | `stretch.img.key` → `os.path.join(image_path, arch_config["image_key_filename"])` |
| 558 | `normal_pm = {"arch":"amd64"}` → 从 `arch_config` 获取 |
| 573-574 | i386 arch 覆盖通用化为 arch 参数 |

#### `core/interface/utilities.py` — 工具函数

| 行号 | 修改 |
|------|------|
| 124 | `extrace_call_trace()` 新增 `arch='amd64'` 参数 |
| 129 | `call_trace_end` 列表从 `arch_config["call_trace_ends"]` 获取 |

#### `core/scripts/deploy.sh` — 编译部署

| 行号 | 修改 |
|------|------|
| 77-79 | ARM64 时 COMPILER 指向交叉编译器 |
| 130 | `TARGETVMARCH` 按 arch 设置（arm64→amd64，其余→$ARCH） |
| 145-149 | 镜像软链接根据 arch 使用不同文件名 |
| 170-194 | 内核编译配置按 arch 分支 |
| 207-208 | `make` 添加 `ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-`（arm64 时） |

#### `core/scripts/deploy_linux.sh` — 内核单独编译

| 修改 | 说明 |
|------|------|
| 新增 `$ARCH` 位置参数 | 当前接受 5 或 8 个参数，改为 6 或 9 个 |
| 更新参数计数检查 | `$# -ne 6 && $# -ne 9` |
| ARM64 时 COMPILER 指向交叉编译器 | 同 deploy.sh |
| 第 94-118 行 | 内核配置按 arch 分支 |
| 第 131-132 行 | `make` 添加 CROSS_COMPILE 支持 |

#### `core/scripts/upload-exp.sh` — 上传执行器

| 行号 | 修改 |
|------|------|
| 新增 `$ARCH` 位置参数（第11个参数） | 替代 i386 布尔判断 |
| 66 | `TARGETVMARCH` 按 arch 设置 |
| 50, 101 | SSH key 文件名根据 arch 选择 |
| 67-69 | 二进制路径逻辑已正确（syz-execprog=amd64，executor=目标arch） |

#### `core/scripts/requirements.sh` — 环境准备

| 行号 | 修改 |
|------|------|
| 4 | apt 添加 `qemu-system-arm` |
| 新增块 | ARM64 镜像构建：调用 `create-image.sh -a arm64`，重命名为统一格式 |
| 新增块 | ARM64 交叉编译器下载到 `tools/aarch64-gcc/` |
| 新增块 | ARM64 pwndbg 不安装（跳过） |

#### `core/scripts/run-vm.sh` — 手动 VM 启动

| 修改 | 说明 |
|------|------|
| 新增第4个参数 `ARCH` | 默认 amd64 |
| 根据 ARCH 分支 | arm64 使用 qemu-system-aarch64、-machine virt、virtio-net-pci 等 |

#### `core/scripts/check_kvm.sh` — KVM 检查

| 行号 | 修改 |
|------|------|
| 14-17 | `/dev/kvm` 不存在时改为警告而非退出 |

#### `core/scripts/syz-compile.sh` — Syzkaller 重编译

| 行号 | 修改 |
|------|------|
| 21 | `TARGETVMARCH` 按 arch 设置 |

#### `core/scripts/run-script.sh` — 运行脚本生成

| 行号 | 修改 |
|------|------|
| 新增参数传递 | SSH key 文件名根据 arch 选择 |

#### `core/__main__.py` — 入口

| 修改 | 说明 |
|------|------|
| 155-162 | `check_kvm()` 返回非零时打印警告但不退出 |

#### `Dockerfile` — Docker 构建

| 修改 | 说明 |
|------|------|
| apt 安装行 | 添加 `qemu-system-arm gcc-aarch64-linux-gnu g++-aarch64-linux-gnu` |

### 3.3 不修改的文件

| 文件 | 原因 |
|------|------|
| `core/patches/syzkaller-9b1f3e6-ditto.patch` | 默认 arch=amd64 不影响，Ditto 通过 config JSON 的 target 字段覆盖 |
| `core/interface/vm/kernel.py` | angr/capstone 仅 x86 GDB 调试用，arm64 跳过 VMState 即可 |
| `core/interface/vm/gdb.py` | 同上 |
| `core/interface/vm/monitor.py` | 同上 |
| `core/interface/vm/state.py` | 同上 |
| `core/criticalsys/Get_Critical_Syscall_Seq.py` | 与架构无关 |
| `core/interface/crash_log2json.py` | 仅解析日志文本，与架构无关 |

---

## 4. 参数传递链

`arch` 值从 case 检测开始，贯穿整个调用链：

```
case["manager"]
  → detect_arch() → self.arch + self.arch_config
    → deploy.sh ($ARCH, 已有第10个参数)
    → worker.get_cg(report, arch=self.arch)
    → crash.CrashChecker(..., arch=self.arch)
      → VM(..., arch=self.arch)
      → upload-exp.sh (新增arch参数)
      → deploy_linux.sh (新增arch参数)
      → run-script.sh (新增arch参数)
    → utilities.extrace_call_trace(report, arch=...)
```

---

## 5. 风险与对策

| 风险 | 严重度 | 对策 |
|------|--------|------|
| ARM64 TCG 极慢（10-100x 慢于 KVM） | 高 | qemu_timeout 从 6 增到 30；fuzzing 超时建议 24h+；文档中明确说明 |
| 旧 syzkaller commit 不支持 TARGETARCH=arm64 | 中 | 极少数旧 bug 可能失败，deploy.sh 中已有 exitcode 重试机制 |
| ARM64 镜像构建依赖 debootstrap/qemu-user | 中 | requirements.sh 中安装 qemu-user-static，确保 debootstrap 能在 x86 上构建 arm64 rootfs |
| .format() 命名参数改动量大 | 中 | 一次性改好，避免后续维护问题 |
| ARM64 crash 报告格式可能有变体 | 低 | 先覆盖主流格式，后续根据实际报告迭代 |
| `create-image.sh -a arm64` 构建耗时长 | 低 | 首次构建后缓存在 tools/img/，后续不重复构建 |

---

## 6. 实现顺序

| 阶段 | 内容 | 依赖 |
|------|------|------|
| 1 | 创建 `arch_config.py` | 无 |
| 2 | 修改 `instance.py` + `vm/__init__.py`（QEMU 启动） | 阶段1 |
| 3 | 修改 `deploy.py`（架构检测 + 配置模板） | 阶段1 |
| 4 | 修改 `worker.py` + `crash.py` + `utilities.py`（crash 解析） | 阶段1 |
| 5 | 修改 Shell 脚本（deploy.sh, deploy_linux.sh, upload-exp.sh 等） | 阶段3 |
| 6 | 修改 `requirements.sh`（ARM64 镜像+工具链） | 无 |
| 7 | 修改 `__main__.py` + `Dockerfile` | 阶段5 |
| 8 | 验证回归测试（x86 案例） | 全部完成后 |

---

## 7. 验证方法

1. **回归测试**：使用 `work/test_case.json`（x86 案例）运行，确保行为与修改前完全一致
2. **ARM64 VM 启动**：手动 `run-vm.sh arm64` 验证 QEMU 启动、SSH 连接
3. **ARM64 内核编译**：`deploy.sh` 传入 `ARCH=arm64` 验证 `arch/arm64/boot/Image` 生成
4. **ARM64 crash 解析**：用 ARM64 crash report 测试 `get_cg()` 输出
5. **端到端**：ARM64 syzbot case 完整 fuzzing 流程
