# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Ditto is a Linux kernel dual-mutation fuzzing tool built on syzkaller. It crawls syzbot for known fixed bugs, then mutates their PoCs to discover latent bugs behind the known ones. The core technique is dual-mutation: **Activation** (mutating non-critical syscalls while preserving critical ones) and **Diffusion** (mutating the syscall sequence itself).

## Environment and build

```bash
# Activate virtualenv (required)
. venv/bin/activate

# Install system dependencies + compile syzkaller/kernel toolchain
python3 core --install-requirements
```

Python 3.6+ with the packages in `requirements.txt`. The `tools/` directory contains prebuilt compilers (gcc 7/8/9/10, clang 7/8/10/11), Go toolchain (`goroot/`, `gopath/`), and kernel images (`img/`, `linux-0/`). These are compiled by `core/scripts/deploy.sh` and `core/scripts/deploy_linux.sh`.

## Running Ditto

Entry point: `python3 core` (runs `core/__main__.py`). Key modes:

```bash
# Crawl and fuzz one known bug
python3 core -i 5fcfdc26bc84536f79bd ...
# Fuzz from cache (recommended after crawling)
python3 core --use-cache --cache-file test_case.json -KF --mutate-time 500 ...
# Reproduce original PoC without mutation
python3 core --use-cache --cache-file test_case.json -RP
# Crawl only titles (saves to work/cases.json)
python3 core --onlytitle
# Extract critical syscall sequences
python3 core/criticalsys/Get_Critical_Syscall_Seq.py
```

Critical CLI flags: `--mutate-type` (`Activation`|`Diffusion`), `--calltrace-sim` (0-1 threshold), `--repro-sim` (0-1 threshold), `--key-syscall` (JSON path), `--parallel-max -pm` (concurrency), `--debug`, `--arch` (`amd64`|`arm64`|`386`).

## Architecture

```
core/
  __main__.py        Entry point. Parses args, drives Crawler → Deployer pipeline.
  modules/
    syzbotCrawler.py Crawls syzbot webpage for bug cases (title, config, reproducers, commits).
    crash.py         CrashChecker: QEMU-based crash reproduction and comparison.
    deploy/
      deploy.py      Deployer: orchestrates the full case workflow (setup → compile → fuzz → analyze).
      case.py        Case base: state tracking via stamp files (BUILD_KERNEL, FINISH_FUZZING, etc.).
      worker.py      Workers: call-trace extraction, KASAN crash detection, crash comparison.
  interface/
    arch_config.py   Per-architecture config: QEMU args, kernel paths, cross-compilers, boot params.
    vm/              QEMU VM lifecycle management (instance.py: VM launch, SSH, monitoring).
    utilities.py     Regexes (KASAN patterns, call traces), Levenshtein distance, compiler selection.
    crash_log2json.py Post-hoc fuzzing log parser.
  criticalsys/
    Get_Critical_Syscall_Seq.py  TF-IDF-based critical syscall extraction from syzbot cases.
    key_syscalls_keynum-20_ngram-2-4-tfidf.json  Precomputed critical syscalls by bug type.
  scripts/           Shell scripts for: kernel build, syzkaller compile, QEMU launch, SCP upload.
  patches/           syzkaller-9b1f3e6-ditto.patch — Ditto's custom modifications to syzkaller.
```

## Work flow

1. **Crawler** reads syzbot for fixed cases matching keywords (e.g., "KASAN:use-after-free")
2. For each case, it fetches: kernel commit, syzkaller commit, config, syz_repro, log, C reproducer, report
3. **Deployer** clones the specific Linux kernel commit, applies KASAN/KCOV config, compiles with the correct compiler version
4. Compiles Ditto-customized syzkaller (commit `9b1f3e6`) — other syzkaller commits use native syzkaller with minimal config
5. Generates syzkaller config with critical syscalls, enabled syscalls, and mutation parameters
6. Runs syz-manager for kernel fuzzing; detects KASAN write/read/double-free crashes
7. Moves completed cases to `work/analyzing/`

## Architecture support

Adding a new architecture means:
- Add a new entry to `ARCH_CONFIG` in `core/interface/arch_config.py` with QEMU binary, kernel paths, cross-compiler, boot params, config options, crash regex patterns
- Add the cross-compiler toolchain to `tools/`
- Add kernel image + SSH key to `tools/img/`
- See `docs/ARM64_implementation_plan.md` for the ARM64 port details

## Output structure

`work/` contains subdirectories per case stage: `incomplete/`, `error/`, `analyzing/`, `warning/`, `completed/`, `succeed/`. Each case directory has:
- `.stamp/` — progress-flag files (BUILD_SYZKALLER, BUILD_KERNEL, REPRO_ORI_POC, FINISH_FUZZING)
- `basic_info/` — downloaded syzbot materials (config, syz_repro, log, c_repro, report, report_cg)
- `poc/` — reproduction run artifacts
- `crashes/` — fuzzing crash reports
- `linux` → symlink to the compiled kernel for this case

## Ditto-customized syzkaller

The Ditto fork of syzkaller is based on commit `9b1f3e6`. The patch is at `core/patches/syzkaller-9b1f3e6-ditto.patch`. Cases using this syzkaller commit get the full Ditto config template (`mutatetime`, `calltracesim`, `reprosim`, `critical_sys`, `critical_sys_seq`). Cases using other syzkaller commits get a minimal native config — they can only reproduce the original PoC, not fuzz with Ditto mutations.
