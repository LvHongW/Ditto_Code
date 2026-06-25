#!/bin/bash

set -ex

echo "running deploy.sh"

LATEST="9b1f3e6"

function config_disable() {
  key=$1
  if [ -f scripts/config ]; then
    scripts/config --disable $key
  else
    sed -i "s/$key=n/# $key is not set/g" .config
    sed -i "s/$key=m/# $key is not set/g" .config
    sed -i "s/$key=y/# $key is not set/g" .config
  fi
}

function config_enable() {
  key=$1
  if [ -f scripts/config ]; then
    scripts/config --enable $key
  else
    sed -i "s/$key=n/# $key is not set/g" .config
    sed -i "s/$key=m/# $key is not set/g" .config
    sed -i "s/# $key is not set/$key=y/g" .config
  fi
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-$COMPILER_VERSION
  exit 1
}

function set_git_config() {
  set +x
  echo "set user.email for git config"
  echo "Input email: "
  read email
  echo "set user.name for git config"
  echo "Input name: "
  read name
  git config --global user.email $email
  git config --global user.name $name
  set -x
}

function build_golang() {
  echo "setup golang environment"
  rm goroot || echo "clean goroot"
  wget https://dl.google.com/go/go1.23.2.linux-amd64.tar.gz
  tar -xf go1.23.2.linux-amd64.tar.gz
  mv go goroot
  if [ ! -d "gopath" ]; then
    mkdir gopath
  fi
  rm go1.23.2.linux-amd64.tar.gz
}

if [ $# -ne 13 ]; then
  echo "Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase index catalog image arch gcc_version max_compiling_kernel save_linux_folder"
  exit 1
fi

HASH=$2
COMMIT=$3
SYZKALLER=$4
CONFIG=$5
TESTCASE=$6
INDEX=$7
CATALOG=$8
IMAGE=$9
ARCH=${10}
COMPILER_VERSION=${11}
MAX_COMPILING_KERNEL=${12}
save_linux_folder=${13}
PROJECT_PATH="$(pwd)"
PKG_NAME="core"
CASE_PATH=$PROJECT_PATH/work/$CATALOG/$INDEX
PATCHES_PATH=$PROJECT_PATH/$PKG_NAME/patches
LLVM_PATCHED_PATH=$PROJECT_PATH/tools/llvm/build

# ARM64 uses cross-compiler (gcc-12 required for KCOV on arm64 due to ARCH_WANTS_NO_INSTR)
if [ "$ARCH" = "arm64" ]; then
  COMPILER=$PROJECT_PATH/tools/aarch64-gcc/bin/aarch64-linux-gnu-gcc
  CROSS_COMPILE="aarch64-linux-gnu-"
  MAKE_ARCH="ARCH=arm64 CROSS_COMPILE=$CROSS_COMPILE"
else
  echo "Compiler: "$COMPILER_VERSION | grep gcc && \
  COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/gcc || \
  COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/clang
  CROSS_COMPILE=""
  MAKE_ARCH=""
fi
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))

echo "[deploy.sh] ARCH=$ARCH COMPILER=$COMPILER"

if [ ! -d "$save_linux_folder/$1-$INDEX" ]; then
  echo "No linux repositories detected"
  exit 1
fi

cd $save_linux_folder/$1-$INDEX
if [ ! -d ".git" ]; then
  echo "This linux repo is not clone by git."
  exit 1
fi

cd ..

export GO111MODULE=auto
export GOPATH=$CASE_PATH/gopath
export GOROOT=$PROJECT_PATH/tools/goroot
export LLVM_BIN=$PROJECT_PATH/tools/llvm/build/bin
export PATH=$GOROOT/bin:$LLVM_BIN:$PATH

# Add cross-compiler to PATH for syzkaller executor build (arm64)
if [ "$ARCH" = "arm64" ]; then
  export PATH=$PROJECT_PATH/tools/aarch64-gcc/bin:$PATH
fi
echo "[+] Downloading golang"
go version || build_golang

cd $CASE_PATH || exit 1
if [ ! -d ".stamp" ]; then
  mkdir .stamp
fi

if [ ! -d "compiler" ]; then
  mkdir compiler
fi
cd compiler
if [ ! -L "$CASE_PATH/compiler/compiler" ]; then
  ln -s $COMPILER ./compiler
fi

echo "[+] Building syzkaller"
if [ ! -f "$CASE_PATH/.stamp/BUILD_SYZKALLER" ]; then
  if [ -d "$GOPATH/src/github.com/google/syzkaller" ]; then
    rm -rf $GOPATH/src/github.com/google/syzkaller
  fi
  mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
  cd $GOPATH/src/github.com/google/
  cp -r $PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller ./
  cd $GOPATH/src/github.com/google/syzkaller || exit 1
  make clean
  git stash --all || set_git_config

  # Use the case's syzkaller commit (supports compressed_image, bcachefs, etc.)
  # The old Ditto base commit (9b1f3e6) predates compressed_image and bcachefs.
  # Newer syzkaller versions (e.g. 6f888b75) support these natively.
  DITTO_BASE="9b1f3e665308ee2ddd5b3f35a078219b5c509cdb"
  echo "[deploy.sh] syzkaller commit: $SYZKALLER (ditto base: $DITTO_BASE)"
  git checkout -f $SYZKALLER

  # Only apply Ditto patch if using the old base commit
  if [ "$SYZKALLER" = "$DITTO_BASE" ]; then
    echo "[deploy.sh] Applying Ditto patch for base commit"
    patch -p1 -i $PATCHES_PATH/syzkaller-9b1f3e6-ditto.patch

    # Add bcachefs + compressed_image support (needed for newer syzbot testcases)
    # The Ditto base commit (9b1f3e6, Mar 2020) predates both the compressed_image
    # type (Nov 2022) and bcachefs descriptions (May 2024). Add minimal support.
    cp $PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller/sys/linux/filesystem.txt sys/linux/filesystem.txt
    # prog/types.go: add BufferCompressed to BufferKind enum (after BufferText)
    sed -i 's/^\tBufferText$/&\n\tBufferCompressed/' prog/types.go
    # prog/types.go: add IsCompressed() method (before type ArrayKind)
    sed -i 's/^type ArrayKind int$/\nfunc (t *BufferType) IsCompressed() bool {\n\treturn t.Kind == BufferCompressed\n}\n\n&/' prog/types.go
    # pkg/compiler/types.go: append typeCompressedImage before init()
    cat > /tmp/ditto_tci.go << 'TCIEOF'
// typeCompressedImage is used for compressed disk images.
var typeCompressedImage = &typeDesc{
	Names:     []string{"compressed_image"},
	CantBeOpt: true,
	CanBeArgRet: func(comp *compiler, t *ast.Type) (bool, bool) {
		return true, false
	},
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		return true
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.TypeSize = 0
		return &prog.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       prog.BufferCompressed,
		}
	},
}
TCIEOF
    sed -i '$ r /tmp/ditto_tci.go' pkg/compiler/types.go
    rm -f /tmp/ditto_tci.go
    # pkg/compiler/types.go: add typeCompressedImage to builtins list
    sed -i 's/\t\ttypeFmt,/\t\ttypeCompressedImage,\n\t\ttypeFmt,/' pkg/compiler/types.go
  else
    echo "[deploy.sh] Using native syzkaller (skipping Ditto patch)"
  fi


  # Make unknown enabled syscall a warning instead of fatal error.
  # The enable_syscalls list may contain x86 syscalls that do not exist
  # on other architectures (e.g. open, fork, pipe on ARM64).
  sed -i 's/return nil, fmt\.Errorf("unknown enabled syscall: %v", c)/continue/' pkg/mgrconfig/load.go
  # ARM64: increase timeouts for TCG emulation (udev-trigger takes 10+ min)
  if [ "$ARCH" = "arm64" ]; then
    # Increase SSH/SCP timeouts for slow TCG emulation
    sed -i 's/WaitForSSH(inst.debug, [0-9]*\*time.Minute/WaitForSSH(inst.debug, 60*time.Minute/' vm/qemu/qemu.go 2>/dev/null || true
    sed -i 's/WaitForSSH([0-9]*\*time.Minute/WaitForSSH(60*time.Minute/' vm/qemu/qemu.go 2>/dev/null || true
    sed -i 's/RunCmd([0-9]*\*time.Minute, "", "scp"/RunCmd(30*time.Minute, "", "scp"/' vm/qemu/qemu.go 2>/dev/null || true
    sed -i 's/RunCmd([0-9]*\*time.Minute, "", "scp"/RunCmd(30*time.Minute, "", "scp"/' vm/qemu/qemu.go 2>/dev/null || true
    sed -i 's/RunCmd(time.Minute, "", executor/RunCmd(10*time.Minute, "", executor/' pkg/host/features.go 2>/dev/null || true
    sed -i 's/RunCmd([0-9]*\*time.Minute, "", executor/RunCmd(10*time.Minute, "", executor/' pkg/host/features.go 2>/dev/null || true
  fi

  # For ARM64: syz-fuzzer/syz-execprog run inside the VM, so TARGETVMARCH must be arm64
  # For amd64: syz-fuzzer/syz-execprog run on the host, TARGETVMARCH=amd64
  if [ "$ARCH" = "arm64" ]; then
    # The Makefile's generate_rpc target requires flatc >= 2.0 (--warnings-as-errors).
    # Extract pre-generated flatrpc files from git instead of running flatc 1.12.
    mkdir -p pkg/flatrpc
    git show HEAD:pkg/flatrpc/flatrpc.h > pkg/flatrpc/flatrpc.h 2>/dev/null && \
      echo "[deploy.sh] Extracted flatrpc.h from git" || \
      echo "[deploy.sh] WARNING: could not extract flatrpc.h"
    git show HEAD:pkg/flatrpc/flatrpc.go > pkg/flatrpc/flatrpc.go 2>/dev/null && \
      echo "[deploy.sh] Extracted flatrpc.go from git" || \
      echo "[deploy.sh] WARNING: could not extract flatrpc.go"
    make TARGETARCH=arm64 TARGETVMARCH=arm64
    # Create symlinks so syz-manager finds ARM64 binaries in bin/
    cd bin
    ln -sf linux_arm64/syz-fuzzer syz-fuzzer
    ln -sf linux_arm64/syz-execprog syz-execprog
    ln -sf linux_arm64/syz-executor syz-executor
    ln -sf linux_arm64/syz-stress syz-stress
    cd ..
  else
    make TARGETARCH=$ARCH TARGETVMARCH=amd64
  fi

  if [ ! -d "workdir" ]; then
    mkdir workdir
  fi

  cp $CASE_PATH/basic_info/syz_repro $GOPATH/src/github.com/google/syzkaller/workdir/testcase-$HASH
  touch $CASE_PATH/.stamp/BUILD_SYZKALLER
fi

cd $CASE_PATH || exit 1
echo "[+] Copy image"
if [ ! -d "$CASE_PATH/img" ]; then
  mkdir -p $CASE_PATH/img
fi
cd img
# ARM64 uses different image filenames
if [ "$ARCH" = "arm64" ]; then
  if [ ! -L "$CASE_PATH/img/arm64-trixie.img" ]; then
    ln -s $PROJECT_PATH/tools/img/$IMAGE.img ./arm64-trixie.img
  fi
  if [ ! -L "$CASE_PATH/img/arm64-trixie.img.key" ]; then
    ln -s $PROJECT_PATH/tools/img/$IMAGE.img.key ./arm64-trixie.img.key
  fi
else
  if [ ! -L "$CASE_PATH/img/stretch.img" ]; then
    ln -s $PROJECT_PATH/tools/img/$IMAGE.img ./stretch.img
  fi
  if [ ! -L "$CASE_PATH/img/stretch.img.key" ]; then
    ln -s $PROJECT_PATH/tools/img/$IMAGE.img.key ./stretch.img.key
  fi
fi
cd ..

echo "[+] Building kernel"
OLD_INDEX=`ls -l linux | cut -d'-' -f 3`
if [ "$OLD_INDEX" != "$INDEX" ]; then
  rm -rf "./linux" || echo "No linux repo"
  ln -s $save_linux_folder/$1-$INDEX ./linux
  if [ -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
      rm $CASE_PATH/.stamp/BUILD_KERNEL
  fi
fi
if [ ! -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
  cd linux
  git stash || echo "it's ok"
  make clean > /dev/null || echo "it's ok"
  git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null || echo "it's ok"
  if ! git cat-file -t $COMMIT >/dev/null 2>&1; then
    echo "[WARNING] Commit $COMMIT not found, fetching from additional remotes..."
    # Try to fetch from arm64, linux-next, and bcachefs trees
    for remote in arm64 linux-next bcachefs; do
      if git remote get-url $remote >/dev/null 2>&1; then
        echo "[INFO] Fetching from $remote..."
        git fetch $remote 2>/dev/null || true
        if git cat-file -t $COMMIT >/dev/null 2>&1; then
          echo "[INFO] Found commit in $remote tree"
          break
        fi
      fi
    done
    # If still not found, fall back to closest tag by date
    if ! git cat-file -t $COMMIT >/dev/null 2>&1; then
      echo "[WARNING] Commit still not found, finding closest tag by date..."
      # Find the tag with the closest date to the commit
      CLOSEST_TAG=""
      MIN_DIFF=999999999
      # Only consider mainline tags (v*.*.*) from the origin remote
      for tag in $(git tag -l 'v*' --sort=-creatordate | head -200); do
        TAG_DATE=$(git log -1 --format="%at" $tag 2>/dev/null)
        if [ -n "$TAG_DATE" ]; then
          DIFF=$((TAG_DATE - $(date -d "2024-09-23" +%s 2>/dev/null || echo 0)))
          DIFF=${DIFF#-}  # absolute value
          if [ $DIFF -lt $MIN_DIFF ]; then
            MIN_DIFF=$DIFF
            CLOSEST_TAG=$tag
          fi
        fi
      done
      if [ -n "$CLOSEST_TAG" ]; then
        echo "[WARNING] Using closest tag: $CLOSEST_TAG"
        COMMIT=$CLOSEST_TAG
      else
        echo "[ERROR] No suitable tag found, cannot checkout kernel"
        exit 1
      fi
    fi
  fi
  git checkout -f $COMMIT || exit 1
  cp $CASE_PATH/basic_info/config .config

  if [ "$ARCH" = "arm64" ]; then
    CONFIGKEYSENABLE="
      CONFIG_HAVE_ARCH_KASAN
      CONFIG_KASAN
      CONFIG_KASAN_GENERIC
      CONFIG_KASAN_INLINE
      CONFIG_DEBUG_INFO
      CONFIG_FRAME_POINTER
      CONFIG_CC_HAS_SANCOV_TRACE_PC
      CONFIG_KCOV
      CONFIG_KCOV_INSTRUMENT_ALL
      CONFIG_KCOV_ENABLE_COMPARISONS
      CONFIG_DEBUG_FS
      CONFIG_DEBUG_KMEMLEAK
      CONFIG_KALLSYMS
      CONFIG_KALLSYMS_ALL
      CONFIG_VIRTIO_BLK
      CONFIG_VIRTIO_NET
      CONFIG_VIRTIO_PCI"

    CONFIGKEYSDISABLE="
      CONFIG_BUG_ON_DATA_CORRUPTION
      CONFIG_RANDOMIZE_BASE
      CONFIG_PANIC_ON_OOPS"
  else
    CONFIGKEYSENABLE="
      CONFIG_HAVE_ARCH_KASAN
      CONFIG_KASAN
      CONFIG_KASAN_OUTLINE
      CONFIG_DEBUG_INFO
      CONFIG_FRAME_POINTER
      CONFIG_UNWINDER_FRAME_POINTER
      CONFIG_KCOV
      CONFIG_KCOV_INSTRUMENT_ALL
      CONFIG_KCOV_ENABLE_COMPARISONS
      CONFIG_DEBUG_FS
      CONFIG_DEBUG_KMEMLEAK
      CONFIG_DEBUG_INFO
      CONFIG_KALLSYMS
      CONFIG_KALLSYMS_ALL"

    CONFIGKEYSDISABLE="
      CONFIG_BUG_ON_DATA_CORRUPTION
      CONFIG_KASAN_INLINE
      CONFIG_RANDOMIZE_BASE
      CONFIG_PANIC_ON_OOPS
      CONFIG_X86_SMAP
      CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC
      CONFIG_BOOTPARAM_HARDLOCKUP_PANIC
      CONFIG_BOOTPARAM_HUNG_TASK_PANIC"
  fi

  for key in $CONFIGKEYSDISABLE;
  do
    config_disable $key
  done


  for key in $CONFIGKEYSENABLE;
  do
    config_enable $key
  done

  make olddefconfig $MAKE_ARCH CC=$COMPILER
  make -j$N_CORES $MAKE_ARCH CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
  rm $CASE_PATH/config || echo "It's ok"
  cp .config $CASE_PATH/config
  touch $CASE_PATH/.stamp/BUILD_KERNEL
fi

exit 0
