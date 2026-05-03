#!/bin/bash

set -ex

echo "running deploy.sh"

LATEST="9b1f3e6"

function config_disable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/$key=y/# $key is not set/g" .config
}

function config_enable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/# $key is not set/$key=y/g" .config
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
CASE_PATH=$PROJECT_PATH/work/$CATALOG/$HASH
PATCHES_PATH=$PROJECT_PATH/$PKG_NAME/patches
LLVM_PATCHED_PATH=$PROJECT_PATH/tools/llvm/build

echo "Compiler: "$COMPILER_VERSION | grep gcc && \
COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/gcc || \
COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/clang
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))

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
  git checkout -f 9b1f3e665308ee2ddd5b3f35a078219b5c509cdb
  patch -p1 -i $PATCHES_PATH/syzkaller-9b1f3e6-ditto.patch

  make TARGETARCH=$ARCH TARGETVMARCH=amd64
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
if [ ! -L "$CASE_PATH/img/stretch.img" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img ./stretch.img
fi
if [ ! -L "$CASE_PATH/img/stretch.img.key" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img.key ./stretch.img.key
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
  git checkout -f $COMMIT || exit 1
  cp $CASE_PATH/basic_info/config .config

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
  
  for key in $CONFIGKEYSDISABLE;
  do
    config_disable $key
  done


  for key in $CONFIGKEYSENABLE;
  do
    config_enable $key
  done

  make olddefconfig CC=$COMPILER
  make -j$N_CORES CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
  rm $CASE_PATH/config || echo "It's ok"
  cp .config $CASE_PATH/config
  touch $CASE_PATH/.stamp/BUILD_KERNEL
fi

exit 0
