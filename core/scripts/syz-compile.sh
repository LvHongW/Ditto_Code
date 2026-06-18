#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Usage ./syz-compile.sh case_path arch"
  exit 1
fi

CASE_PATH=$1
SYZ_PATH=$CASE_PATH/gopath/src/github.com/google/syzkaller
ARCH=$2

export GO111MODULE=auto
export GOPATH=$CASE_PATH/gopath
export GOROOT=`pwd`/tools/goroot
export LLVM_BIN=`pwd`/tools/llvm/build/bin
export PATH=$GOROOT/bin:$LLVM_BIN:$PATH

cd $SYZ_PATH
# make generate may fail if the description files use newer syntax than the
# old syzkaller parser supports (e.g. syz_mount_image$* with compressed_image).
# Try make generate; if it fails, fall back to building with existing generated code.
if make generate 2>/dev/null; then
  :
else
  echo "[syz-compile.sh] make generate failed, building with existing generated code"
fi
rm -f CorrectTemplate
if [ "$ARCH" = "arm64" ]; then
  make TARGETARCH=$ARCH TARGETVMARCH=arm64 || exit 1
else
  make TARGETARCH=$ARCH TARGETVMARCH=amd64 || exit 1
fi
exit 0