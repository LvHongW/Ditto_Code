#!/bin/bash

if [ ! -f "$(pwd)/tools/.stamp/ENV_SETUP" ]; then
  sudo apt-get -y install gdb curl git wget qemu-system-x86 debootstrap flex bison libssl-dev libelf-dev locales cmake libxml2-dev libz3-dev bc libncurses5 gcc-multilib g++-multilib dwarves
fi

if [ ! -d "work/completed" ]; then
  mkdir -p work/completed
fi

if [ ! -d "work/incomplete" ]; then
  mkdir -p work/incomplete
fi

TOOLS_PATH="$(pwd)/tools"
CORE_PATH="$(pwd)/core"
PATCHES_PATH=$CORE_PATH/patches
if [ ! -d "$TOOLS_PATH/.stamp" ]; then
  mkdir -p $TOOLS_PATH/.stamp
fi

echo "[+] Building image"
cd $TOOLS_PATH
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  if [ ! -f "stretch.img" ]; then
    wget https://storage.googleapis.com/syzkaller/stretch.img > /dev/null
    wget https://storage.googleapis.com/syzkaller/stretch.img.key > /dev/null
    chmod 400 stretch.img.key
    wget https://storage.googleapis.com/syzkaller/wheezy.img > /dev/null
    wget https://storage.googleapis.com/syzkaller/wheezy.img.key > /dev/null
    chmod 400 wheezy.img.key
    touch $TOOLS_PATH/.stamp/BUILD_IMAGE
  fi
  cd ..
fi

echo "[+] Building gcc and clang"
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_GCC_CLANG" ]; then
  wget https://storage.googleapis.com/syzkaller/gcc-7.tar.gz > /dev/null
  tar xzf gcc-7.tar.gz
  mv gcc gcc-7
  rm gcc-7.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180301.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180301.tar.gz
  mv gcc gcc-8.0.1-20180301
  rm gcc-8.0.1-20180301.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180412.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180412.tar.gz
  mv gcc gcc-8.0.1-20180412
  rm gcc-8.0.1-20180412.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-9.0.0-20181231.tar.gz > /dev/null
  tar xzf gcc-9.0.0-20181231.tar.gz
  mv gcc gcc-9.0.0-20181231
  rm gcc-9.0.0-20181231.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-10.1.0-syz.tar.xz > /dev/null
  tar xf gcc-10.1.0-syz.tar.xz
  mv gcc-10 gcc-10.1.0-20200507
  rm gcc-10.1.0-syz.tar.xz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-329060.tar.gz > /dev/null
  tar xzf clang-kmsan-329060.tar.gz
  mv clang-kmsan-329060 clang-7-329060
  rm clang-kmsan-329060.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-334104.tar.gz > /dev/null
  tar xzf clang-kmsan-334104.tar.gz
  mv clang-kmsan-334104 clang-7-334104
  rm clang-kmsan-334104.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-343298.tar.gz > /dev/null
  tar xzf clang-kmsan-343298.tar.gz
  mv clang-kmsan-343298 clang-8-343298
  rm clang-kmsan-343298.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang_install_c2443155.tar.gz > /dev/null
  tar xzf clang_install_c2443155.tar.gz
  mv clang_install_c2443155 clang-10-c2443155
  rm clang_install_c2443155.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-11-prerelease-ca2dcbd030e.tar.xz > /dev/null
  tar xf clang-11-prerelease-ca2dcbd030e.tar.xz
  mv clang clang-11-ca2dcbd030e
  rm clang-11-prerelease-ca2dcbd030e.tar.xz

  touch $TOOLS_PATH/.stamp/BUILD_GCC_CLANG
fi

echo "[+] Download pwndbg"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_PWNDBG" ]; then
  git clone https://github.com/plummm/pwndbg_linux_kernel.git pwndbg
  cd pwndbg
  ./setup.sh
  locale-gen
  sudo sed -i "s/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/g" /etc/locale.gen
  locale-gen

  touch $TOOLS_PATH/.stamp/SETUP_PWNDBG
  cd ..
fi

echo "[+] Setup golang environment"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_GOLANG" ]; then
  wget https://dl.google.com/go/go1.23.2.linux-amd64.tar.gz
  tar -xf go1.23.2.linux-amd64.tar.gz
  mv go goroot
  GOPATH=`pwd`/gopath
  if [ ! -d "gopath" ]; then
    mkdir gopath
  fi
  rm go1.23.2.linux-amd64.tar.gz
  touch $TOOLS_PATH/.stamp/SETUP_GOLANG
fi

echo "[+] Setup syzkaller"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_SYZKALLER" ]; then
  mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
  cd $GOPATH/src/github.com/google/
  rm -rf syzkaller || echo "syzkaller does not exist"
  git clone https://github.com/google/syzkaller.git
  touch $TOOLS_PATH/.stamp/SETUP_SYZKALLER
fi

touch $TOOLS_PATH/.stamp/ENV_SETUP

if [ -f "/usr/lib/x86_64-linux-gnu/libmpfr.so.6" ] && [ ! -f "/usr/lib/x86_64-linux-gnu/libmpfr.so.4" ]; then
  sudo ln -s /usr/lib/x86_64-linux-gnu/libmpfr.so.6 /usr/lib/x86_64-linux-gnu/libmpfr.so.4
fi

echo "[+] Clean unfinished jobs"
rm linux-*/.git/index.lock || echo "Removing index.lock"
rm linux-*/THIS_KERNEL_IS_BEING_USED || echo "All set"

exit 0
