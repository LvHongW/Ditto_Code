#!/bin/bash

echo "running linux-clone.sh"

if [ $# -ne 3 ]; then
  echo "Usage ./linux-clone save_linux_folder linux_folder hash_val"
  exit 1
fi

if [ -d "$1/$2-$3" ]; then
  echo "$1/$2-$3 exist"
  exit 0
fi
if [ ! -d "tools" ]; then
  mkdir tools
fi
cd tools || exit 1
if [ ! -d "linux-0" ]; then
  git clone https://github.com/torvalds/linux.git linux-0
  cp -r linux-0 $1/$2-$3
else
  cp -r linux-0 $1/$2-$3
fi
echo "Linux cloned to $1/$2-$3"
