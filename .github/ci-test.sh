#!/bin/sh
set -ex

curl -L -O https://github.com/cia-foundation/TempleOS/raw/archive/0000Boot/0000Kernel.BIN.C
curl -L -O https://github.com/cia-foundation/TempleOS/raw/archive/Compiler/Compiler.BIN

mkdir -p output

./bininfo Compiler.BIN > output/Compiler.txt
./bininfo 0000Kernel.BIN.C > output/Kernel.txt

diff output/Compiler.txt $(dirname "$0")/expected/Compiler.txt
diff output/Kernel.txt $(dirname "$0")/expected/Kernel.txt
