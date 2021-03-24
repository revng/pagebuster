#!/bin/bash
echo "Entering submodules"
cd submodules

echo "Checkout binutils-gdb @2d2ea781"
cd binutils-gdb/
git checkout 2d2ea781
cd ..

# echo "Checkout boot-wrapper-aarch64 @ed60963"
# cd boot-wrapper-aarch64/
# git checkout ed60963
# cd ..

echo "Checkout buildroot @b8c14b5b"
cd buildroot/
git checkout b8c14b5b
cd ..

# echo "Checkout crosstool-ng @b2151f1"
# cd crosstool-ng/
# git checkout b2151f1
# cd ..

# echo "Checkout freebsd @b91f25e"
# cd freebsd/
# git checkout b91f25e
# cd ..

echo "Checkout gcc @2d7ded1"
cd gcc/
git checkout 2d7ded1
cd ..

# echo "Checkout gem5 @ccee328"
# cd gem5/
# git checkout ccee328
# cd ..

# echo "Checkout gem5-resources @caf7ef4"
# cd gem5-resources/
# git checkout caf7ef4
# cd ..

# echo "Checkout gemsim @1c2c608"
# cd gemsim/
# git checkout 1c2c608
# cd ..

echo "Checkout glibc @be9a328"
cd glibc/
git checkout be9a328
cd ..

# echo "Checkout googletest @b1fbd33"
# cd googletest/
# git checkout b1fbd33
# cd ..

echo "Checkout linux kernel @ee336b3 - v5.9.2"
cd linux/
git checkout ee336b3
cd ..

echo "Checkout qemu @553032d"
cd qemu/
git checkout 553032d
cd ..

# echo "Checkout xen @96cbd08"
# cd xen/
# git checkout 96cbd08
# cd ..

cd ..