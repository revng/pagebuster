# PageBuster

>_Ever wanted to dump all the executable pages of a process? Do you crave something capable of dealing with **packed** processes?_  

We've got you covered! May I introduce **PageBuster**, our tool to gather dumps of all executable pages of packed processes.

[![asciicast](https://asciinema.org/a/cJH2O5N8w8Dd0GUuHw9kj8CZM.svg)](https://asciinema.org/a/cJH2O5N8w8Dd0GUuHw9kj8CZM)

This code is licensed under [GPLv2](https://github.com/zTehRyaN/pagebuster/blob/main/LICENSE).

Please consider using a **virtual machine** (VirtualBox, VMWare, QEMU, etc.) for testing. The module could be 
harmful. Avoid killing your machine or production environment by accident.

Make sure you have installed GCC and Linux kernel headers for your kernel. For Debian-based systems:
```sh
$ sudo apt install build-essential linux-headers-$(uname -r)
```
Then, build the kernel module:
```sh
$ cd pagebuster
$ make
output
```
This will build the module for the kernel you are currently running.

Getting started (Buildroot setup)
------------------------------------

This setup has been mostly tested on Ubuntu.
Reserve 12Gb of disk and run:
```sh
git clone https://github.com/zTehRyaN/linux-kernel-module-cheat
cd linux-kernel-module-cheat
./build --download-dependencies qemu-buildroot
sh checkout.sh
./run
```
The initial build will take a while (30 minutes to 2 hours) to clone and build.


Usage
-----------

After`./run`, QEMU opens up leaving you in the `/lkmc/` directory, and you can start playing with the kernel modules inside the simulated system.  
To test **PageBuster**, you can insert the LKM and try it with whatever binary you want. We provided you with [`sigsegv.c`](https://github.com/zTehRyaN/linux-kernel-module-cheat/blob/master/userland/c/sigsegv.c), a `.c` program that simply maps and executes a shellcode. Inside the `/userland/c/` directory you will find many `c` programs you can use, among which also the one shown in the demo (`simple.c`).

After the first `./run`, you will find all the files inside the [`/userland/c`](https://github.com/zTehRyaN/linux-kernel-module-cheat/tree/master/userland/c) folder automatically compiled and ready for use. To test them, simply insert the module and pass the name of the process as argument. Then, execute it.

```sh
insmod /mnt/9p/out_rootfs_overlay/lkmc/ftrace_hook.ko path=sigsegv.out
/mnt/9p/out_rootfs_overlay/lkmc/c/sigsegv.out
```

Inside the `/tmp` directory, you will find all the timestamped dumps.
```sh
root@buildroot# ls /tmp                        
100000000_494     7ffff7d4b000_291  7ffff7dc7000_415  7ffff7eb9000_30                         
100001000_495     7ffff7d4c000_292  7ffff7dc8000_416  7ffff7eba000_31                         
7ffff7cd1000_169  7ffff7d4d000_293  7ffff7dc9000_417  7ffff7ebb000_32                         
7ffff7cd2000_170  7ffff7d4e000_294  7ffff7dca000_418  7ffff7ebc000_33                         
7ffff7cd3000_171  7ffff7d4f000_295  7ffff7dcb000_419  7ffff7ebd000_34                         
7ffff7cd4000_172  7ffff7d50000_296  7ffff7dcc000_420  7ffff7ebe000_35                         
7ffff7cd5000_173  7ffff7d51000_297  7ffff7dcd000_421  7ffff7ebf000_36                         
7ffff7cd6000_174  7ffff7d52000_298  7ffff7dce000_422  7ffff7ec0000_37
...
```

To remove the LKM, run:

```sh
rmmod ftrace_hook.ko
```

Quit QEMU with `Ctrl-A X` or running `poweroff`.

If you want to test with other binaries, you may put the source `.c` file inside the [`/userland/c`](https://github.com/zTehRyaN/linux-kernel-module-cheat/tree/master/userland/c) folder and let the simulator compile it for you by running `./build-userland`. Now, after running the system, you will find it compiled inside `/mnt/9p/out_rootfs_overlay/lkmc/c/`.

UPX testing
----------------

If you want to try how **PageBuster** behaves with UPX-packed binaries, you should prepare them outside the QEMU guest environment, and then inject into it.  
First of all, install [upx](https://upx.github.io/). On Ubuntu 20.04 LTS, run:
```sh
sudo apt-get update -y
sudo apt-get install -y upx-ucl
```
Then, for instance, grab a `.c` program and compile it. Make sure it reaches the minimum size required by upx to pack it: UPX cannot handle binaries under 40Kb. The best way to work-around this problem is to compile your binary in static mode, in order to get a bigger executable file.  
So, just try:
```sh
gcc -static -o mytest mytest.c
upx -o mytest_packed mytest
```

The easiest way to put it inside QEMU is the following.
```c
cd linux-kernel-module-cheat
cp /path/to/mytest_packed $PWD/out/buildroot/build/default/x86_64/target/lkmc/
./build-buildroot
```

Now you can test it, in the usual way:
```sh
./run
insmod /mnt/9p/out_rootfs_overlay/lkmc/ftrace_hook.ko path=mytest_packed
./mytest_packed
ls /tmp
```
Output will be something like that:
```sh
root@buildroot# ls /tmp  
401000_2        427000_40       44d000_78       473000_116                                                                                
402000_3        428000_41       44e000_79       474000_117                                                                                
403000_4        429000_42       44f000_80       475000_118                                                                                
404000_5        42a000_43       450000_81       476000_119                                                                                
405000_6        42b000_44       451000_82       477000_120
406000_7        42c000_45       452000_83       478000_121
407000_8        42d000_46       453000_84       479000_122
408000_9        42e000_47       454000_85       47a000_123
409000_10       42f000_48       455000_86       47b000_124
40a000_11       430000_49       456000_87       47c000_125

```
