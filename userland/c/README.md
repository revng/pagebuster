# PageBuster - A user-space prototype

Rather than immediately getting our hands dirty with the kernel-side implementation, we started with a user-space prototype, and then we moved the logic to the kernel level solution.
In order to hook/hijack `mmap/mrotect`, we leveraged `LD_PRELOAD` environment variable. It's a simple way to hook library calls in a program. If you are not familiar with it, check out [
Rafał Cieślak's blog post on this topic](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/).
The interesting thing is that the libraries inside that variable have the highest priority. If you set `LD_PRELOAD` to the path of a shared object, that file will be loaded **before** any other library (including the C runtime, `libc.so`).

For more information, please refer to our [blogpost](https://rev.ng/blog/dump/post.html).

**Note**: This is a proof-of-concept of the real PageBuster. Its utility was only to warm up with the hook/dump logic. It's main limitation is that it will catch only library calls performed by the target process itself, and **not** the ones by the kernel nor the loader.

Installation
------------

The prototype requires [glib-2.56](http://ftp.gnome.org/pub/gnome/sources/glib/2.56/glib-2.56.4.tar.xz).

#### Pre-requisites:
```sh
apt-get install libffi-dev
apt-get install libmount-dev
```
#### Installation:
```sh
./configure --prefix=/usr      \
            --with-pcre=system \
            --with-python=/usr/bin/python3 &&
make

make install
```
#### Check: 
```bash
make -k check
```

Usage
-----

To build the library just run `make`.

Then you'll have to load the library inside the `LD_PRELOAD` variable.
```sh
export LD_PRELOAD=$PWD/userpagebuster.so
```
To void the env variable:
```sh
unset LD_PRELOAD
```

At this point, you can execute the target binary to obtain the executable pages dumped out of it.

If you want to set the `LD_PRELOAD` variable only for a single execution of the target process, use this:
```sh
LD_PRELOAD=$PWD/userpagebuster.so ./<target_process>
```
