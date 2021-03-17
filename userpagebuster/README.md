# PageBuster - A user-space prototype

This is a user-space-only prototype implementation of PageBuster.

Rather than immediately getting our hands dirty with the kernel-side implementation, we started with a user-space prototype, and then we moved the logic to the kernel level solution.
In order to hook/hijack `mmap/mrotect`, we leveraged `LD_PRELOAD` environment variable. It's a simple way to hook library calls in a program. If you are not familiar with it, check out [
Rafał Cieślak's blog post on this topic](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/).
The interesting thing is that the libraries inside that variable have the highest priority. If you set `LD_PRELOAD` to the path of a shared object, that file will be loaded **before** any other library (including the C runtime, `libc.so`).

For more information, please refer to our [blogpost](https://rev.ng/blog/pagebuster/post.html).

**Note**: This is a proof-of-concept of the real PageBuster. Its utility was only to warm up with the hook/dump logic. Main limitation: it will catch only library calls performed by the target process itself, and _not_ the ones by the kernel nor the loader.

Usage
-----

To build the library and the test binary just run:

```sh
sudo apt-get install gcc build-essential libglib2.0-dev
make
```

Then you'll have to load the library inside the `LD_PRELOAD` variable.

If you want to set the `LD_PRELOAD` variable only for a single execution of the target process, use this:

```sh
rm -f 0x*_*
LD_PRELOAD=$PWD/userpagebuster.so ./example
```

At this point, you can execute the target binary to obtain the executable pages dumped out of it.

```
objdump -b binary -m i386:x86-64 -D 0x*_*
```

You should see three `nop` and `ret`.
