/* 
 * PageBuster - dump all executable pages of packed processes.
 * 
 * Copyright (C) 2021  Matteo Giordano
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) "pagebuster: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/fs.h>

#include <asm/segment.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/current.h>
#include <asm/smap.h>

#include <uapi/asm-generic/mman-common.h>

/* External parameters */
static char *path;
module_param(path, charp, 0000);
MODULE_PARM_DESC(path, "Path/Name of the target process");

/* 
 * Data structure for memory areas tracked.
 *
 * Each entry is a memory page, index by its address
 * and with some protection flags.
 */
static LIST_HEAD(marea_list);

/* Data structure for all the memory areas to be considered */
extern struct list_head marea_list;

/* 
 * Structure for a memory area to be tracked.
 * 
 * Entry of the doubly-linked list.
 * 
 */
struct marea {

	/* intrusive list core */
	struct list_head list;
	
	/* mprotect/mmap address */
	unsigned long addr;
	
	/* mprotect/mmap access flag */
	unsigned long  prot;
};

static unsigned long epoch_counter = 0;

/* 
 * Searches inside the list @marea_list if it exists
 * an entry for the given @addr_given
 * 
 */
static struct marea *search_page(unsigned long addr_given, struct list_head marea_list)
{
	struct marea *result = NULL;

	list_for_each_entry(result, &marea_list, list) {
		unsigned long start_addr = (unsigned long) result->addr;
		unsigned long end_addr = start_addr + PAGE_SIZE -1;

		if(addr_given >= start_addr && addr_given <= end_addr){
			break;
		}
	}

	return result;
}

/* Allocates space for a new struct marea */
struct marea *new_marea(unsigned long addr, int prot)
{
	struct marea *new_m = (struct marea *) kmalloc(sizeof(struct marea), GFP_KERNEL);
	if (new_m) {
		new_m->addr = addr;
		new_m->prot = prot;
		INIT_LIST_HEAD(&new_m->list);
	}
	return new_m;
}

static void dump_to_file(unsigned long buf, size_t size, loff_t *offset) 
{
	struct file *dest_file = NULL;	
	char file_path[100];

	// Permanent path
	//sprintf(file_path, "/lkmc/dump/%lx_%lu", buf, epoch_counter);

	// Temporary path
	sprintf(file_path, "/tmp/%lx_%lu", buf, epoch_counter);

	epoch_counter++;

	size_t res;

	dest_file = filp_open(file_path, O_CREAT | O_RDWR | O_APPEND | O_LARGEFILE, 0666);
	if (IS_ERR(dest_file)) {
		printk("Error in opening: <%ld>", (long) dest_file);
	}
	if (dest_file == NULL) {
		printk("Error in opening: null");
	}

	res = kernel_write(dest_file, (void *) buf, size, offset);
	filp_close(dest_file, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("Unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/* mprotect() hook'd function */
static asmlinkage long (*real_sys_mprotect)(struct pt_regs *regs);

/*
 *	%rdi	regs->di	unsigned long addr
 *	%rsi	regs->si	size_t len
 *	%rdx	regs->dx	unsigned long prot
 */
static asmlinkage long fh_sys_mprotect(struct pt_regs *regs)
{
	int n_pages;
	size_t quotient, remainder;

	struct marea *entry, *tmp;

	if (strstr(current->comm, path) != NULL) {

		quotient = regs->si / PAGE_SIZE;
		remainder = regs->si % PAGE_SIZE;

		if (remainder == 0)
			n_pages = quotient;
		else 
			n_pages = quotient + 1;

		/* Avoid cohexistence of W^X */
		if (regs->dx >= (PROT_EXEC | PROT_WRITE)) {

			/* Create an entry for each page covered by mprotect */
			for (int i = 0; i < n_pages; i++) {
				entry = NULL;
				int replaced = 0;

				list_for_each_entry(entry, &marea_list, list) {
					if (entry->addr == (regs->di + (i * PAGE_SIZE))) {
						struct marea *tmp = new_marea(regs->di + (i * PAGE_SIZE), regs->dx);
						list_replace(&entry->list, &tmp->list);
						replaced = 1;
						break;
					}
				}

				if(!replaced) {
					struct marea *tmp = new_marea(regs->di + (i * PAGE_SIZE), regs->dx);
					list_add(&tmp->list, &marea_list);
				}
			}

			regs->dx &= ~PROT_WRITE;

		} else if ((regs->dx == PROT_EXEC) || (regs->dx == (PROT_EXEC | PROT_READ))) {

			/* EFLAGS.AC <- 1 */
			stac();
			for (int i = 0; i < n_pages; i++) {
				loff_t offset = 0;
				loff_t *off_p = &offset;
				dump_to_file(regs->di + (i * PAGE_SIZE), PAGE_SIZE, off_p);
			}

			/* EFLAGS.AC <- 0 */
			clac();

		/* User issued mprotect(0|1|2|3) */
		} else {
			for (int i = 0; i < n_pages; i++) {
				entry = NULL;
				tmp = NULL;
				list_for_each_entry_safe(entry, tmp, &marea_list, list) {
					if (entry->addr == (regs->di + (i * PAGE_SIZE))) {
						list_del(&entry->list);
						kfree(entry);
					}
				}
			}
		}

	return real_sys_mprotect(regs);

	} else {
		return real_sys_mprotect(regs);
	}
}

/* mmap() hook'd function */
static asmlinkage long (*real_sys_mmap)(struct pt_regs *regs);

/*
 *	%rdi	regs->di	unsigned long addr
 *	%rsi	regs->si	unsigned long len
 *	%rdx	regs->dx	unsigned long prot
 *	%r10 	regs->r10	unsigned long flags
 *	%r8 	regs->r8	unsigned long fd
 *	%r9 	regs->r9	unsigned long off
 */
static asmlinkage long fh_sys_mmap(struct pt_regs *regs)
{
	long ret;
	int n_pages;

	size_t quotient, remainder;

	long intended_permissions;

	struct marea *entry, *tmp;

	if (strstr(current->comm, path) != NULL) {

		regs->r10 |= MAP_POPULATE;

		quotient = regs->si / PAGE_SIZE;
		remainder = regs->si % PAGE_SIZE;

		if (remainder == 0)
			n_pages = quotient;
		else
			n_pages = quotient + 1;

		/* Avoid cohexistence of W^X */
		if (regs->dx >= (PROT_EXEC | PROT_WRITE)) {

			intended_permissions = regs->dx;
			regs->dx &= ~PROT_WRITE;
			
			ret = real_sys_mmap(regs);

			/* Create an entry for each page allocated by the mmap */
			for (int i = 0; i < n_pages; i++) {
				entry = NULL;
				int replaced = 0;

				list_for_each_entry(entry, &marea_list, list) {
					if (entry->addr == (ret + (i * PAGE_SIZE))) {
						struct marea *tmp = new_marea(ret + (i * PAGE_SIZE), intended_permissions);
						list_replace(&entry->list, &tmp->list);
						replaced = 1;
						break;
					}
				}
				
				if (!replaced) {
					struct marea *tmp = new_marea(ret + (i * PAGE_SIZE), intended_permissions);
					list_add(&tmp->list, &marea_list);
				}
			}

			return ret;

		} else if ((regs->dx == PROT_EXEC) || (regs->dx == (PROT_EXEC | PROT_READ))) {
			ret = real_sys_mmap(regs);

			/* EFLAGS.AC <- 1 */
			stac();

			for (int i = 0; i < n_pages; i++) {
				loff_t offset = 0;
				loff_t *off_p = &offset;
				dump_to_file(ret + (i * PAGE_SIZE), PAGE_SIZE, off_p);
			}

			/* EFLAGS.AC <- 0 */
			clac();

			return ret;

		/* User issued mmap(0|1|2|3) */
		} else {
			ret = real_sys_mmap(regs);
			for (int i = 0; i < n_pages; i++) {
				entry = NULL;
				tmp = NULL;
				list_for_each_entry_safe(entry, tmp, &marea_list, list) {
					if (entry->addr == (ret + (i * PAGE_SIZE))) {
						list_del(&entry->list);
						kfree(entry);
					}
				}
			}
			return ret;
		}

	} else {
		return real_sys_mmap(regs);	
	}
}

static asmlinkage long (*real_force_sig_fault)(int sig, int code, void __user *addr);

static asmlinkage int fh_force_sig_fault(int sig, int code, void __user *addr)
{
	struct marea *page_inducted = NULL;
	unsigned long address = (unsigned long) addr;

	/* If found, then this segfault has been inducted */
	if (!list_empty(&marea_list)) {
		page_inducted = search_page(address, marea_list);
	}

	
	/* Standard SIGSEGV handling */
	if (page_inducted == NULL) {
		return real_force_sig_fault(sig, code, addr);

	/* Custom SIGSEGV handling */
	} else {
		struct pt_regs *regs = kmalloc(sizeof(struct pt_regs), GFP_KERNEL);
		// Address
		regs->di = page_inducted->addr;
		// Length
		regs->si = PAGE_SIZE;

		unsigned long new_permissions = page_inducted->prot;

		/* Invalid write attempt */
		if (current->thread.error_code & X86_PF_WRITE) {

			new_permissions &= ~PROT_EXEC;

			// Protections
			regs->dx = new_permissions;

			real_sys_mprotect(regs);

		/* Bad jump */
		} else if (current->thread.error_code & X86_PF_INSTR) {
			
			new_permissions &= ~PROT_WRITE;
			
			stac();
			loff_t offset = 0;
			loff_t *off_p = &offset;
			dump_to_file(page_inducted->addr, PAGE_SIZE, off_p);
			clac();

			// Protections
			regs->dx = new_permissions;

			real_sys_mprotect(regs);
		}
		kfree(regs);

		return 0;
	}
}

/* execve() hook'd function */
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	struct marea *entry = NULL, *tmp = NULL;

	char *kernel_filename = kmalloc(4096, GFP_KERNEL);

	if (!kernel_filename) {
		return -ENOMEM;
	}

	if (strncpy_from_user(kernel_filename, (const char __user *) regs->di, 4096) < 0) {
		kfree(kernel_filename);
		return -EINVAL;
	}

	/* 
	 * If the path matches the given parameter, then empty the list.
 	 */
	if (strstr(kernel_filename, path) != NULL) {
		list_for_each_entry_safe(entry, tmp, &marea_list, list) {
			list_del(&entry->list);	
		}
	}

	kfree(kernel_filename);

	return real_sys_execve(regs);
}

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

#define HOOK_NOSYS(_name, _function, _original)	\
	{					\
		.name = _name,	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_mprotect",  fh_sys_mprotect,  &real_sys_mprotect),
	HOOK("sys_mmap", fh_sys_mmap, &real_sys_mmap),
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
	HOOK_NOSYS("force_sig_fault", fh_force_sig_fault, &real_force_sig_fault),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;
	pr_info("PageBuster Module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	pr_info("PageBuster Module unloaded\n");
}
module_exit(fh_exit);

MODULE_DESCRIPTION("PageBuster - dump all executable pages of packed processes.");
MODULE_AUTHOR("Matteo Giordano <matteo.giordano@protonmail.com>");
MODULE_LICENSE("GPL");
