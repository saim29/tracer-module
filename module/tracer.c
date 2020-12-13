#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>

#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>                
#include<linux/uaccess.h>          
#include <linux/ioctl.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("saim29");
MODULE_DESCRIPTION("A Syscall Tracer");
MODULE_VERSION("1.0");

#define NUM_SYSCALLS 3
#define TRACER_REG 1
#define TRACER_UNREG 2
#define DEV_FILE "etx_device"

/*
	sys_call_table pointer
*/
char *sym_name = "sys_call_table";
typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table;

/* 
	Allocate an array of kprobes for every syscall traced
*/
static struct kprobe kp[NUM_SYSCALLS];

/*
	Define a hashtable to store all the Processes that
	register with the tracer
*/
static DEFINE_HASHTABLE(pid_table, 7);

/*
	Hashtable node
*/
struct ht_entry {
	pid_t pid;
	struct hlist_node list;
};

/*
	Device driver variables for the tracer linux kernel module
*/
dev_t dev = 0;
static struct class *dev_class;
static struct cdev etx_cdev;


/*
	Custom hashtable APIs for ease of use
*/

static int store_value(pid_t pid) 
{
	struct ht_entry *new_ht_entry;
	//hashtable insertion
	new_ht_entry = kmalloc(sizeof(struct ht_entry), GFP_KERNEL);

	if (new_ht_entry == NULL) {
		return -ENOMEM;
	}

	new_ht_entry->pid = pid;
	hash_add(pid_table, &new_ht_entry->list, new_ht_entry->pid);
	//hashtable insertion end

	return 0;
}

static struct ht_entry * ht_lookup(pid_t pid) {

	struct ht_entry *cur = NULL;

	hash_for_each_possible(pid_table, cur, list, pid) {

		if (cur->pid == pid) {

			return cur;
		}
	}

	return NULL;
}

static void del_value(pid_t pid)
{

	struct ht_entry *a = NULL;

	a = ht_lookup(pid);

	if (a) {

		hash_del(&a->list);
		kfree(a);
		
	}
}

static void destroy_hash_table_and_free(void)
{
	struct ht_entry *cur;
	unsigned int bk;

    hash_for_each(pid_table, bk, cur, list) {
        
		hash_del(&cur->list);
		kfree(cur);
    }
}

/*
** This fuction will be called when we open the Device file
*/
static int etx_open(struct inode *inode, struct file *file)
{
        printk(KERN_INFO "Device File Opened\n");
        return 0;
}
 
/*
** This fuction will be called when we close the Device file
*/
static int etx_release(struct inode *inode, struct file *file)
{
        printk(KERN_INFO "Device File Closed\n");
        return 0;
}
 
/*
** This fuction will be called when we read the Device file
*/
static ssize_t etx_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        printk(KERN_INFO "Read Function\n");
        return 0;
}
 
/*
** This fuction will be called when we write the Device file
*/
static ssize_t etx_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        printk(KERN_INFO "Write function\n");
        return 0;
}
 
/*
** This fuction will be called when we write IOCTL on the Device file
*/
static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	pid_t pp = current->pid;
	switch(cmd) 
	{
		case TRACER_REG:
				//copy_from_user(&value ,(int32_t*) arg, sizeof(value));
				store_value(pp);
				printk(KERN_INFO "Process with pid %d registered\n", pp);
				break;
		case TRACER_UNREG:
				//copy_to_user((int32_t*) arg, &value, sizeof(value));
				del_value(pp);
				printk(KERN_INFO "Process with pid %d removed\n", pp);
				break;
	}
	return 0;
}

static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = etx_read,
        .write          = etx_write,
        .open           = etx_open,
        .unlocked_ioctl = etx_ioctl,
        .release        = etx_release,
};
 

/* 
	kprobe pre_handler: called just before the probed instruction is executed 
*/
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{	
	struct ht_entry *a = NULL;
	pid_t pp = current->pid;

	a = ht_lookup(pp);

	if (a==NULL) {

		return 0;
	} else {

		printk(KERN_INFO "Syscall made by CoMpk process with pid: %d\n", a->pid);
	}

	return 0;
}

/* 
	kprobe post_handler: called after the probed instruction is executed 
*/
static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) 
{
	//pid_t pp = current->pid;
	//printk(KERN_INFO "Syscall allowed to PID: %d\n", pp);
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	//printk(KERN_INFO "faulty syscall\n");
	/* Return 0 because we don't handle the fault. */
	return 0;
}

/*
	This function adds probes to syscalls when the module is loaded
*/

static int addProbes(void) 
{
	unsigned i;
	int ret;

    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(sym_name);

	for(i=0; i<NUM_SYSCALLS; i++) {
		//kp.symbol_name = "pkey_mprotect";
		kp[i].addr=(kprobe_opcode_t *) sys_call_table[i];
		kp[i].pre_handler = handler_pre;
		kp[i].post_handler = handler_post;
		kp[i].fault_handler = handler_fault;

		ret = register_kprobe(&kp[i]);
		if (ret < 0) {
			printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
			return ret;
		}
		printk(KERN_INFO "Planted kprobe at %p\n", kp[i].addr);
	}

	return 0;
}

/*
	This function removes probes when the module is unloaded
*/
static void removeProbes(void)
{
	unsigned i;

	for(i = 0; i<NUM_SYSCALLS; i++) {

		unregister_kprobe(&kp[i]);
		printk(KERN_INFO "kprobe at %p unregistered\n", kp[i].addr);
	}
}

/*
	module init function
*/
static int __init kprobe_init(void)
{

	/*Allocating Major number*/
	if((alloc_chrdev_region(&dev, 0, 1, "etx_Dev")) <0){
			printk(KERN_INFO "Cannot allocate major number\n");
			return -1;
	}
	//printk(KERN_INFO "Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

	/*Creating cdev structure*/
	cdev_init(&etx_cdev,&fops);

	/*Adding character device to the system*/
	if((cdev_add(&etx_cdev,dev,1)) < 0){
		printk(KERN_INFO "Cannot add the device to the system\n");
		goto r_class;
	}

	/*Creating struct class*/
	if((dev_class = class_create(THIS_MODULE,"etx_class")) == NULL){
		printk(KERN_INFO "Cannot create the struct class\n");
		goto r_class;
	}

	/*Creating device*/
	if((device_create(dev_class,NULL,dev,NULL,"etx_device")) == NULL){
		printk(KERN_INFO "Cannot create the Device 1\n");
		goto r_device;
	}
	printk(KERN_INFO "Device Driver Insert\n");

	if (addProbes() < 0)
		return -1;

	return 0;

	r_device:
			class_destroy(dev_class);
	r_class:
			unregister_chrdev_region(dev,1);
			return -1;
}


/*
	Module exit function
*/
static void __exit kprobe_exit(void)
{

	printk(KERN_INFO "Destroying Device ... \n");
	device_destroy(dev_class,dev);
	class_destroy(dev_class);
	cdev_del(&etx_cdev);
	unregister_chrdev_region(dev, 1);

	printk(KERN_INFO "Freeing Hashtable ... \n");
	destroy_hash_table_and_free();

	printk(KERN_INFO "Removing Probes ... \n");
	removeProbes();

	printk(KERN_INFO "Module Removed!\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
