/*
Created by Cwolf9 on 2023.06.13 14:06.

*/

#include <asm/pgtable.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "hmdfs_test.h"

static char *cmd;
MODULE_PARM_DESC(cmd, "A string, ");
module_param(cmd, charp, 0000);

static int dst_pid = 0;
MODULE_PARM_DESC(dst_pid, "A int, ");
module_param(dst_pid, int, S_IRUGO);

static int chardev_open(struct inode *inode, struct file *file);
static int chardev_release(struct inode *inode, struct file *file);
static ssize_t chardev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
static ssize_t chardev_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
static loff_t chardev_lseek(struct file *f, loff_t off, int whence);
static long chardev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static long chardev_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

/*这里是char设备驱动的重头戏file_operations 是一个庞大的结构，汇聚内核中文件的操作，目前测试我们仅仅是测试open和release功能*/
static const struct file_operations char_fops = {
    .owner = THIS_MODULE,  // 代表当前模块
    .read = chardev_read,
    .write = chardev_write,
    .open = chardev_open,        // 应用程序open打开这个设备时实际调用
    .release = chardev_release,  // 与.open对应的函数
    .llseek = chardev_lseek,
    .unlocked_ioctl = chardev_ioctl,
    .compat_ioctl = chardev_compat_ioctl,
    // .compat_ioctl 32位的用户程序在64位的kernel上执行
};
#define NAME "hmtchadev"
// /dev/hmtchadev       cat /proc/devices

static struct cdev cdev;  // c -> char dev->device 字符设备的主要结构体
static struct class *chaclass;
static struct device *chadevice;
static dev_t devno;
static int major, minor, minor_num;
static unsigned char simple_inc = 0;
static unsigned char demoBuffer[1024];
static unsigned int tempui[F_SIZE];


// other file
extern void set_g_hmdfs_reqrecv(int id, int val) ;
extern int get_g_hmdfs_reqrecv(int id) ;
extern void set_g_hmdfs_send(int id, int val) ;
extern int get_g_hmdfs_send(int id) ;


extern int spc_client_init(char *localip) ;
extern int spc_status_sync_test(int cnt) ;
extern int spc_local_init(void *sbi) ;
extern int spc_local_exit(void) ;
extern int establish_connection_test(char *dst_ipaddr, unsigned short dst_port) ;
extern int spc_cat_peer_info_test(void) ;
extern int spc_change_state_by_did_test(uint32_t d_id, int new_state) ;
extern int sync_device_cache(int did, int clear) ;
extern void spc_client_attr_set(int flag, int a, int b, int c, int d) ;


// invalid command



static void help(void)
{
    hmdfs_info("help\n");
}

long chardev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int rc = 0;
	struct IOC_arg args_r = {123, 456, 0};
	struct IOC_arg args_w;
    char tempstr1[16];

    hmdfs_info("chardev_ioctl: cmd: %d, arg: %ld\n", cmd, arg);
	if (_IOC_TYPE(cmd) != CMD_IOC_MAGIC) {
		hmdfs_err("%s: command type [%c] error.\n", __func__, _IOC_TYPE(cmd));
		return -ENOTTY;
	}
	switch(cmd) {
		case CMD_IOC_0:
			rc = copy_to_user((char __user *)arg, &args_r, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_to_user failed: %d\n", __func__, rc);
				return rc;
			}
			hmdfs_info("0 CMD_IOC_0 read argi1 = %d, argi2 = %d\n", args_r.argi1, args_r.argi2);
			break;
		case CMD_IOC_1:
			rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
			hmdfs_info("1 CMD_IOC_1 write argi1 = %d, argi2 = %d\n", args_w.argi1, args_w.argi2);
			break;
        case CMD_IOC_10:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            memset(tempstr1, 0, sizeof(tempstr1));
            sprintf(tempstr1, "%pI4", &args_w.argi1);
            rc = spc_client_init(tempstr1);

            hmdfs_info("10 spc_client_init: %d, a1: %d %s, \n", rc, args_w.argi1, tempstr1);
            break;
        case CMD_IOC_11:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            rc = spc_local_exit();

            hmdfs_info("11 spc_local_exit: %d\n", rc);
            break;
        case CMD_IOC_12:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            rc = spc_local_init(NULL);

            hmdfs_info("12 spc_local_init: %d\n", rc);
            break;
        case CMD_IOC_20: // hmdfs_reqrecv_r
            tempui[F_READPAGE] = get_g_hmdfs_reqrecv(F_READPAGE);
            tempui[F_WRITEPAGE] = get_g_hmdfs_reqrecv(F_WRITEPAGE);
            tempui[F_ITERATE] = get_g_hmdfs_reqrecv(F_ITERATE);
            tempui[F_GETATTR] = get_g_hmdfs_reqrecv(F_GETATTR);

            tempui[F_SETATTR] = get_g_hmdfs_reqrecv(F_SETATTR);
            tempui[F_READPAGES] = get_g_hmdfs_reqrecv(F_READPAGES);
            tempui[F_CPC_ATTR] = get_g_hmdfs_reqrecv(F_CPC_ATTR);
            args_r.argi1 = tempui[F_READPAGE];
            args_r.argi2 = tempui[F_WRITEPAGE];
            args_r.argi3 = tempui[F_ITERATE];
            args_r.argi4 = tempui[F_GETATTR];
            args_r.argi5 = tempui[F_SETATTR];

			hmdfs_info("20 CMD_IOC_20 readp: %u, writep: %u, iter: %u, geta: %u, seta: %u, rdpgs: %u, cpca: %u \n", 
                tempui[F_READPAGE], tempui[F_WRITEPAGE], tempui[F_ITERATE], tempui[F_GETATTR], tempui[F_SETATTR], tempui[F_READPAGES], tempui[F_CPC_ATTR]);
			
            rc = copy_to_user((char __user *)arg, &args_r, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_to_user failed: %d\n", __func__, rc);
				return rc;
			}
            break;
        case CMD_IOC_21: // hmdfs_reqrecv_c
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            set_g_hmdfs_reqrecv(F_READPAGE, 0);
            set_g_hmdfs_reqrecv(F_WRITEPAGE, 0);
            set_g_hmdfs_reqrecv(F_ITERATE, 0);
            set_g_hmdfs_reqrecv(F_GETATTR, 0);

            set_g_hmdfs_reqrecv(F_SETATTR, 0);
            set_g_hmdfs_reqrecv(F_READPAGES, 0);
            set_g_hmdfs_reqrecv(F_CPC_ATTR, 0);
            rc = 0;
			hmdfs_info("21 CMD_IOC_21 clear count: %d\n", rc);
			break;
        case CMD_IOC_22: // hmdfs_reqsend_r
            tempui[F_READPAGE] = get_g_hmdfs_send(F_READPAGE);
            tempui[F_WRITEPAGE] = get_g_hmdfs_send(F_WRITEPAGE);
            tempui[F_ITERATE] = get_g_hmdfs_send(F_ITERATE);
            tempui[F_GETATTR] = get_g_hmdfs_send(F_GETATTR);

            tempui[F_SETATTR] = get_g_hmdfs_send(F_SETATTR);
            tempui[F_READPAGES] = get_g_hmdfs_send(F_READPAGES);
            tempui[F_CPC_ATTR] = get_g_hmdfs_send(F_CPC_ATTR);
            args_r.argi1 = tempui[F_READPAGE];
            args_r.argi2 = tempui[F_WRITEPAGE];
            args_r.argi3 = tempui[F_ITERATE];
            args_r.argi4 = tempui[F_GETATTR];
            args_r.argi5 = tempui[F_SETATTR];

			hmdfs_info("22 CMD_IOC_22 readp: %u, writep: %u, iter: %u, geta: %u, seta: %u, rdpgs: %u, cpca: %u \n", 
                tempui[F_READPAGE], tempui[F_WRITEPAGE], tempui[F_ITERATE], tempui[F_GETATTR], tempui[F_SETATTR], tempui[F_READPAGES], tempui[F_CPC_ATTR]);
			
            rc = copy_to_user((char __user *)arg, &args_r, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_to_user failed: %d\n", __func__, rc);
				return rc;
			}
            break;
        case CMD_IOC_23: // hmdfs_reqsend_c
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            set_g_hmdfs_send(F_READPAGE, 0);
            set_g_hmdfs_send(F_WRITEPAGE, 0);
            set_g_hmdfs_send(F_ITERATE, 0);
            set_g_hmdfs_send(F_GETATTR, 0);

            set_g_hmdfs_send(F_SETATTR, 0);
            set_g_hmdfs_send(F_READPAGES, 0);
            set_g_hmdfs_send(F_CPC_ATTR, 0);
            rc = 0;
			hmdfs_info("23 CMD_IOC_23 clear count: %d\n", rc);
			break;
        case CMD_IOC_30:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            hmdfs_info("30 begin\n");
            rc = spc_status_sync_test(args_w.argi1);
            hmdfs_info("30 spc_status_sync_test, ret: %d, a1: %d \n", rc, args_w.argi1);
            break;
        case CMD_IOC_31:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            memset(tempstr1, 0, sizeof(tempstr1));
            sprintf(tempstr1, "%pI4", &args_w.argi1);
            rc = establish_connection_test(tempstr1, args_w.argi2);
            hmdfs_info("31 establish_connection_test: %d, a1: %d %s, a2: %d\n", rc, args_w.argi1, tempstr1, args_w.argi2);
            break;
        case CMD_IOC_32:
            args_r.argi1 = spc_cat_peer_info_test();
			rc = copy_to_user((char __user *)arg, &args_r, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_to_user failed: %d\n", __func__, rc);
				return rc;
			}
            rc = args_r.argi1;
			hmdfs_info("32 spc_cat_peer_info_test ret: %d\n", args_r.argi1);
			break;
        case CMD_IOC_33:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            rc = spc_change_state_by_did_test(args_w.argi1, args_w.argi2);
            hmdfs_info("33 spc_change_state_by_did_test ret: %d, a1: %d, a2: %d \n", rc, args_w.argi1, args_w.argi2);
            break;
        case CMD_IOC_34:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            rc = sync_device_cache(args_w.argi1, 0);
            hmdfs_info("34 sync_device_cache ret: %d, a1: %d\n", rc, args_w.argi1);
            break;
        case CMD_IOC_35:
            rc = copy_from_user(&args_w, (char __user *)arg, sizeof(struct IOC_arg));
			if (rc) {
				hmdfs_err("%s: copy_from_user failed: %d\n", __func__, rc);
				return rc;
			}
            spc_client_attr_set(args_w.argi1, args_w.argi2, args_w.argi3, args_w.argi4, args_w.argi5);
            hmdfs_info("35 spc_client_attr_set args: %d %d %d %d %d\n", args_w.argi1, args_w.argi2, args_w.argi3, args_w.argi4, args_w.argi5);
            break;


		default:
            help();
			hmdfs_err("%s: invalid command\n", __func__);
			return -ENOTTY;
	}
	return rc;
}
long chardev_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    // hmdfs_info("chardev_compat_ioctl\n");
    return chardev_ioctl(filp, cmd, (unsigned long)compat_ptr((void __user *)arg));
}
/*
ioctl() 地址传参 用户态和内核态 https://blog.csdn.net/baidu_38797690/article/details/123714431
ioctl() 源码地址: https://blog.csdn.net/weixin_42857944/article/details/127725150


_IO _IOR _IOW _IORW
cmd 的大小为 32位，共分 4 个域
    bit31~bit30  2位为 “区别读写” 区，作用是区分是读取命令还是写入命令。
    bit29~bit16 14位为 "数据大小" 区，表示 ioctl() 中的 arg 变量传送的内存大小。
    bit15~bit08  8位为 “魔数"(也称为"幻数")区，这个值用以与其它设备驱动程序的 ioctl 命令进行区别。
    bit07~bit00  8位为 "区别序号" 区，是区分命令的命令顺序序号。
_IO (魔数, 区别序号);
_IOR (魔数, 区别序号, 变量型=数据大小)
_IOW (魔数, 区别序号, 变量型=数据大小)
_IOWR (魔数, 区别序号, 变量型=数据大小)

#define _IOC_NRSHIFT    0
_IOC_TYPESHIFT = 8
_IOC_SIZESHIFT = 16
_IOC_DIRSHIFT = 30

CMD：
    30-31 bit: dir：ioctl命令访问模式，制定数据传输方向；
    16-29 bit: size：如果命令带参数，则制定参数所占用的内存空间大小；
    08-15 bit: type：设备类型，也叫幻数，代表一种设备，一般用一个字母或者8bit数字表示；
    00-07 bit: nr：命令编号，代表设备的第几个命令。
2.1 置位_IO宏
（1）_IO(type, nr)：创建不带参数cmd，只传输命令；
（2）_IOR(type, nr, size)：创建从设备读取数据cmd；
（3）_IOW(type, nr, size)：创建向设备写入数据cmd；
（4） _IOWR(type, nr, size)：创建双向传输数据cmd；
2.2 取位_IO宏
（1）_IOC_DIR(cmd)：检查cmd读写属性；
（2）_IOC_TYPE(cmd)：检查cmd设备类型（幻数）；
（3）_IOC_NR(cmd)：检查cmd命令编号；
（4）_IOC_SIZE(cmd)：检查cmd传输数据大小。
access_ok(type, addr, size)
    检查用户空间地址是否是可用，通常在进行数据传输之前使用。
    输入参数：
        type：访问类型，其值可以是VERIFY_READ或者VERIFY_WRITE；
        addr：用户空间的指针变量，指向一个要检查的内存块的开始处；
        size：要检查的内存块大小。

*/

int mycdev_setup(void)
{
    int ret = 0;
    minor_num = 1;
    // MKDEV宏能将主次设备号放在一个32位的变量中，变成一个编号. 高12位 低12位
    devno = MKDEV(major, minor);
    /* 注册字符设备 */
    ret = alloc_chrdev_region(&devno, 0, 1, NAME);
    if (ret < 0) {
        hmdfs_err("register_chrdev error ...\n");
        return -EINVAL;
    }
    cdev_init(&cdev, &char_fops);  //将 char_fops 放到cdev结构体中
    cdev.owner = THIS_MODULE;
    //将设备号再放到cdev结构体中， 1代表子设备数量1个
    ret = cdev_add(&cdev, devno, minor_num);
    if (ret < 0) {
        hmdfs_err("cdev_add error ...\n");
        return -EINVAL;
    }
    major = MAJOR(devno);
    minor = MINOR(devno);
    hmdfs_info("register_chrdev OK ... major = %d, minor = %d.\n", major, minor);
    return ret;
}

int mycdev_create(void)
{
    int ret = 0;
    // 创建类
    chaclass = class_create(THIS_MODULE, NAME);
    if (IS_ERR_OR_NULL(chaclass)) {
        hmdfs_err("Error: class_create\n");
        return -1;
    }
    // 创建设备
    // 类 父设备 设备号 数据 设备名称
    chadevice = device_create(chaclass, NULL, devno, NULL, NAME);
    if (IS_ERR_OR_NULL(chadevice)) {
        hmdfs_err("Error: device_create\n");
        return -1;
    }
    return ret;
}

/*
创建字符设备
https://www.cnblogs.com/salvare/p/8395066.html
https://blog.csdn.net/qq_33216792/article/details/126216115

设备类 struct class 设备文件
https://blog.csdn.net/weixin_42031299/article/details/124566329
https://blog.csdn.net/weixin_42031299/article/details/124700063
https://blog.csdn.net/weixin_45905650/article/details/121572485
https://blog.csdn.net/zqixiao_09/article/details/50849735


major = register_chrdev_region(0, NAME, &char_fops);

*/
static int __init chardev_init(void)
{
    int ret;
    hmdfs_info("hmdfs_test chardev_init, [trace] pid:%d ,c->comm:%s\n", current->pid, current->comm);
    hmdfs_info("hmdfs_test chardev_init, \n");
    // 初始化设备号及注册设备到内核
    ret = mycdev_setup();
    if (ret < 0) {
        hmdfs_err("hmdfs_test chardev_init, mycdev_setup err: %d\n", ret);
        return 0;
    }
    // 手动创建设备文件
    hmdfs_info("sudo mknod /dev/hmtchadev c %d %d\n", major, minor);
    hmdfs_info("自动创建设备文件\n");
    // 自动创建设备文件 <linux/device.h>
    // 首先, 在模块初始化代码里调用 class_create宏 为设备在 /sys/class 下创建一个class，再调用 device_create函数 创建对应的设备文件
    // 最后, 在模块的清除函数中还需调用 device_destroy 以及 class_destroy 来进行清除不再使用的文件节点和设备文件。
    ret = mycdev_create();
    if (ret < 0) {
        hmdfs_err("hmdfs_test chardev_init, mycdev_create err: %d\n", ret);
        return 0;
    }
    hmdfs_warn("###### func over! %s: %d.\n\n", __func__, __LINE__);
    return 0;
}

// 模块卸载
static void __exit chardev_exit(void)
{
    hmdfs_info("hmdfs_test chardev_exit, [trace] pid:%d ,c->comm:%s\n", current->pid, current->comm);
    hmdfs_info("hmdfs_test chardev_exit, \n");

    cdev_del(&cdev);
    unregister_chrdev_region(devno, minor_num);
    if (IS_ERR_OR_NULL(chaclass)) {
        if (IS_ERR_OR_NULL(chadevice)) {
            // 摧毁设备
            device_destroy(chaclass, devno);
        }
        // 摧毁类
        class_destroy(chaclass);
    }
    hmdfs_warn("###### func over! %s: %d.\n\n", __func__, __LINE__);
}
/*
Makefile注意：若不添加CONFIG_MODULE_SIG=n，有可能会出现加载内核模块后签名错误，然后创建设备失败。
Linux中使用struct miscdevice来描述一个混杂设备 https://blog.csdn.net/github_38294679/article/details/122170681

*/

static int chardev_open(struct inode *inode, struct file *file)
{
    /*在此文中我们先不操作硬件用打印函数先来验证结构的有效性*/
    ++ simple_inc;
    // hmdfs_info("Evaluation_Overhead_lat: chardev_open: %u, cpid: %d ...\n", simple_inc, current->pid);
    return 0;
}

static int chardev_release(struct inode *inode, struct file *file)
{
    -- simple_inc;
    // hmdfs_debug("chardev_release: counter: %u ...\n", simple_inc);
    return 0;
}

static loff_t chardev_lseek(struct file *f, loff_t off, int whence)
{
    // hmdfs_debug("chardev_lseek: END=CUR ...\n");
    switch (whence) {
        case SEEK_SET:
            f->f_pos = off;  //文件开始位置是0
            break;
        case SEEK_CUR:
            f->f_pos += off;
            break;
        case SEEK_END:
            f->f_pos += off;
        default:
            break;
    }
    return f->f_pos;
}

ssize_t chardev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    // hmdfs_debug("chardev_read ...\n");
    /* 把数据复制到应用程序空间 */
    if (copy_to_user(buf, demoBuffer + *f_pos, count)) {
        count = -EFAULT;
    }else {
        *f_pos += count;
    }
    return count;
}

ssize_t chardev_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    // hmdfs_debug("chardev_write ...\n");
    /* 把数据复制到内核空间 */
    if (copy_from_user(demoBuffer + *f_pos, buf, count)) {
        count = -EFAULT;
    }else {
        *f_pos += count;
    }
    return count;
}

module_init(chardev_init);
module_exit(chardev_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("XX");
MODULE_DESCRIPTION("task virtualization_test");
// MODULE_INFO(intree, "Y");
