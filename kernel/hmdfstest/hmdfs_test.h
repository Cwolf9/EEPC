#include <linux/ioctl.h>

#define CDNAME "/dev/hmtchadev"
#define out_string_macro_module "[spc_fix 0.10 test] "
#define hmdfs_info(fmt, ...) \
	printk(KERN_INFO out_string_macro_module fmt, ##__VA_ARGS__)
#define hmdfs_warn(fmt, ...) \
	printk(KERN_WARNING out_string_macro_module fmt, ##__VA_ARGS__)
#define hmdfs_err(fmt, ...) \
	printk(KERN_ERR out_string_macro_module fmt, ##__VA_ARGS__)

typedef struct IOC_arg {
	int	argi1;
	int argi2;
	int argi3;
	int argi4;
	int argi5;
}IOC_args;

#define CMD_IOC_MAGIC	'c'
#define CMD_IOC_0		_IOR(CMD_IOC_MAGIC, 0, struct IOC_arg)
#define CMD_IOC_1		_IOW(CMD_IOC_MAGIC, 1, struct IOC_arg)
// client side
#define CMD_IOC_10		_IOW(CMD_IOC_MAGIC, 10, struct IOC_arg)
#define CMD_IOC_11		_IOW(CMD_IOC_MAGIC, 11, struct IOC_arg)
#define CMD_IOC_12		_IOW(CMD_IOC_MAGIC, 12, struct IOC_arg)

// server side
#define CMD_IOC_20		_IOR(CMD_IOC_MAGIC, 20, struct IOC_arg)
#define CMD_IOC_21		_IOW(CMD_IOC_MAGIC, 21, struct IOC_arg)
#define CMD_IOC_22		_IOR(CMD_IOC_MAGIC, 22, struct IOC_arg)
#define CMD_IOC_23		_IOW(CMD_IOC_MAGIC, 23, struct IOC_arg)

#define CMD_IOC_30		_IOW(CMD_IOC_MAGIC, 30, struct IOC_arg)
#define CMD_IOC_31		_IOW(CMD_IOC_MAGIC, 31, struct IOC_arg)
#define CMD_IOC_32		_IOR(CMD_IOC_MAGIC, 32, struct IOC_arg)
#define CMD_IOC_33		_IOW(CMD_IOC_MAGIC, 33, struct IOC_arg)
#define CMD_IOC_34		_IOW(CMD_IOC_MAGIC, 34, struct IOC_arg)
#define CMD_IOC_35		_IOW(CMD_IOC_MAGIC, 35, struct IOC_arg)


enum CMD_FLAG { C_REQUEST = 0, C_RESPONSE = 1, C_FLAG_SIZE };

enum FILE_CMD {
	F_OPEN = 0,
	F_RELEASE = 1,
	F_READPAGE = 2,
	F_WRITEPAGE = 3,
	F_ITERATE = 4,
	F_RESERVED_1 = 5,
	F_RESERVED_2 = 6,
	F_RESERVED_3 = 7,
	F_RESERVED_4 = 8,
	F_MKDIR = 9,
	F_RMDIR = 10,
	F_CREATE = 11,
	F_UNLINK = 12,
	F_RENAME = 13,
	F_SETATTR = 14,
	F_RESERVED_5 = 15,
	F_STATFS = 16,
	F_CONNECT_REKEY = 17,
	F_DROP_PUSH = 18,
	F_RESERVED_0 = 19,
	F_GETATTR = 20,
	F_FSYNC = 21,
	F_SYNCFS = 22,
	F_GETXATTR = 23,
	F_SETXATTR = 24,
	F_LISTXATTR = 25,
	F_READPAGES = 26,
	F_READPAGES_OPEN = 27,
	F_ATOMIC_OPEN = 28,
	// spc fix: F_CPC_ATTR
	F_CPC_ATTR = 29,
	F_SIZE,
};


/*
#define pr_emerg(fmt, ...) \
	printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert(fmt, ...) \
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_notice(fmt, ...) \
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
*/