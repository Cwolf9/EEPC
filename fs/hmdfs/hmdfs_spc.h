/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.h
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#ifndef HMDFS_SPC_H
#define HMDFS_SPC_H

#include <asm/errno.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/uio.h>
#include <linux/namei.h> // kern_path

#include <net/sock.h>
#include <asm/socket.h>
#include <linux/sockptr.h>
#include <linux/un.h>
#include <linux/inet.h>

#include <linux/random.h>
#include <linux/sched/mm.h>

#include "hmdfs.h"

// (45 * 60)
#define WRITEBACK_EXPIRE_SECOND (3600)
// (100 * 1024 * 1024)
#define WRITEBACK_CACHE_SIZEB (524288000) 
// (1 * 60 * 60)
#define TIMER_EXPIRE_SECOND (3600)
#define CDNAME "/dev/hmtchadev"
#define PPCACHE_ROOT "hmdfs_pcache"
#define LOG_FILE "/data/service/el2/100/hmdfs/account/files/spc_logfile.txt"
#define LOCAL_SERVER_PORT (39001)
#define get_a_from_b_field_c(var, callback_timer, timer_fieldname) \
    container_of(callback_timer, typeof(*var), timer_fieldname)


enum FILE_CMD_EXT {
	F_STATUS_SYNC = 50, // 同步自己的状态
    F_STATUS_FORCE_CHANGE = 51, // 更新别人的状态
};



struct spc_peer {
    uint8_t state;
    uint32_t device_id;
    struct socket *sock;
    struct list_head spcp_node;
    char *ipaddr;
    unsigned short port;
    struct task_struct *caller;
    struct list_head sdr_list_head;
    uint32_t sdr_list_len;
    struct timer_list wb_timer;
    uint64_t hmdfs_device_id;

    struct mutex send_mutex;
    spinlock_t req_lock;
    struct rcu_head rcu;
};

struct spc_delayed_req {
    uint8_t type;
    uint32_t spc_did;
    void * req;
    struct list_head dreq_node;
    uint32_t hashval;
    // char * filedir;
    // char * filename;

    struct rcu_head rcu;
};

struct spc_head_cmd {
	__u8 magic;
	__le32 data_len;
	__le32 msg_id;
	__le32 reserved;
} __packed;

struct spc_send_data {
	void *head;
	size_t head_len;
    void *data;
	size_t data_len;
};



struct spc_status_sync_request {
	__u8 new_state;
} __packed;


typedef struct {
	char *taskd_name;
} Kthread_data;



extern struct hmdfs_sb_info *spc_sbi;
extern spinlock_t spc_peer_lock;
extern struct spc_peer local_peer;
extern struct list_head spc_peer_list_head;
extern uint32_t spc_peer_list_len;
extern struct timer_list net_timer;
extern struct timer_list scr_timer;
extern struct task_struct *comm_handler;
extern struct task_struct *cache_syncer;
extern int64_t delayed_req_size;
extern spinlock_t spc_log_lock;

int spc_local_init(void *sbi) ;
int spc_cross_device_connect(struct task_struct **comm_handler);
int spc_change_state_by_did_test(uint32_t d_id, int new_state) ;




#define out_string_macro_module "[spc_fix 0.10 module] "
#define spc_info(fmt, ...) \
	__hmdfs_log(KERN_INFO, false, __func__, out_string_macro_module fmt, ##__VA_ARGS__)
#define spc_warn(fmt, ...) \
	__hmdfs_log(KERN_INFO, false, __func__, out_string_macro_module fmt, ##__VA_ARGS__)
#define spc_err(fmt, ...) \
	__hmdfs_log(KERN_ERR, false, __func__, out_string_macro_module fmt, ##__VA_ARGS__)

#define CONFIG_SPC_DEBUG
#ifdef CONFIG_SPC_DEBUG
#define spc_debug(fmt, ...) \
	__hmdfs_log(KERN_INFO, false, __func__, out_string_macro_module fmt, ##__VA_ARGS__)
#else
#define spc_debug(fmt, ...)       ((void)0)
#endif

#endif // HMDFS_SPC_H