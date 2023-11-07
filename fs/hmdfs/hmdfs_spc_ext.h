/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#ifndef HMDFS_SPC_EXT_H
#define HMDFS_SPC_EXT_H

#include "hmdfs_device_view.h"

// hmdfs_client_writepage hmdfs_remote_writepage_retry hmdfs_writepage_cb hmdfs_writepage_remote
struct spc_client_writepage_request {
    uint64_t initiate_jif;
    // 过去记录下层请求 (struct hmdfs_peer *con, struct hmdfs_writepage_context *param)
    // void *con;
    // void *param;
    // 现在记录上层请求
    char *filepath; // 记得释放
    // struct page *page;
    char *buf;
    loff_t pos;
    uint32_t count;
    // struct rcu_head rcu;
} __packed;

struct spc_client_getattr_request {
    uint32_t spc_did;
    char *send_buf;
    unsigned int lookup_flags;
    struct hmdfs_getattr_ret attr;
    struct list_head req_node;
} __packed;

struct spc_request_info {
    uint64_t i_ino;
} ;


int get_local_device_state(void) ;
int get_file_device_state(struct file *filp, struct hmdfs_inode_info *iinfo, struct hmdfs_peer *con, uint32_t *res) ;
void spc_network_transceive(int msg_id, int sr, struct spc_request_info *sri) ;
void spc_wakeup_screen(void) ;
int spc_capture_client_request(uint32_t spc_did, int msg_id, void *vreq) ;
int spc_getattr(uint32_t spc_did, char *send_buf, unsigned int lookup_flags, struct hmdfs_getattr_ret *attr) ;
int spc_record_getattr(uint32_t spc_did, char *send_buf, unsigned int lookup_flags, struct hmdfs_getattr_ret *attr) ;
int spc_delay_setattr(uint32_t spc_did, char *send_buf, struct setattr_info *ssi) ;

extern struct list_head getattr_req_list_head;
extern int spc_coverage;

#endif // HMDFS_SPC_EXT_H