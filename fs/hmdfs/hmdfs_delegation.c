/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/jffs2.h>

#include "hmdfs.h"
#include "inode.h"
#include "comm/connection.h"
#include "hmdfs_tool.h"
#include "hmdfs_delegation.h"
#include "hmdfs_server.h"

int hmdfs_check_delegated(struct hmdfs_peer *conn, struct file *file) {
    struct hmdfs_delegation *delegation;
    struct hmdfs_sb_info *sbi = conn->sbi;
    char *full_path = get_full_path(&file->f_path);
    int ret = 0;
    //int loop = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(delegation, &sbi->delegations, super_list) {
        //hmdfs_debug("----- looping for %d time(s), finding for file %s -----", ++loop, full_path);
        if (!strcmp(delegation->full_path, full_path) &&
                (delegation->permission == (FMODE_READ | FMODE_WRITE)) &&
                delegation->device_id != conn->device_id &&
                time_after(delegation->timeout, jiffies)) {
            //hmdfs_debug("----- time_after_eq: %d, current = %lu, timeout = %lu -----", time_after_eq(delegation->timeout, jiffies), jiffies, delegation->timeout);
            // hmdfs_debug("----- write permission has been handed over to device %llu for file %s -----", delegation->device_id, full_path);
            ret = 1;
            break;
        }
    }
    rcu_read_unlock();

    // hmdfs_debug("----- write permission is now available for file %s -----", full_path);

    return ret;
}

struct hmdfs_delegation *hmdfs_file_get_delegation(struct hmdfs_peer *conn, struct file *file) {
    struct hmdfs_delegation *delegation;
    struct hmdfs_delegation *ret = NULL;
    struct hmdfs_sb_info *sbi = conn->sbi;
    char *full_path = get_full_path(&file->f_path);
    //int loop = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(delegation, &sbi->delegations, super_list) {
        //hmdfs_debug("----- looping for %d time(s), finding for device_id = %llu and %s -----", ++loop, conn->device_id, full_path);
        if (delegation->device_id == conn->device_id && !strcmp(delegation->full_path, full_path)) {
            // hmdfs_debug("----- delegation found at %p -----", delegation);
            if (hmdfs_check_delegated(conn, file)) {
                delegation->permission = FMODE_READ;
            } else {
                delegation->permission = (FMODE_READ | FMODE_WRITE);
                delegation->timeout = jiffies + msecs_to_jiffies(DEL_EXPIRE_TIMEOUT_MSEC);
            }
            ret = delegation;
            break;
        }
    }
    rcu_read_unlock();

    // hmdfs_debug("----- no delegation found -----");
    return ret;
}

struct hmdfs_delegation *hmdfs_file_alloc_delegation(struct hmdfs_peer *conn, struct file *file) {
    struct hmdfs_delegation *delegation;
    struct hmdfs_sb_info *sbi = conn->sbi;
    char *filename = NULL;

    filename = kstrdup(file->f_path.dentry->d_name.name, GFP_KERNEL);

    delegation = kmalloc(sizeof(*delegation), GFP_NOFS);
    delegation->device_id = conn->device_id;
    delegation->full_path = get_full_path(&file->f_path);

    // hmdfs_debug("----- file->f_path.dentry->d_name.name is %s -----", filename);
    if (!strncmp(filename, TMP_FILENAME_PREFIX, TMP_FILENAME_PREFIX_LEN)) {
        // hmdfs_debug("----- Allocated Delegation for device %llu for tmp file %s and SKIP -----", conn->device_id, filename);
        delegation->is_tmp = 1;
    } else {
        // hmdfs_debug("----- Allocated Delegation for device %llu for file %s at %p -----", conn->device_id, delegation->full_path, delegation);
        delegation->is_tmp = 0;
    }

    delegation->timeout = jiffies + msecs_to_jiffies(DEL_EXPIRE_TIMEOUT_MSEC);

    if (hmdfs_check_delegated(conn, file)) {
        delegation->permission = FMODE_READ;
    } else {
        delegation->permission = (FMODE_READ | FMODE_WRITE);
    }

    list_add_tail_rcu(&delegation->super_list, &sbi->delegations);

    return delegation;
}

void hmdfs_file_release_tmp_delegations(struct hmdfs_peer *conn) {
    struct hmdfs_delegation *delegation;
    struct hmdfs_sb_info *sbi = conn->sbi;

    rcu_read_lock();
    list_for_each_entry_rcu(delegation, &sbi->delegations, super_list) {
        if (delegation->is_tmp ||
                (delegation->permission == FMODE_READ) ||
                time_before_eq(delegation->timeout, jiffies)) {
            //hmdfs_debug("----- time_after_eq: %d, current = %lu, timeout = %lu -----", time_after_eq(delegation->timeout, jiffies), jiffies, delegation->timeout);
            // hmdfs_debug("----- tmp delegation found at %p for file %s used by device %llu -----", delegation, delegation->full_path, delegation->device_id);
            list_del_rcu(&delegation->super_list);
        }
    }
    rcu_read_unlock();
}

void hmdfs_file_release_device_delegations(struct hmdfs_peer *conn) {
    struct hmdfs_delegation *delegation;
    struct hmdfs_sb_info *sbi = conn->sbi;

    rcu_read_lock();
    list_for_each_entry_rcu(delegation, &sbi->delegations, super_list) {
        if (delegation->device_id == conn->device_id) {
            // hmdfs_debug("----- device delegation found at %p for file %s used by device %llu -----", delegation, delegation->full_path, delegation->device_id);
            list_del_rcu(&delegation->super_list);
        }
    }
    rcu_read_unlock();
}