/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#ifndef HMDFS_DELEGATION_H
#define HMDFS_DELEGATION_H

#endif //HMDFS_DELEGATION_H

#define TMP_FILENAME_PREFIX ".goutputstream-"
#define TMP_FILENAME_PREFIX_LEN 15

#define DEL_EXPIRE_TIMEOUT_MSEC 30000

/*
 * HMDFS Delegation
 */
struct hmdfs_delegation {
    struct list_head super_list;
    uint64_t device_id;
    char *full_path;
    int is_tmp;
    unsigned long timeout;
    fmode_t permission;
    struct rcu_head rcu;
};

int hmdfs_check_delegated(struct hmdfs_peer *conn, struct file *file);

struct hmdfs_delegation *hmdfs_file_get_delegation(struct hmdfs_peer *conn, struct file *file);

struct hmdfs_delegation *hmdfs_file_alloc_delegation(struct hmdfs_peer *conn, struct file *file);

void hmdfs_file_release_tmp_delegations(struct hmdfs_peer *conn);

void hmdfs_file_release_device_delegations(struct hmdfs_peer *conn);