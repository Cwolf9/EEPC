/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagevec.h>

#include "hmdfs.h"
#include "hmdfs_tool.h"
#include "client_writeback.h"

char *get_full_path(struct path *path)
{
    char *buf, *tmp;
    char *ret = NULL;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return ret;

    tmp = d_path(path, buf, PATH_MAX);
    if (IS_ERR(tmp))
        goto out;

    ret = kstrdup(tmp, GFP_KERNEL);
out:
    kfree(buf);
    return ret;
}

int check_path(char *full_path) {
    struct path path;
    int not_exist = 0;

    not_exist = kern_path(full_path, 0, &path);

    if (not_exist == 0) {
        path_put(&path);
        return 1;
    } else {
        return 0;
    }
}

int check_and_mkdir(char *full_path) {
    int err = 0;
    struct path path;
    struct dentry *child_dentry = NULL;

    if (!check_path(full_path)) {
        child_dentry = kern_path_create(AT_FDCWD, full_path, &path, LOOKUP_DIRECTORY);
        if (IS_ERR(child_dentry)) {
            hmdfs_err("----- kern_path_create failed! -----");
            path_put(&path);
            return 0;
        }
        err = vfs_mkdir(d_inode(path.dentry), child_dentry, 0775);
        if (err) {
            hmdfs_err("----- mkdir failed! -----");
            done_path_create(&path, child_dentry);
            return 0;
        }
        done_path_create(&path, child_dentry);
        return 1;
    } else {
        // hmdfs_debug("----- dir is existed: %s -----", full_path);
        return 1;
    }
}

int check_and_create(char *full_path) {
    int err = 0;
    struct path path;
    struct dentry *child_dentry = NULL;

    if (!check_path(full_path)) {
        child_dentry = kern_path_create(AT_FDCWD, full_path, &path, 0);
        if (IS_ERR(child_dentry)) {
            hmdfs_debug("----- create failed -----");
            path_put(&path);
            return 0;
        }
        err = vfs_create(d_inode(path.dentry), child_dentry, 0100664, true);
        if (err) {
            hmdfs_err("path create failed! err=%d", err);
            done_path_create(&path, child_dentry);
            return 0;
        }
        done_path_create(&path, child_dentry);
        return 1;
    } else {
        hmdfs_debug("----- file is existed: %s -----", full_path);
        return 0;
    }
}

int get_list_len(struct list_head *list) {
    struct list_head *tmp = list;
    int count = 0;
    while (tmp->next != list) {
        count++;
        tmp = tmp->next;
    }
    return count;
}

struct list_head *get_list_node_n(struct list_head *list, int n) {
    struct list_head *tmp = list;
    int i;
    for (i = 1; i <= n; i++) {
        tmp = tmp->next;
    }
    return tmp;
}

struct hmdfs_inode_info *get_inode_info_n(struct list_head *list, int n) {
    return list_entry(get_list_node_n(list, n), struct hmdfs_inode_info, wb_list);
}

unsigned long hmdfs_idirty_pages(struct inode *inode, int tag)
{
    struct pagevec pvec;
    unsigned long nr_dirty_pages = 0;
    pgoff_t index = 0;

#if KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE
    pagevec_init(&pvec);
#else
    pagevec_init(&pvec, 0);
#endif
    // 5error:
    while (pagevec_lookup_tag(&pvec, inode->i_mapping, &index, tag)) {
        nr_dirty_pages += pagevec_count(&pvec);
        pagevec_release(&pvec);
        cond_resched();
    }
    return nr_dirty_pages;
}
// -1 优先
int compare_inode_info(struct hmdfs_inode_info *a, struct hmdfs_inode_info *b) {
    struct inode *a_inode = &a->vfs_inode;
    struct inode *b_inode = &b->vfs_inode;
    unsigned long dirty_a = hmdfs_idirty_pages(a_inode, PAGECACHE_TAG_DIRTY);
    unsigned long dirty_b = hmdfs_idirty_pages(b_inode, PAGECACHE_TAG_DIRTY);
    // 5error:
    struct timespec64 cts;
    long t_a, t_b;
    long delta = 24000;

    jiffies_to_timespec64(jiffies, &cts);
    t_a = cts.tv_nsec - a_inode->i_mtime.tv_nsec;
    t_b = cts.tv_nsec - b_inode->i_mtime.tv_nsec;
    if(cts.tv_sec - a->ab_fre_ts.tv_sec > 10 * 60) a->ab_frequency = 0;
    if(cts.tv_sec - b->ab_fre_ts.tv_sec > 10 * 60) b->ab_frequency = 0;
    if(cts.tv_sec % 600 == 0 && cts.tv_nsec < 100 * 1000 * 1000) a->latest_wb_times = 0, b->latest_wb_times = 0;

    if (t_a <= delta && t_b <= delta) {
        if(a->ab_frequency > 3 || b->ab_frequency > 3) {
            if (a->ab_frequency < b->ab_frequency) return -1;
            else if (a->ab_frequency == b->ab_frequency) return 0;
            else return 1;
        }else if(a->ab_frequency > 3) return -1;
        else if(b->ab_frequency > 3) return 1;

        if (dirty_a < dirty_b) {
            return -1;
        } else if (dirty_a == dirty_b) {
            if(a->latest_wb_times > 10 || b->latest_wb_times > 10) {
                if (a->latest_wb_times < b->latest_wb_times) return -1;
                else if (a->latest_wb_times == b->latest_wb_times) return 0;
                else return 1;
            }else if(a->latest_wb_times > 10) return -1;
            else if(b->latest_wb_times > 10) return 1;

            if(a->file_wb_type < b->file_wb_type) return -1;
            else if(a->file_wb_type > b->file_wb_type) return 1;
            return 0;
        } else {
            return 1;
        }
    } else if (t_a > delta && t_b <= delta) {
        return -1;
    } else if (t_a <= delta && t_b > delta) {
        return -1;
    } else {
        if (t_a < t_b) {
            return 1;
        } else if (t_a == t_b) {
            return 0;
        } else {
            return -1;
        }
    }
}

void swap_list_node(struct list_head *list, int a, int b) {
    struct list_head *a_node = get_list_node_n(list, a);
    struct list_head *b_node = get_list_node_n(list, b);
    struct list_head tmp = {NULL, NULL};
    list_add_tail(&tmp, b_node);
    list_del(b_node);
    list_add_tail(b_node, a_node);
    list_del(a_node);
    list_add_tail(a_node, &tmp);
    list_del(&tmp);
}

int get_partition(struct list_head *list, int low, int high) {
    struct hmdfs_inode_info *tmp_info = NULL;
    struct hmdfs_inode_info *pivot_info = get_inode_info_n(list, low);
    while (low < high) {
        tmp_info = get_inode_info_n(list, high);
        while (low < high && compare_inode_info(tmp_info, pivot_info) >= 0) {
            high--;
            tmp_info = get_inode_info_n(list, high);
        }
        if (low != high) {
            swap_list_node(list, low, high);
        }
        tmp_info = get_inode_info_n(list, low);
        while (low < high && compare_inode_info(tmp_info, pivot_info) <= 0) {
            low++;
            tmp_info = get_inode_info_n(list, low);
        }
        if (low != high) {
            swap_list_node(list, high, low);
        }
    }
    return low;
}

void quick_sort(struct list_head *list, int low, int high) {
    int pivot;
    if (low < high) {
        pivot = get_partition(list, low, high);
        quick_sort(list, low, pivot - 1);
        quick_sort(list, pivot + 1, high);
    }
}

void writeback_sort(struct hmdfs_writeback *hwb) {
    if (!list_empty(&hwb->inode_list_head)) {
        quick_sort(&hwb->inode_list_head, 1, get_list_len(&hwb->inode_list_head));
    }
}

struct hmdfs_inode_info *get_info_insert_pos(struct hmdfs_inode_info *info, struct hmdfs_writeback *hwb) {
    struct hmdfs_inode_info *tmp = NULL;
    struct hmdfs_inode_info *ret = NULL;
    if (!list_empty(&hwb->inode_list_head)) {
        list_for_each_entry(tmp, &hwb->inode_list_head, wb_list) {
            if (compare_inode_info(info, tmp) <= 0){
                ret = tmp;
                break;
            }
        }
    }
    return ret;
}