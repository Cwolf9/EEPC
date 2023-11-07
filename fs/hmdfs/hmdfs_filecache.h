/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#ifndef HMDFS_FILECACHE_H
#define HMDFS_FILECACHE_H

#endif //HMDFS_FILECACHE_H

#define PCACHE_ROOT "hmdfs_pcache"

//struct hmdfs_pcache_ctx {
//    struct dir_context ctx;
//    struct hmdfs_sb_info *sbi;
//    struct path *parent_path;
//};

struct pcache_file_info {
    struct list_head super_list;
    __u64 file_ver;
    __u32 file_id;
    struct file *file;
    char *device_view_path;
    char *pcache_full_path;
    loff_t size;
    int need_truncate;
    unsigned long *pg_index_bitmap;
    struct rcu_head rcu;
};

int hmdfs_init_pcache(struct hmdfs_sb_info *sbi);

int hmdfs_set_pcache_truncate(struct hmdfs_sb_info *sbi, struct file *file);

int hmdfs_page_pcache(struct hmdfs_sb_info *sbi, struct file *file, __u64 file_ver, __u32 file_id, struct page *page);

int hmdfs_pcache_hit_at_lru(struct hmdfs_sb_info *sbi, struct file *file);

int hmdfs_is_pcache_hit(struct hmdfs_sb_info *sbi, struct file *file, struct page *page);

int hmdfs_write_pcache_page(__u64 file_ver, __u32 file_id, struct page *page, uint32_t count);

int hmdfs_rename_pcache(struct hmdfs_sb_info *sbi, const char *oldpath, const char *oldname, const char *newpath, const char *newname, unsigned int flags);

void hmdfs_clear_pcache(struct hmdfs_sb_info *sbi);

struct pcache_file_info *get_file_cache_by_fid(struct hmdfs_sb_info *sbi, __u64 file_ver, __u32 file_id);

uint32_t hmdfs_get_writecount(struct page *page);


//int hmdfs_scan_pcache_dir(struct hmdfs_sb_info *sbi);