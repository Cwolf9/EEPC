/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mount.h>

#include "hmdfs.h"
#include "inode.h"
#include "hmdfs_tool.h"
#include "hmdfs_device_view.h"
#include "hmdfs_filecache.h"

int nex[256];

void set_page_cached(struct pcache_file_info *pfi, pgoff_t pg_index) {
    // hmdfs_debug("----- BEFORE: test_bit: %d ------", test_bit(pg_index, pfi->pg_index_bitmap));
    __set_bit(pg_index, pfi->pg_index_bitmap);
}

int is_page_cached(struct pcache_file_info *pfi, pgoff_t pg_index) {
    return test_bit(pg_index, pfi->pg_index_bitmap) ? 1 : 0;
}

struct pcache_file_info *get_file_cache_by_fid(struct hmdfs_sb_info *sbi, __u64 file_ver, __u32 file_id) {
    struct pcache_file_info *pfi;
    struct pcache_file_info *ret = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(pfi, &sbi->pcache_files, super_list) {
        if (pfi->file_ver == file_ver) {// && pfi->file_id == file_id
            ret = pfi;
            break;
        }
    }
    rcu_read_unlock();

    return ret;
}

struct pcache_file_info *get_file_cache_by_fullpath(struct hmdfs_sb_info *sbi, char *full_path, int need_reopen, pgoff_t pg_index) {
    struct pcache_file_info *pfi;
    struct pcache_file_info *ret = NULL;
    char *las_pos;
    char temp_char;
    // int temp_strlen;
    struct path parent_path;
    struct file *pcache_file;

    rcu_read_lock();
    list_for_each_entry_rcu(pfi, &sbi->pcache_files, super_list) {
        if (strncmp(pfi->pcache_full_path, full_path, strlen(pfi->pcache_full_path)) == 0 
            || strncmp(pfi->device_view_path, full_path, strlen(pfi->device_view_path)) == 0) {
            if (need_reopen) {
                // spc_debug("----- %s %s %s -----", full_path, pfi->pcache_full_path, pfi->device_view_path);
                // /mnt/hmdfs/100/account/device_view/90b0df2f03a415ad2f90a8ccc68aca44c6b5e6a4a013e72bf6f323a1222ba96c/files/spc/testdir/f1 
                // /data/service/el2/100/hmdfs/account/hmdfs_pcache/files/spc/testdir/f1 
                // /mnt/hmdfs/100/account/device_view/90b0df2f03a415ad2f90a8ccc68aca44c6b5e6a4a013e72bf6f323a1222ba96c/files/spc/testdir/f1

                // 重新打开缓存文件，才能看到修改
                if (!is_page_cached(pfi, pg_index)) {
                    spc_info("----- pcache not finished yet: pg_index: %d, file_ino: %llu -----", pg_index, pfi->file->f_inode->i_ino);
                    break;
                }
                las_pos = strrchr(pfi->pcache_full_path, '/');
                if(!las_pos) {
                    spc_debug("----- strrchr: %s, not found / -----", pfi->pcache_full_path);
                    break;
                }
                temp_char = *las_pos;
                *las_pos = '\0';
                if (kern_path(pfi->pcache_full_path, 0, &parent_path)) {
                    hmdfs_err("kern_path failed");
                    *las_pos = temp_char;
                    break;
                }
                *las_pos = temp_char;
                // 5error:
                pcache_file = file_open_root(&parent_path, pfi->file->f_path.dentry->d_name.name,
                                             O_RDWR | O_LARGEFILE, 0644);
                path_put(&parent_path);
                if (IS_ERR_OR_NULL(pcache_file)) {
                    hmdfs_err("pcache_file reopen failed");
                    break;
                }
                filp_close(pfi->file, NULL);
                pfi->file = pcache_file;
                hmdfs_debug("----- pcache file found and reopened -----");
            }
            ret = pfi;
            break;
        }
    }
    rcu_read_unlock();
    return ret;
}

struct pcache_file_info *persist_file_cache(struct hmdfs_sb_info *sbi, struct file *file) {
    struct pcache_file_info *pfi;

    pfi = kmalloc(sizeof(*pfi), GFP_NOFS);
    pfi->file = file;

    list_add_rcu(&pfi->super_list, &sbi->pcache_files);
    hmdfs_debug("persist file for %s", get_full_path(&file->f_path));

    return pfi;
}

void pcache_evict_from_lru(struct hmdfs_sb_info *sbi) {
    int err = 0;
    struct pcache_file_info *pfi;
    struct path pcache_path;
    struct dentry *parent_dentry = NULL;
    struct dentry *dentry = NULL;

    if (!list_empty(&sbi->pcache_files)) {
        pfi = list_last_entry(&sbi->pcache_files, struct pcache_file_info, super_list);
        err = kern_path(pfi->pcache_full_path, 0, &pcache_path);
        if (err) {
            hmdfs_err("----- kern_path failed: %d -----", err);
            // list_del_rcu(&pfi->super_list);
            // kfree(pfi);
            // return ;
        }

        dentry = pcache_path.dentry;
        dget(dentry);
        parent_dentry = dget_parent(dentry);
        err = vfs_unlink(parent_dentry->d_inode, dentry, NULL);
        if (err) {
            hmdfs_err("----- vfs_unlink failed 1: %d -----", err);
        } else {
            hmdfs_debug("----- pcache file evicted: %s -----", pfi->pcache_full_path);
            sbi->current_cache_size -= i_size_read(pfi->file->f_inode);
        }
        dput(parent_dentry);
        dput(dentry);
        path_put(&pcache_path);
        list_del_rcu(&pfi->super_list);
        kfree(pfi);
    }
}

int init_pcache_dir_info(struct hmdfs_sb_info *sbi) {
    int err = 0;
    int len = 0;

    spc_info("----- spc_fix: init_pcache_dir_info sbi->local_src: %s, sbi->local_dst: %s -----", sbi->local_src, sbi->local_dst);
    // /data/service/el2/100/hmdfs/account    /device_view/local

    len = strlen(sbi->local_src) + strlen("/") + strlen(PCACHE_ROOT) + strlen("/") + 1;
    if (len > PATH_MAX) {
        err = -EINVAL;
        goto out_err;
    }

    sbi->cache_dir_src = kmalloc(len, GFP_KERNEL);
    if (!sbi->cache_dir_src) {
        err = -ENOMEM;
        goto out_err;
    }
    snprintf(sbi->cache_dir_src, len, "%s/%s/", sbi->local_src, PCACHE_ROOT);

    len = strlen(sbi->local_dst) + strlen(PCACHE_ROOT) + strlen("/") + 1;
    if (len > PATH_MAX) {
        err = -EINVAL;
        goto out_err;
    }

    sbi->cache_dir_local = kmalloc(len, GFP_KERNEL);
    if (!sbi->cache_dir_local) {
        err = -ENOMEM;
        goto out_err;
    }
    snprintf(sbi->cache_dir_local, len, "%s%s/", sbi->local_dst, PCACHE_ROOT);

out_err:
    return err;
}

int hmdfs_init_pcache(struct hmdfs_sb_info *sbi) {
    int err = 0;

    sbi->current_cache_size = 0;

    if (sbi->persist_cache_limit == 0) {
        sbi->cache_dir_local = kstrdup("PCACHE_NOT_ENABLED", GFP_KERNEL);
        sbi->cache_dir_src = kstrdup("PCACHE_NOT_ENABLED", GFP_KERNEL);
        return err;
    }

    if (!sbi->cache_dir_local || !sbi->cache_dir_src) {
        if (init_pcache_dir_info(sbi) == 0) {
            hmdfs_debug("----- sbi->cache_dir_src is %s -----", sbi->cache_dir_src);
            hmdfs_debug("----- sbi->cache_dir_local is %s -----", sbi->cache_dir_local);
            INIT_LIST_HEAD(&sbi->pcache_files);
        } else {
            hmdfs_debug("----- init_pcache_dir_info failed! -----");
        }
    }

    return err;
}
/*
递归创建缓存文件的目录。
*/
char *generate_pcache_dir(char *root_path, struct dentry *child_dentry, struct hmdfs_sb_info *sbi) {
    struct dentry *parent_dentry;
    const char *child_name = child_dentry->d_name.name;
    const char *parent_name = NULL;
    char *path_to_check = NULL;
    char *tmp = NULL;
    int len = 0;

    parent_dentry = dget_parent(child_dentry);
    parent_name = parent_dentry->d_name.name;
    if (strcmp(parent_name, sbi->local_cid) == 0) {
        spc_info("----- parent_name 1: %s, %s -----", parent_name, child_name);
        len = strlen(root_path) + strlen(child_name) + strlen("/") + 1;
        if (len > PATH_MAX) {
            hmdfs_err("path too long");
            goto out_err;
        }

        path_to_check = kmalloc(len, GFP_KERNEL);
        if (!path_to_check) {
            hmdfs_err("memory not enough");
            goto out_err;
        }
        snprintf(path_to_check, len, "%s%s/", root_path, child_name);
        spc_info("----- path_to_check 1: %s -----", path_to_check);
        if (!check_and_mkdir(path_to_check))
            goto out_err;
    } else {
        spc_info("----- generate_pcache_dir 2: %s, %s -----", root_path, parent_name);
        tmp = generate_pcache_dir(root_path, parent_dentry, sbi);
        if (!tmp) {
            goto out_err;
        }
        len = strlen(tmp) + strlen(child_name) + strlen("/") + 1;
        if (len > PATH_MAX) {
            hmdfs_err("path too long");
            kfree(tmp);
            goto out_err;
        }

        path_to_check = kmalloc(len, GFP_KERNEL);
        if (!path_to_check) {
            hmdfs_err("memory not enough");
            kfree(tmp);
            goto out_err;
        }
        snprintf(path_to_check, len, "%s%s/", tmp, child_name);
        spc_info("----- path_to_check 2: %s -----", path_to_check);
        if (!check_and_mkdir(path_to_check))
            kfree(tmp);
        goto out_err;
    }

out_err:
    dput(parent_dentry);
    return path_to_check;
}

/*
new generate_pcache_dir2 log:
[  798.329528]  hmdfs: hmdfs_open_path() get file with magic 538968834
[  798.329548]  hmdfs: hmdfs_set_pcache_truncate() ----- no pcache file found for /home/lih/Desktop/node_c/dst/device_view/fake_cid123456/manual/s3.txt -----
[  798.329550]  hmdfs: hmdfs_do_open_remote() ----- OPEN: s3.txt, file_ver = 11742291628691554304 , file_id = 0 -----
[  798.329551]  hmdfs: hmdfs_pcache_hit_at_lru() ----- not cached yet, missing pcache -----
[  798.329592]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache cache_dir_src: /home/lih/Desktop/node_c/src/hmdfs_pcache/
[  798.329594]  hmdfs: get_path_to_check() ----- relative_parent_path: manual/, sbi->local_cid: fake_cid123456 -----
[  798.329598]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache path_to_check: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/, have: 0
[  798.329599]  hmdfs: generate_pcache_dir2() ----- spc_fix: mkdir path: /home/lih/Desktop/node_c/src/hmdfs_pcache/ -----
[  798.329600]  hmdfs: generate_pcache_dir2() ----- spc_fix: mkdir path: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/ -----
[  798.329624]  hmdfs: persist_file_cache() persist file for /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/s3.txt
[  798.329634]  hmdfs: get_file_cache_by_fullpath() ----- pcache not finished yet -----
[  798.329634]  hmdfs: hmdfs_is_pcache_hit() ----- no pcache file found for /home/lih/Desktop/node_c/dst/device_view/fake_cid123456/manual/s3.txt -----
[  798.329643]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache cache_dir_src: /home/lih/Desktop/node_c/src/hmdfs_pcache/
[  798.329644]  hmdfs: get_path_to_check() ----- relative_parent_path: manual/, sbi->local_cid: fake_cid123456 -----
[  798.329645]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache path_to_check: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/, have: 1
[  798.333054]  hmdfs: update_pcache_size() ----- current_cache_size INcreased to 658 -----
[  798.333106]  hmdfs: hmdfs_server_release() close 0
*/
void generate_pcache_dir2(char *fa_full_path_src) {
    char *pcache, *temp_path, *ori;
    temp_path = kzalloc(512, GFP_KERNEL);
    if (!temp_path) {
        hmdfs_err("----- -ENOMEM: %d -----", -ENOMEM);
        return;
    }
    ori = temp_path;
    pcache = strstr(fa_full_path_src, PCACHE_ROOT);
    if(!pcache) {
        hmdfs_err("----- %s not fount %s -----", fa_full_path_src, PCACHE_ROOT);
        kfree(ori);
        return ;
    }
    for(; *fa_full_path_src != '\0' && fa_full_path_src != pcache; ++fa_full_path_src) {
        *temp_path = *fa_full_path_src;
        temp_path ++;
    }
    for(; *fa_full_path_src != '\0'; ++fa_full_path_src) {
        *temp_path = *fa_full_path_src;
        if (*temp_path == '/') {
            spc_info("----- spc_fix: mkdir path: %s -----", ori);
            if(!check_and_mkdir(ori)) {
                break;
            }
        }
        temp_path ++;
    }
    kfree(ori);
}


void get_next(char *t) {
    int i, k;
    int lent = strlen(t);

    nex[0] = -1;
    for(i = 0,k = -1;i < lent;) {
        if(k==-1||t[i] == t[k]) {
        	++k;++i;
        	nex[i]=k;
		}else k = nex[k];
    }
}

char * kmp(char *s, char *t, int which) {
    int i = 0, j = 0;
    int lens = strlen(s);
    int lent = strlen(t);
    int ans = -1;
    while(i < lens&&j<lent) {
        if(j==-1||s[i] == t[j]) {
        	i++;j++;
        	if(j==lent) {
                ans = i - j + 1;
                if(which != -1) break;
        		j=nex[j];
			}
    	}else j=nex[j];
    }
    if(ans == -1) return NULL;
    return s + ans - 1;
}

/*
new get_path_to_check log:
[  205.645378]  hmdfs: hmdfs_open_path() get file with magic 538968834
[  205.645395]  hmdfs: hmdfs_set_pcache_truncate() ----- no pcache file found for /home/lih/Desktop/node_c/dst/device_view/fake_cid123456/manual/s3.txt -----
[  205.645396]  hmdfs: hmdfs_do_open_remote() ----- OPEN: s3.txt, file_ver = 16047732852927430656 , file_id = 0 -----
[  205.645397]  hmdfs: hmdfs_pcache_hit_at_lru() ----- not cached yet, missing pcache -----
[  205.645443]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache cache_dir_src: /home/lih/Desktop/node_c/src/hmdfs_pcache/, cache_dir_local: /home/lih/Desktop/node_c/dst/device_view/local/hmdfs_pcache/
[  205.645445]  hmdfs: get_path_to_check() ----- relative_parent_path: manual/, sbi->local_cid: fake_cid123456 -----
[  205.645447]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache path_to_check: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/, have: 0
[  205.645448]  hmdfs: hmdfs_page_pcache() ----- generate_pcache_dir in: /home/lih/Desktop/node_c/src/hmdfs_pcache/, s3.txt -----
[  205.645449]  hmdfs: generate_pcache_dir() ----- parent_name 1: fake_cid123456 -----
[  205.645449]  hmdfs: generate_pcache_dir() ----- path_to_check 1: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/ -----
[  205.645472]  hmdfs: persist_file_cache() persist file for /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/s3.txt
[  205.645483]  hmdfs: get_file_cache_by_fullpath() ----- pcache not finished yet -----
[  205.645483]  hmdfs: hmdfs_is_pcache_hit() ----- no pcache file found for /home/lih/Desktop/node_c/dst/device_view/fake_cid123456/manual/s3.txt -----
[  205.645491]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache cache_dir_src: /home/lih/Desktop/node_c/src/hmdfs_pcache/, cache_dir_local: /home/lih/Desktop/node_c/dst/device_view/local/hmdfs_pcache/
[  205.645492]  hmdfs: get_path_to_check() ----- relative_parent_path: manual/, sbi->local_cid: fake_cid123456 -----
[  205.645493]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache path_to_check: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/, have: 1
[  205.645684]  hmdfs: update_pcache_size() ----- current_cache_size INcreased to 658 -----
[  205.645776]  hmdfs: hmdfs_server_release() close 0
*/
char *get_path_to_check(struct hmdfs_sb_info *sbi, struct file *file) {
    int len = 0;
    char *file_server_path = get_full_path(&file->f_path);
    char *relative_parent_path;
    int relative_parent_path_len = 0;
    char *path_to_check = NULL;
    int cntXieGang = 0;
    char *dvp, *filenp;

    // len = strlen(sbi->real_dst) + strlen("/") + strlen(DEVICE_VIEW_ROOT) + strlen("/") + strlen(sbi->local_cid) + strlen("/");
    // relative_parent_path_len = strlen(file_server_path) - len - strlen(file->f_path.dentry->d_name.name);
    // relative_parent_path = kmalloc(relative_parent_path_len + 1, GFP_KERNEL);
    // if (!relative_parent_path) {
    //     hmdfs_err("----- -ENOMEM: %d -----", -ENOMEM);
    //     goto out_err;
    // }
    // memcpy(relative_parent_path, file_server_path + len, relative_parent_path_len);
    
    relative_parent_path = kzalloc(256, GFP_KERNEL);
    if(!relative_parent_path) {
        hmdfs_err("----- -ENOMEM: %d -----", -ENOMEM);
        goto out_err;
    }
    dvp = strstr(file_server_path, DEVICE_VIEW_ROOT);
    // strrstr
    get_next(file->f_path.dentry->d_name.name);
    filenp = kmp(file_server_path, file->f_path.dentry->d_name.name, -1);
    if(dvp && filenp) {
        for(; *dvp != '\0'; ++dvp) {
            if(*dvp == '/') {
                cntXieGang += 1;
                if(cntXieGang == 2) {
                    ++ dvp;
                    break;
                }
            }
        }
        for(; *dvp != '\0' && *filenp != '\0' && dvp != filenp; ++dvp) {
            relative_parent_path[relative_parent_path_len] = *dvp;
            relative_parent_path_len += 1;
        }
    }

    relative_parent_path[relative_parent_path_len] = '\0';

    // spc_info("----- relative_parent_path: %s, fullpath: %s, name: %s -----", relative_parent_path, file_server_path, file->f_path.dentry->d_name.name);
    // relative_parent_path: files/ok/, sbi->local_cid:  ---
    // local_cid 不能包含 name

    len = strlen(sbi->cache_dir_src) + strlen(relative_parent_path) + 1;
    if (len > PATH_MAX) {
        hmdfs_err("----- -EINVAL: %d -----", -EINVAL);
        goto out_err;
    }
    path_to_check = kzalloc(len, GFP_KERNEL);
    if (!path_to_check) {
        hmdfs_err("----- -ENOMEM: %d -----", -ENOMEM);
        goto out_err;
    }
    snprintf(path_to_check, len, "%s%s", sbi->cache_dir_src, relative_parent_path);

out_err:
    if(relative_parent_path) kfree(relative_parent_path);
    kfree(file_server_path);
    return path_to_check;
}

void update_pcache_size(struct hmdfs_sb_info *sbi, loff_t count, int truncate) {
    if (!truncate) {
        sbi->current_cache_size += count;
        hmdfs_debug("----- current_cache_size INcreased to %llu -----", sbi->current_cache_size);
        while (sbi->current_cache_size > sbi->persist_cache_limit) {
            pcache_evict_from_lru(sbi);
        }
    } else {
        if (sbi->current_cache_size < count) {
            sbi->current_cache_size = 0;
        } else {
            sbi->current_cache_size -= count;
        }
        hmdfs_debug("----- current_cache_size DEcreased to %llu -----", sbi->current_cache_size);
    }
}

int pcache_delete(struct hmdfs_sb_info *sbi, struct file *file) {
    int err = 0;
    char *device_view_path = get_full_path(&file->f_path);
    char *pcache_full_path = NULL;
    struct pcache_file_info *pfi = NULL;
    struct path pcache_path;
    struct dentry *parent_dentry = NULL;
    struct dentry *dentry = NULL;

    pfi = get_file_cache_by_fullpath(sbi, device_view_path, 0, 0);
    if (!pfi) {
        err = 1;
        hmdfs_debug("----- no pcache file found for %s -----", device_view_path);
        goto out_err;
    }


    pcache_full_path = get_full_path(&pfi->file->f_path);
    err = kern_path(pcache_full_path, 0, &pcache_path);
    if (err) {
        hmdfs_err("----- kern_path failed: %d -----", err);
        goto out;
    }
    dentry = pcache_path.dentry;
    dget(dentry);
    parent_dentry = dget_parent(pfi->file->f_path.dentry);
    err = vfs_unlink(parent_dentry->d_inode, dentry, NULL);
    if (err) {
        hmdfs_err("----- vfs_unlink failed 2: %d -----", err);
    } else {
        list_del_rcu(&pfi->super_list);
        hmdfs_debug("----- current = %llu, to truncate = %llu -----", sbi->current_cache_size, i_size_read(pfi->file->f_inode));
        update_pcache_size(sbi, i_size_read(pfi->file->f_inode), 1);
        kfree(pfi);
    }
    dput(parent_dentry);
    dput(dentry);
    path_put(&pcache_path);

    out:
    kfree(pcache_full_path);

    out_err:
    kfree(device_view_path);
    return err;
}

struct pcache_file_info *check_and_update_pfi(struct hmdfs_sb_info *sbi, struct file *file, __u64 file_ver, __u32 file_id, char *path_to_check, struct page *page) {
    int len = 0;
    int err = 0;
    char *full_path = NULL;
    struct path pcache_path;
    struct file *pcache_file;
    struct pcache_file_info *pfi = NULL;
    struct path need_to_truncate;
    struct dentry *parent_dentry = NULL;
    struct dentry *dentry = NULL;
    int new;
    pgoff_t max_pg_num = i_size_read(file->f_inode) / HMDFS_PAGE_SIZE + 1;
    int lh_err = 0;

retry:

    new = 0;

    len = strlen(path_to_check) + strlen(file->f_path.dentry->d_name.name) + 1;
    if (len > PATH_MAX) {
        hmdfs_err("----- -EINVAL: %d -----", -EINVAL);
        return NULL;
    }
    full_path = kmalloc(512, GFP_KERNEL);
    if (!full_path) {
        hmdfs_err("----- -ENOMEM: %d -----", -ENOMEM);
        return NULL;
    }
    snprintf(full_path, len, "%s%s", path_to_check, file->f_path.dentry->d_name.name);

persist_new:

    lh_err += 1;
    if(lh_err >= 5) {
        goto out_err;
    }

    if (!check_path(full_path)) {
        check_and_create(full_path);
        new = 1;
    }

    if (new == 1) {
        err = kern_path(path_to_check, 0, &pcache_path);
        if (err) {
            hmdfs_err("kern_path failed: %d, %s", err, path_to_check);
            goto out_err;
        }
        // 5error:
        pcache_file = file_open_root(&pcache_path, file->f_path.dentry->d_name.name,
                                     O_RDWR | O_LARGEFILE, 0644);
        path_put(&pcache_path);
        if (IS_ERR_OR_NULL(pcache_file)) {
            hmdfs_err("pcache_file open failed");
            pcache_file = NULL;
            goto out_err;
        }
        pfi = persist_file_cache(sbi, pcache_file);
        pfi->file_ver = file_ver;
        pfi->file_id = file_id;
        pfi->device_view_path = get_full_path(&file->f_path);
        pfi->pcache_full_path = full_path;
        pfi->size = 0;
        pfi->need_truncate = 0;
        pfi->pg_index_bitmap = kmalloc(max_pg_num, GFP_KERNEL);
        bitmap_zero(pfi->pg_index_bitmap, max_pg_num);
        if (page) {
            set_page_cached(pfi, page->index);
            spc_info("----- Persisted: pg_index: %d, file_ino: %llu -----", page->index, pfi->file->f_inode->i_ino);
            len = strlen(pfi->device_view_path);
            if(pfi->device_view_path[len - 1] == ')') {
                spc_info("----- Persisted: pfi->device_view_path: %s -----", pfi->device_view_path);
            }
            len = strlen(pfi->pcache_full_path);
            if(pfi->pcache_full_path[len - 1] == ')') {
                spc_info("----- Persisted: pfi->pcache_full_path: %s -----", pfi->pcache_full_path);
            }
        }
        spc_debug("----- Persisted new file -----");
        // device_view_path: /mnt/hmdfs/100/account/device_view/7c02b4062414afaba15d398e0c2edb90a4d41baf6d5912b31e85c1ff8cd04d76/files/ok/a.txt 
        // pcache_full_path: /data/service/el2/100/hmdfs/account/hmdfs_pcache/files/ok/a.txt 
        return pfi;
    } else {
        if (page) {
            pfi = get_file_cache_by_fullpath(sbi, full_path, 0, page->index);
        }
        if (!pfi) {
            err = kern_path(full_path, 0, &need_to_truncate);
            if (err) {
                hmdfs_err("----- kern_path failed: %d -----", err);
                goto persist_new;
            }

            dentry = need_to_truncate.dentry;
            dget(dentry);
            parent_dentry = dget_parent(dentry);
            err = vfs_unlink(parent_dentry->d_inode, dentry, NULL);
            if (err) {
                hmdfs_err("----- vfs_unlink failed 3: %d -----", err);
                goto out_err;
            } else {
                hmdfs_debug("----- existed file deleted: %s -----", full_path);
            }
            dput(parent_dentry);
            dput(dentry);
            path_put(&need_to_truncate);
            goto persist_new;
        }
        if (pfi->need_truncate == 1) {
            hmdfs_debug("----- truncating: %s..... (full_path: %s) -----", pfi->file->f_path.dentry->d_name.name, full_path);
            err = pcache_delete(sbi, pfi->file);
            if(err != 0) {
                hmdfs_err("----- check_and_update_pfi err: %d -----", err);
            }
            pfi = NULL;
            goto persist_new;
        }
        if (page) {
            set_page_cached(pfi, page->index);
            spc_info("----- Persisted: pg_index: %d, file_ino: %llu -----", page->index, pfi->file->f_inode->i_ino);
        }
    }

out_err:
    kfree(full_path);
    return pfi;
}

int hmdfs_set_pcache_truncate(struct hmdfs_sb_info *sbi, struct file *file) {
    int err = 0;
    char *device_view_path = get_full_path(&file->f_path);
    struct pcache_file_info *pfi = NULL;

    pfi = get_file_cache_by_fullpath(sbi, device_view_path, 0, 0);
    if (!pfi) {
        err = 1;
        hmdfs_debug("----- no pcache file found for %s -----", device_view_path);
        goto out_err;
    }
    pfi->need_truncate = 1;

out_err:
    kfree(device_view_path);
    return err;
}
/*
开发板中 dst 和 src 不在相邻目录，就找不到 src 就出问题了，所以写持久化缓存的时候，应该写 device_view 下的 local 就好了
---
ls /storage/media/100/local
data files
---
ls /mnt/hmdfs/100/account/device_view
local fake...
---
ls /mnt/hmdfs/100/account/merge_view
data files
---
[   85.985491]  hmdfs: hmdfs_open_path() get file with magic 538968834
[   85.985564]  hmdfs: hmdfs_set_pcache_truncate() ----- no pcache file found for /home/lih/Desktop/node_c/dst/device_view/fake_cid123456/s3.txt -----
[   85.985565]  hmdfs: hmdfs_do_open_remote() ----- OPEN: s3.txt!!!!! file_ver = 10314369048324964352 , file_id = 0 -----
[   85.985566]  hmdfs: hmdfs_pcache_hit_at_lru() ----- not cached yet, missing pcache -----
[   85.985606]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache cache_dir_src: /home/lih/Desktop/node_c/src/hmdfs_pcache/
[   85.985607]  hmdfs: get_path_to_check() ----- relative_parent_path:  -----
[   85.985609]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache path_to_check: /home/lih/Desktop/node_c/src/hmdfs_pcache/, have: 1
[   85.985637]  hmdfs: persist_file_cache() persist file for /home/lih/Desktop/node_c/src/hmdfs_pcache/s3.txt
[   85.985649]  hmdfs: get_file_cache_by_fullpath() ----- pcache not finished yet -----
[   85.985649]  hmdfs: hmdfs_is_pcache_hit() ----- no pcache file found for /home/lih/Desktop/node_c/dst/device_view/fake_cid123456/s3.txt -----
[   85.985658]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache cache_dir_src: /home/lih/Desktop/node_c/src/hmdfs_pcache/
[   85.985659]  hmdfs: get_path_to_check() ----- relative_parent_path:  -----
[   85.985660]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache path_to_check: /home/lih/Desktop/node_c/src/hmdfs_pcache/, have: 1
[   85.985868]  hmdfs: update_pcache_size() ----- current_cache_size INcreased to 658 -----
[   85.985930]  hmdfs: hmdfs_server_release() close 0



rm, cat
[ 1743.953439]  hmdfs: hmdfs_open_path() get file with magic 538968834
[ 1743.953526]  hmdfs: hmdfs_do_open_remote() ----- OPEN: s3.txt!!!!! file_ver = 10314369048324964352 , file_id = 4 -----
[ 1743.953539]  hmdfs: get_file_cache_by_fullpath() ----- pcache not finished yet -----
[ 1743.953540]  hmdfs: hmdfs_is_pcache_hit() ----- no pcache file found for /home/lih/Desktop/node_c/dst/device_view/fake_cid123456/manual/s3.txt -----
[ 1743.953682]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache cache_dir_src: /home/lih/Desktop/node_c/src/hmdfs_pcache/
[ 1743.953684]  hmdfs: get_path_to_check() ----- relative_parent_path: manual/ -----
[ 1743.953688]  hmdfs: hmdfs_page_pcache() ----- hmdfs_page_pcache path_to_check: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/, have: 0
[ 1743.953689]  hmdfs: hmdfs_page_pcache() ----- generate_pcache_dir in: /home/lih/Desktop/node_c/src/hmdfs_pcache/, s3.txt -----
[ 1743.953690]  hmdfs: generate_pcache_dir() ----- parent_name 1: fake_cid123456 -----
[ 1743.953690]  hmdfs: generate_pcache_dir() ----- path_to_check 1: /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/ -----
[ 1743.953711]  hmdfs: persist_file_cache() persist file for /home/lih/Desktop/node_c/src/hmdfs_pcache/manual/s3.txt
[ 1743.953718]  hmdfs: update_pcache_size() ----- current_cache_size INcreased to 1974 -----
[ 1743.953796]  hmdfs: hmdfs_server_release() close 4

*/
int hmdfs_page_pcache(struct hmdfs_sb_info *sbi, struct file *file, __u64 file_ver, __u32 file_id, struct page *page) {
    int err = 0;
    // struct dentry *parent_dentry = NULL;
    struct pcache_file_info *pcache_file = NULL;
    char *path_to_check = NULL;
    char *kaddr = NULL;
    uint32_t count = 0;
    loff_t pos = 0;
    struct inode *inode = NULL;
    loff_t size = 0;
    ssize_t ret = 0;
    // 这里的 file 是原文件的 file
    // 5error:
    struct timespec64 cts;
    struct hmdfs_inode_info *info = NULL;
    jiffies_to_timespec64(jiffies, &cts);
    if(cts.tv_sec % 600 == 0 && cts.tv_nsec < 100 * 1000 * 1000) info->latest_rd_times = 0;

    if(file->f_inode != NULL) info = hmdfs_i(file->f_inode);

    if(page && info) info->latest_rd_times  += 1;
    // if(file && info && page) spc_info("----- hmdfs_page_pcache ino: %lu, latest_rd_times: %d file_wb_type: %d, page: %lX %p, pindex: %lu -----", file->f_inode->i_ino, info->latest_rd_times, info->file_wb_type, (long unsigned int)page, page, page->index);
    // if(info && file->f_inode->i_size >= 16 * 1024 && ((info->file_wb_type < 4 && info->latest_rd_times < 16 / 4 + 1) || (info->file_wb_type >= 4 && info->latest_rd_times < 128 / 4))) {
    //     return 0;
    // }

    check_and_mkdir(sbi->cache_dir_src);

    path_to_check = get_path_to_check(sbi, file);
    if (!path_to_check) {
        hmdfs_err("----- get path_to_check failed -----");
        err = -ENOMEM;
        goto out_err;
    }

    spc_info("----- hmdfs_page_pcache path_to_check: %s, have: %d", path_to_check, check_path(path_to_check));
    // /data/service/el2/100/hmdfs/account/hmdfs_pcache/files/ok/

    if (!check_path(path_to_check)) {
        generate_pcache_dir2(path_to_check);
        // parent_dentry = dget_parent(file->f_path.dentry);
        // spc_info("----- generate_pcache_dir in: %s, %s -----", sbi->cache_dir_src, file->f_path.dentry->d_name.name);
        // path_to_check = generate_pcache_dir(kstrdup(sbi->cache_dir_src, GFP_KERNEL), parent_dentry, sbi);
        // dput(parent_dentry);
    }

    if (page) {
        pcache_file = check_and_update_pfi(sbi, file, file_ver, file_id, path_to_check, page);
    } else {
        pcache_file = check_and_update_pfi(sbi, file, file_ver, file_id, path_to_check, NULL);
        if (!pcache_file) {
            hmdfs_err("----- check_and_update_pfi failed -----");
            err = -ENOMEM;
        }
        // If it only creates but no page persisted, just return
        goto out;
    }

    if (!pcache_file) {
        hmdfs_err("----- check_and_update_pfi failed -----");
        err = -ENOMEM;
        goto out;
    }

    pos = (loff_t)page->index << HMDFS_PAGE_OFFSET;
    inode = page->mapping->host;
    size = i_size_read(inode);

    if (size < pos + HMDFS_PAGE_SIZE)
        count = size - pos;
    else
        count = HMDFS_PAGE_SIZE;

    // Need to wait async readpage finished
    lock_page(page);
    kaddr = kmap_atomic(page);
    ret = kernel_write(pcache_file->file, kaddr, count, &pos);
    if (ret != count) {
        err = -EIO;
        hmdfs_err("----- kernel_write error! -----");
    } else {
        update_pcache_size(sbi, (loff_t)count, 0);
        pcache_file->size += (loff_t)count;
    }
    kunmap_atomic(kaddr);
    unlock_page(page);

out:

    kfree(path_to_check);

out_err:
    spc_info("----- hmdfs_page_pcache: err: %d, ret: %d, ccs: %lld", err, ret, sbi->current_cache_size);
    // sbi->cache_dir_src, sbi->cache_dir_local
    // /data/service/el2/100/hmdfs/account/hmdfs_pcache/, /mnt/hmdfs/100/account/device_view/local/hmdfs_pcache/
    return err;
}

int hmdfs_pcache_hit_at_lru(struct hmdfs_sb_info *sbi, struct file *file) {
    struct pcache_file_info *pfi;
    char *device_view_path = get_full_path(&file->f_path);

    pfi = get_file_cache_by_fullpath(sbi, device_view_path, 0, 0);
    if (!pfi) {
        hmdfs_debug("----- not cached yet, missing pcache -----");
        kfree(device_view_path);
        return 0;
    }
    list_del_rcu(&pfi->super_list);
    list_add_rcu(&pfi->super_list, &sbi->pcache_files);
    kfree(device_view_path);
    return 1;
}

int hmdfs_is_pcache_hit(struct hmdfs_sb_info *sbi, struct file *file, struct page *page) {
    int ret = 1;
    char *device_view_path = get_full_path(&file->f_path);
    struct pcache_file_info *pfi = NULL;
    char *buf = NULL;
    char *kaddr = NULL;
    uint32_t count = 0;
    loff_t pos = (loff_t)page->index << HMDFS_PAGE_OFFSET;
    struct inode *inode = page->mapping->host;
    loff_t size = i_size_read(inode);
    ssize_t read_ret = 0;

    pfi = get_file_cache_by_fullpath(sbi, device_view_path, 1, page->index);
    if (!pfi) {
        ret = 0;
        spc_debug("----- no pcache file found for %s -----", device_view_path);
        goto out;
    }

    if (pfi->need_truncate == 1) {
        ret = 0;
        spc_debug("----- STALE pcache file-----");
        goto out;
    }
    
    kaddr = kmap_atomic(page);
    memset(kaddr, 0, PAGE_SIZE);

    if (size < pos + HMDFS_PAGE_SIZE)
        count = size - pos;
    else
        count = HMDFS_PAGE_SIZE;

    buf = kzalloc(count, GFP_KERNEL);
    read_ret = kernel_read(pfi->file, buf, count, &pos);
    if (read_ret < 0 || read_ret != count) {
        ret = 0;
        hmdfs_err("----- kernel_read failed -----");
        goto out_err;
    }
    memcpy(kaddr, buf, count);
    hmdfs_debug("----- read pcache file page successfully -----");

out_err:
    kfree(buf);
    kunmap_atomic(kaddr);
    SetPageUptodate(page);
    unlock_page(page);

out:
    kfree(device_view_path);
    return ret;
}

int hmdfs_write_pcache_page(__u64 file_ver, __u32 file_id, struct page *page, uint32_t count) {
    int err = 0;
    struct inode *dvinode = page->mapping->host;
    struct hmdfs_sb_info *sbi = hmdfs_sb(dvinode->i_sb);
    struct pcache_file_info *pfi = NULL;
    loff_t pos = (loff_t)page->index << HMDFS_PAGE_OFFSET;
    char *kaddr = NULL;
    ssize_t ret = 0;

    pfi = get_file_cache_by_fid(sbi, file_ver, file_id);
    if (!pfi) {
        err = 1;
        hmdfs_debug("----- NO pfi found by fid -----");
        return err;
    }
    hmdfs_debug("----- pfi found by fid, count = %u -----", count);

    kaddr = kmap_atomic(page);
    ret = kernel_write(pfi->file, kaddr, count, &pos);
    if (ret != count) {
        err = -EIO;
        hmdfs_err("----- kernel_write error! -----");
    } else {
        update_pcache_size(sbi, (loff_t)count, 0);
        pfi->size += (loff_t)count;
    }
    kunmap_atomic(kaddr);

    return err;
}

struct pcache_file_info *get_file_cache_by_dir(struct hmdfs_sb_info *sbi, struct path *relative_parent_path, const char *name) {
    int len = 0;
    char *parent_path = NULL;
    char *full_path = NULL;
    struct pcache_file_info *pfi = NULL;

    parent_path = get_full_path(relative_parent_path);
    len = strlen(parent_path) + strlen("/") + strlen(name) + 1;
    if (len > PATH_MAX) {
        hmdfs_err("----- -EINVAL: %d -----", -EINVAL);
        goto out;
    }

    full_path = kmalloc(len, GFP_KERNEL);
    if (!full_path) {
        hmdfs_err("----- -ENOMEM: %d -----", -ENOMEM);
        goto out;
    }
    snprintf(full_path, len, "%s/%s", parent_path, name);
    pfi = get_file_cache_by_fullpath(sbi, full_path, 0, 0);
    if (pfi) {
        hmdfs_debug("----- pfi found by full_path: %s, size = %llu-----", full_path, pfi->size);
    } else {
        hmdfs_debug("----- pfi not found by old_full_path: %s -----", full_path);
    }
    kfree(full_path);
    
out:
    kfree(parent_path);
    return pfi;
}

int hmdfs_rename_pcache(struct hmdfs_sb_info *sbi, const char *oldpath, const char *oldname, const char *newpath, const char *newname, unsigned int flags) {
    int err = 0;
    struct path path_dst;
    struct path path_old;
    struct path path_new;
    struct dentry *trap = NULL;
    struct dentry *old_dentry = NULL;
    struct dentry *new_dentry = NULL;
    struct pcache_file_info *old_pfi = NULL;
    struct pcache_file_info *new_pfi = NULL;

    err = kern_path(sbi->cache_dir_src, 0, &path_dst);
    if (err) {
        hmdfs_err("kern_path for pcache dir failed %d", err);
        return err;
    }

    err = vfs_path_lookup(path_dst.dentry, path_dst.mnt, oldpath, 0,
                          &path_old);
    if (err) {
        spc_info("lookup oldpath from pcache dir failed, err %d", err);
        goto put_path_dst;
    }

    err = vfs_path_lookup(path_dst.dentry, path_dst.mnt, newpath, 0,
                          &path_new);
    if (err) {
        spc_info("lookup newpath from pcache dir failed, err %d", err);
        goto put_path_old;
    }

    err = mnt_want_write(path_dst.mnt);
    if (err) {
        spc_info("get write access failed for pcache dir, err %d",
                   err);
        goto put_path_new;
    }

    trap = lock_rename(path_new.dentry, path_old.dentry);

    old_dentry = lookup_one_len(oldname, path_old.dentry, strlen(oldname));
    if (IS_ERR(old_dentry)) {
        err = PTR_ERR(old_dentry);
        spc_info("lookup old dentry failed, err %d", err);
        goto unlock;
    }

    /* source should not be ancestor of target */
    if (old_dentry == trap) {
        err = -EINVAL;
        goto put_old_dentry;
    }

    new_dentry = lookup_one_len(newname, path_new.dentry, strlen(newname));
    if (IS_ERR(new_dentry)) {
        err = PTR_ERR(new_dentry);
        spc_info("lookup new dentry failed, err %d", err);
        goto put_old_dentry;
    }

    /*
     * Exchange rename is not supported, thus target should not be an
     * ancestor of source.
     */
    if (trap == new_dentry) {
        err = -ENOTEMPTY;
        goto put_new_dentry;
    }

    if (d_is_positive(new_dentry) && (flags & RENAME_NOREPLACE)) {
        err = -EEXIST;
        goto put_new_dentry;
    }
    
    old_pfi = get_file_cache_by_dir(sbi, &path_old, oldname);
    if (!old_pfi) {
        goto rename;
    }

    new_pfi = get_file_cache_by_dir(sbi, &path_new, newname);
    if (!new_pfi) {
        goto rename;
    }

    update_pcache_size(sbi, new_pfi->size, 1);
    new_pfi->size = old_pfi->size;
    list_del_rcu(&old_pfi->super_list);
    kfree(old_pfi);
    
rename:
    err = vfs_rename(d_inode(path_old.dentry), old_dentry,
                     d_inode(path_new.dentry), new_dentry, NULL, 0);
    
put_new_dentry:
    dput(new_dentry);
put_old_dentry:
    dput(old_dentry);
unlock:
    unlock_rename(path_new.dentry, path_old.dentry);
    mnt_drop_write(path_dst.mnt);
put_path_new:
    path_put(&path_new);
put_path_old:
    path_put(&path_old);
put_path_dst:
    path_put(&path_dst);

    return err;
}

void hmdfs_clear_pcache(struct hmdfs_sb_info *sbi) {
    int err = 0;
    struct pcache_file_info *pfi;
    struct path pcache_path;
    struct dentry *parent_dentry = NULL;
    struct dentry *dentry = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(pfi, &sbi->pcache_files, super_list) {
        err = kern_path(pfi->pcache_full_path, 0, &pcache_path);
        if (err) {
            hmdfs_debug("----- kern_path failed (%d) for %s -----", err, pfi->pcache_full_path);
            // Maybe some tmp files already deleted or from remote thus cannot be found
            continue;
        }

        dentry = pcache_path.dentry;
        dget(dentry);
        parent_dentry = dget_parent(dentry);
        err = vfs_unlink(parent_dentry->d_inode, dentry, NULL);
        if (err) {
            hmdfs_err("----- vfs_unlink failed 4: %d -----", err);
        } else {
            hmdfs_debug("----- pcache file deleted -----");
        }
        dput(parent_dentry);
        dput(dentry);
        path_put(&pcache_path);
    }
    rcu_read_unlock();
}

//int lookup_pcache_update(struct dir_context *ctx, const char *name,
//                         int name_len, loff_t offset, u64 ino,
//                         unsigned int d_type) {
//    struct hmdfs_pcache_ctx *pctx = NULL;
//    struct dentry *child = NULL;
//    int len = 0;
//    char *current_path = NULL;
//    char *next_path = NULL;
//    struct path next;
//    struct file *file = NULL;
//    struct hmdfs_pcache_ctx iter_ctx = {
//            .ctx.actor = lookup_pcache_update,
//    };
//
//    if (name_len > NAME_MAX) {
//        hmdfs_err("name_len:%d NAME_MAX:%u", name_len, NAME_MAX);
//        goto out;
//    }
//
//    pctx = container_of(ctx, struct hmdfs_pcache_ctx, ctx);
//    current_path = get_full_path(pctx->parent_path);
//    iter_ctx.sbi = pctx->sbi;
//
//    child = lookup_one_len(name, pctx->parent_path->dentry, name_len);
//    if (IS_ERR(child)) {
//        // hmdfs_debug("lookup failed because %ld", PTR_ERR(child));
//        goto out;
//    }
//
//    if (d_type == DT_REG) {
//        // hmdfs_debug("----- regular file name is %s, size = %llu -----", name, i_size_read(child->d_inode));
//        pctx->sbi->current_cache_size += i_size_read(child->d_inode);
//    } else if (d_type == DT_DIR) {
//        if (strcmp(name, "..") != 0 && strcmp(name, ".") != 0) {
//            len = strlen(current_path) + strlen("/") + strlen(name) + 1;
//            if (len > PATH_MAX) {
//                goto out;
//            }
//
//            next_path = kmalloc(len, GFP_KERNEL);
//            if (!next_path) {
//                goto out;
//            }
//            snprintf(next_path, len, "%s/%s", current_path, name);
//
//            // hmdfs_debug("----- now scanning lower directory: %s -----", next_path);
//
//            if (kern_path(next_path, 0, &next)) {
//                hmdfs_err("----- kern_path failed -----");
//                goto out;
//            } else {
//                iter_ctx.parent_path = &next;
//            }
//
//            file = dentry_open(&next, O_RDONLY | O_DIRECTORY, current_cred());
//            if (IS_ERR(file)) {
//                hmdfs_err("----- dentry_open failed -----");
//                kfree(next_path);
//                path_put(&next);
//                if (!IS_ERR_OR_NULL(file))
//                    fput(file);
//            }
//
//            if (iterate_dir(file, &iter_ctx.ctx)) {
//                hmdfs_err("----- iterate_dir failed -----");
//                kfree(next_path);
//                path_put(&next);
//                if (!IS_ERR_OR_NULL(file))
//                    fput(file);
//            }
//        }
//    }
//
//    dput(child);
//
//    out:
//    return 0;
//}
//
//int hmdfs_scan_pcache_dir(struct hmdfs_sb_info *sbi) {
//    int err = 0;
//    struct path pcache_root_path;
//    struct file *file = NULL;
//    struct hmdfs_pcache_ctx pctx = {
//            .ctx.actor = lookup_pcache_update,
//            .sbi = sbi,
//    };
//
//    sbi->current_cache_size = 0;
//
//    err = kern_path(sbi->cache_dir_src, 0, &pcache_root_path);
//    if (err) {
//        hmdfs_err("----- kern_path failed or pcache dir not created: %d -----", err);
//        return err;
//    }
//    pctx.parent_path = &pcache_root_path;
//    file = dentry_open(&pcache_root_path, O_RDONLY | O_DIRECTORY, current_cred());
//    if (IS_ERR(file)) {
//        err = PTR_ERR(file);
//        hmdfs_err("----- dentry_open failed: %d -----", err);
//        goto out;
//    }
//
//    err = iterate_dir(file, &pctx.ctx);
//    if (err) {
//        hmdfs_err("----- iterate_dir failed: %d -----", err);
//        goto out;
//    }
//    hmdfs_debug("----- updated current pcache used space: %llu -----", sbi->current_cache_size);
//
//    out:
//    path_put(&pcache_root_path);
//    if (!IS_ERR_OR_NULL(file))
//        fput(file);
//    return err;
//}