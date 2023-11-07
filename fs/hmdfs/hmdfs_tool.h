/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#ifndef HMDFS_TOOL_H
#define HMDFS_TOOL_H

#endif //HMDFS_TOOL_H

char *get_full_path(struct path *path);

int check_path(char *full_path);

int check_and_mkdir(char *full_path);

int check_and_create(char *full_path);

void writeback_sort(struct hmdfs_writeback *hwb);

struct hmdfs_inode_info *get_info_insert_pos(struct hmdfs_inode_info *info, struct hmdfs_writeback *hwb);
