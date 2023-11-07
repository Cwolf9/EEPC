// SPDX-License-Identifier: GPL-2.0
/*
 * rtg control entry
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#include "rtg.h"
#include "rtg_ctrl.h"
#include "rtg_qos.h"

#include <linux/module.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#ifdef CONFIG_SCHED_RTG_AUTHORITY
#include <linux/cred.h>
#include <linux/user.h>
#include <linux/slab.h>
#include <linux/refcount.h>
#endif
#include <trace/events/rtg.h>

atomic_t g_rtg_enable = ATOMIC_INIT(0);
static atomic_t g_rt_frame_num = ATOMIC_INIT(0);
static int g_frame_max_util = DEFAULT_MAX_UTIL;
static int g_max_rt_frames = DEFAULT_MAX_RT_FRAME;
typedef long (*rtg_ctrl_func)(int abi, void __user *arg);

static long ctrl_set_enable(int abi, void __user *uarg);
static long ctrl_set_rtg(int abi, void __user *uarg);
static long ctrl_set_config(int abi, void __user *uarg);
static long ctrl_set_rtg_attr(int abi, void __user *uarg);
static long ctrl_begin_frame(int abi, void __user *uarg);
static long ctrl_end_frame(int abi, void __user *uarg);
static long ctrl_end_scene(int abi, void __user *uarg);
static long ctrl_set_min_util(int abi, void __user *uarg);
static long ctrl_set_margin(int abi, void __user *uarg);
static long ctrl_list_rtg(int abi, void __user *uarg);
static long ctrl_list_rtg_thread(int abi, void __user *uarg);
static long ctrl_search_rtg(int abi, void __user *uarg);
static long ctrl_get_enable(int abi, void __user *uarg);
#ifdef CONFIG_SCHED_RTG_AUTHORITY
static long ctrl_auth_manipulate(int abi, void __user *uarg);
#endif
#ifdef CONFIG_SCHED_RTG_QOS
static long ctrl_qos_manipulate(int abi, void __user *uarg);
#endif

static rtg_ctrl_func g_func_array[RTG_CTRL_MAX_NR] = {
	NULL, /* reserved */
	ctrl_set_enable,  // 1
	ctrl_set_rtg,
	ctrl_set_config,
	ctrl_set_rtg_attr,
	ctrl_begin_frame,  // 5
	ctrl_end_frame,
	ctrl_end_scene,
	ctrl_set_min_util,
	ctrl_set_margin,
	ctrl_list_rtg,  // 10
	ctrl_list_rtg_thread,
	ctrl_search_rtg,
	ctrl_get_enable,
#ifdef CONFIG_SCHED_RTG_AUTHORITY
	ctrl_auth_manipulate,
#endif
#ifdef CONFIG_SCHED_RTG_QOS
	ctrl_qos_manipulate,
#endif
};

static int init_proc_state(const int *config, int len);
static void deinit_proc_state(void);

static int set_enable_config(char *config_str)
{
	char *p = NULL;
	char *tmp = NULL;
	int value;
	int config[RTG_CONFIG_NUM];
	int i;
	int ret = 0;

	for (i = 0; i < RTG_CONFIG_NUM; i++)
		config[i] = INVALID_VALUE;
	/* eg: key1:value1;key2:value2;key3:value3 */
	for (p = strsep(&config_str, ";"); p != NULL;
		p = strsep(&config_str, ";")) {
		tmp = strsep(&p, ":");
		if ((tmp == NULL) || (p == NULL))
			continue;
		if (kstrtoint((const char *)p, DECIMAL, &value))
			return -INVALID_ARG;

		if (!strcmp(tmp, "sched_cycle"))
			config[RTG_FREQ_CYCLE] = value;
		else if (!strcmp(tmp, "frame_max_util"))
			config[RTG_FRAME_MAX_UTIL] = value;
		else if (!strcmp(tmp, "invalid_interval"))
			config[RTG_INVALID_INTERVAL] = value;
		else
			continue;
	}

	for (i = 0; i < RTG_CONFIG_NUM; i++)
		pr_info("[SCHED_RTG] config[%d] = %d\n", i, config[i]);

	ret = init_proc_state(config, RTG_CONFIG_NUM);

	return ret;
}

static void rtg_enable(int abi, const struct rtg_enable_data *data)
{
	char temp[MAX_DATA_LEN];
	int ret = -1;

	if (atomic_read(&g_rtg_enable) == 1) {
		pr_info("[SCHED_RTG] already enabled!\n");
		return;
	}

	if ((data->len <= 0) || (data->len >= MAX_DATA_LEN)) {
		pr_err("[SCHED_RTG] %s data len invalid\n", __func__);
		return;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	switch (abi) {
	case IOCTL_ABI_ARM32:
		ret = copy_from_user(&temp,
			(void __user *)compat_ptr((compat_uptr_t)data->data), data->len);
		break;
	case IOCTL_ABI_AARCH64:
		ret = copy_from_user(&temp, (void __user *)data->data, data->len);
		break;
	default:
		pr_err("[SCHED_RTG] abi format error\n");
		break;
	}
	if (ret) {
		pr_err("[SCHED_RTG] %s copy user data failed\n", __func__);
		return;
	}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	temp[data->len] = '\0';

	if (set_enable_config(&temp) != SUCC) {
		pr_err("[SCHED_RTG] %s failed!\n", __func__);
		return;
	}
#pragma GCC diagnostic pop

	atomic_set(&g_rtg_enable, 1);
	pr_info("[SCHED_RTG] enabled!\n");
}

static void rtg_disable(void)
{
	if (atomic_read(&g_rtg_enable) == 0) {
		pr_info("[SCHED_RTG] already disabled!\n");
		return;
	}
	pr_info("[SCHED_RTG] disabled!\n");
	atomic_set(&g_rtg_enable, 0);
	deinit_proc_state();
}

static inline bool is_rt_type(int type)
{
	return (type >= VIP && type < NORMAL_TASK);
}

static int do_update_rt_frame_num(struct frame_info *frame_info, int new_type)
{
	int old_type;
	int ret = SUCC;

	mutex_lock(&frame_info->lock);
	old_type = frame_info->prio - DEFAULT_RT_PRIO;
	if (is_rt_type(new_type) == is_rt_type(old_type))
		goto out;

	if (is_rt_type(old_type)) {
		if (atomic_read(&g_rt_frame_num) > 0)
			atomic_dec(&g_rt_frame_num);
	} else if (is_rt_type(new_type)) {
		if (atomic_read(&g_rt_frame_num) < g_max_rt_frames) {
			atomic_inc(&g_rt_frame_num);
		} else {
			pr_err("[SCHED_RTG]: %s g_max_rt_frames is %d\n",
				__func__, g_max_rt_frames);
			ret = -INVALID_ARG;
		}
	}
out:
	mutex_unlock(&frame_info->lock);

	return ret;
}

static int update_rt_frame_num(struct frame_info *frame_info, int new_type, int cmd)
{
	int ret = SUCC;

	switch (cmd) {
	case UPDATE_RTG_FRAME:
		ret = do_update_rt_frame_num(frame_info, new_type);
		break;
	case ADD_RTG_FRAME:
		if (is_rt_type(new_type)) {
			if (atomic_read(&g_rt_frame_num) >= g_max_rt_frames) {
				pr_err("[SCHED_RTG] g_max_rt_frames is %d!\n", g_max_rt_frames);
				ret = -INVALID_ARG;
			} else {
				atomic_inc(&g_rt_frame_num);
			}
		}
		break;
	case CLEAR_RTG_FRAME:
		if ((atomic_read(&g_rt_frame_num) > 0) && is_rt_type(new_type))
			atomic_dec(&g_rt_frame_num);
		break;
	default:
		return -INVALID_ARG;
	}
	trace_rtg_frame_sched(frame_info->rtg->id, "g_rt_frame_num", atomic_read(&g_rt_frame_num));
	trace_rtg_frame_sched(frame_info->rtg->id, "g_max_rt_frames", g_max_rt_frames);

	return ret;
}

static long ctrl_set_enable(int abi, void __user *uarg)
{
	struct rtg_enable_data rs_enable;

	if (copy_from_user(&rs_enable, uarg, sizeof(rs_enable))) {
		pr_err("[SCHED_RTG] CMD_ID_SET_ENABLE copy data failed\n");
		return -INVALID_ARG;
	}
	if (rs_enable.enable == 1)
		rtg_enable(abi, &rs_enable);
	else
		rtg_disable();

	return SUCC;
}

static long ctrl_get_enable(int abi, void __user *uarg)
{
	return atomic_read(&g_rtg_enable);
}

static int parse_config(const struct rtg_str_data *rs_data)
{
	int len;
	char *p = NULL;
	char *tmp = NULL;
	char *data = NULL;
	int value;

	if (rs_data == NULL)
		return -INVALID_ARG;
	data = rs_data->data;
	len = rs_data->len;
	if ((data == NULL) || (strlen(data) != len)) //lint !e737
		return -INVALID_ARG;
	/*
	 *     eg: rtframe:4;
	 */
	for (p = strsep(&data, ";"); p != NULL; p = strsep(&data, ";")) {
		tmp = strsep(&p, ":");
		if ((tmp == NULL) || (p == NULL))
			continue;
		if (kstrtoint((const char *)p, DECIMAL, &value))
			return -INVALID_ARG;
		if (!strcmp(tmp, "rtframe")) {
			if (value > 0 && value <= MULTI_FRAME_NUM) {
				g_max_rt_frames = value;
			} else {
				pr_err("[SCHED_RTG]%s invalid max_rt_frame:%d, MULTI_FRAME_NUM=%d\n",
				       __func__, value, MULTI_FRAME_NUM);
				return -INVALID_ARG;
			}
		}
	}

	return SUCC;
}

static long ctrl_set_config(int abi, void __user *uarg)
{
	struct rtg_str_data rs;
	char temp[MAX_DATA_LEN];
	long ret = SUCC;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&rs, uarg, sizeof(rs))) {
		pr_err("[SCHED_RTG] CMD_ID_SET_CONFIG copy data failed\n");
		return -INVALID_ARG;
	}
	if ((rs.len <= 0) || (rs.len >= MAX_DATA_LEN)) {
		pr_err("[SCHED_RTG] CMD_ID_SET_CONFIG data len invalid\n");
		return -INVALID_ARG;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	switch (abi) {
	case IOCTL_ABI_ARM32:
		ret = copy_from_user(&temp,
			(void __user *)compat_ptr((compat_uptr_t)rs.data), rs.len);
		break;
	case IOCTL_ABI_AARCH64:
		ret = copy_from_user(&temp, (void __user *)rs.data, rs.len);
		break;
	default:
		pr_err("[SCHED_RTG] abi format error\n");
		return -INVALID_ARG;
	}
	if (ret) {
		pr_err("[SCHED_RTG] CMD_ID_SET_CONFIG copy rs.data failed\n");
		return -INVALID_ARG;
	}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	temp[rs.len] = '\0';
	rs.data = &temp;
#pragma GCC diagnostic pop

	return parse_config(&rs);
}

static inline bool is_valid_type(int type)
{
	return (type >= VIP && type < RTG_TYPE_MAX);
}

static int parse_rtg_attr(const struct rtg_str_data *rs_data)
{
	char *p = NULL;
	char *tmp = NULL;
	char *data = NULL;
	int value;
	struct frame_info *frame_info = NULL;
	int rate = -1;
	int type = -1;

	if (rs_data == NULL) {
		pr_err("[SCHED_RTG] rtg attr: rs_data is null!\n");
		return -INVALID_ARG;
	}

	data = rs_data->data;
	if ((data == NULL) || (rs_data->len <= 0) ||
		(rs_data->len > MAX_DATA_LEN)) {
		pr_err("[SCHED_RTG] rtg attr: rs_data len err!\n");
		return -INVALID_ARG;
	}

	// eg: rtgId:xx;rate:xx;type:xx;
	for (p = strsep(&data, ";"); p != NULL; p = strsep(&data, ";")) {
		tmp = strsep(&p, ":");
		if ((tmp == NULL) || (p == NULL))
			continue;
		if (kstrtoint((const char *)p, DECIMAL, &value)) {
			pr_err("[SCHED_RTG] rtg attr: rs_data format err!\n");
			return -INVALID_ARG;
		}
		if (!strcmp(tmp, "rtgId")) {
			frame_info = rtg_frame_info(value);
		} else if (!strcmp(tmp, "rate")) {
			rate = value;
		} else if (!strcmp(tmp, "type")) {
			if (is_valid_type(value)) {
				type = value;
			} else {
				pr_err("[SCHED_RTG] invalid type : %d\n", value);
				return -INVALID_ARG;
			}
		} else {
			pr_err("[SCHED_RTG] parse rtg attr failed!\n");
			return -INVALID_ARG;
		}
	}

	if (!frame_info) {
		pr_err("[SCHED_RTG] rtg attr: invalid args!\n");
		return -INVALID_ARG;
	}

	if (rate > 0)
		set_frame_rate(frame_info, rate);

	if (is_valid_type(type)) {
		if (update_rt_frame_num(frame_info, type, UPDATE_RTG_FRAME)) {
			pr_err("[SCHED_RTG] set rtg attr failed!\n");
			return -INVALID_ARG;
		}

		set_frame_prio(frame_info, (type == NORMAL_TASK ?
			       NOT_RT_PRIO : (type + DEFAULT_RT_PRIO)));
	}

	return SUCC;
}

static long ctrl_set_rtg_attr(int abi, void __user *uarg)
{
	struct rtg_str_data rs;
	char temp[MAX_DATA_LEN];
	int ret;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&rs, uarg, sizeof(rs))) {
		pr_err("[SCHED_RTG] CMD_ID_SET_RTG_ATTR copy data failed\n");
		return -INVALID_ARG;
	}
	if ((rs.len <= 0) || (rs.len >= MAX_DATA_LEN)) {
		pr_err("[SCHED_RTG] CMD_ID_SET_RTG_ATTR data len invalid\n");
		return -INVALID_ARG;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	switch (abi) {
	case IOCTL_ABI_ARM32:
		ret = copy_from_user(&temp,
			(void __user *)compat_ptr((compat_uptr_t)rs.data), rs.len);
		break;
	case IOCTL_ABI_AARCH64:
		ret = copy_from_user(&temp, (void __user *)rs.data, rs.len);
		break;
	default:
		pr_err("[SCHED_RTG] abi format error\n");
		return -INVALID_ARG;
	}
#pragma GCC diagnostic pop

	if (ret) {
		pr_err("[SCHED_RTG] CMD_ID_SET_RTG_ATTR copy rs.data failed with ret %d\n", ret);
		return -INVALID_ARG;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	temp[rs.len] = '\0';
	rs.data = &temp;
#pragma GCC diagnostic pop

	return parse_rtg_attr(&rs);
}

static void start_frame_freq(struct frame_info *frame_info)
{
	if (!frame_info)
		return;

	if (atomic_read(&frame_info->start_frame_freq) == 0) {
		atomic_set(&frame_info->start_frame_freq, 1);
		set_frame_sched_state(frame_info, true);
	}
}

static void set_frame(struct frame_info *frame_info, int margin)
{
	if (!frame_info)
		return;

	atomic_set(&frame_info->frame_state, FRAME_DRAWING);
	if (set_frame_margin(frame_info, margin) == SUCC)
		set_frame_timestamp(frame_info, FRAME_START);
}

static void reset_frame(struct frame_info *frame_info)
{
	if (!frame_info)
		return;

	if (atomic_read(&frame_info->frame_state) == FRAME_END_STATE) {
		pr_debug("[SCHED_RTG]: Frame state is already reset\n");
		return;
	}

	atomic_set(&frame_info->frame_state, FRAME_END_STATE);
	set_frame_timestamp(frame_info, FRAME_END);
}

int update_frame_state(int grp_id, int margin, bool in_frame)
{
	struct frame_info *frame_info = NULL;

	frame_info = lookup_frame_info_by_grp_id(grp_id);
	if (!frame_info || !frame_info->rtg)
		return -INVALID_RTG_ID;

	if (in_frame) {
		start_frame_freq(frame_info);
		set_frame(frame_info, margin);
		trace_rtg_frame_sched(grp_id, "margin", margin);
	} else {
		reset_frame(frame_info);
	}

	return SUCC;
}

static long ctrl_frame_state(void __user *uarg, bool is_enter)
{
	struct proc_state_data state_data;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&state_data, uarg, sizeof(state_data))) {
		pr_err("[SCHED_RTG] CMD_ID_FRAME_FREQ copy data failed\n");
		return -INVALID_ARG;
	}

	return update_frame_state(state_data.grp_id, state_data.state_param, is_enter);
}

static long ctrl_begin_frame(int abi, void __user *uarg)
{
	return ctrl_frame_state(uarg, true);
}

static long ctrl_end_frame(int abi, void __user *uarg)
{
	return ctrl_frame_state(uarg, false);
}

static int stop_frame_freq(int gid)
{
	struct frame_info *frame_info = NULL;

	frame_info = lookup_frame_info_by_grp_id(gid);
	if (!frame_info)
		return -INVALID_RTG_ID;

	atomic_set(&frame_info->start_frame_freq, 0);
	set_frame_sched_state(frame_info, false);

	return 0;
}

static long ctrl_end_scene(int abi, void __user *uarg)
{
	int rtg_id;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&rtg_id, uarg, sizeof(int))) {
		pr_err("[SCHED_RTG] CMD_ID_END_SCENE copy data failed\n");
		return -INVALID_ARG;
	}

	return stop_frame_freq(rtg_id);
}

static int set_min_util(int gid, int min_util)
{
	struct frame_info *frame_info = NULL;

	frame_info = lookup_frame_info_by_grp_id(gid);
	if (!frame_info)
		return -FRAME_ERR_PID;

	set_frame_min_util(frame_info, min_util, false);

	return SUCC;
}

static long ctrl_set_min_util(int abi, void __user *uarg)
{
	struct proc_state_data state_data;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&state_data, uarg, sizeof(state_data))) {
		pr_err("[SCHED_RTG] CMD_ID_SET_MIN_UTIL copy data failed\n");
		return -INVALID_ARG;
	}

	return set_min_util(state_data.grp_id, state_data.state_param);
}

static int set_margin(int grp_id, int margin)
{
	struct frame_info *frame_info = NULL;

	frame_info = lookup_frame_info_by_grp_id(grp_id);
	if (!frame_info)
		return -FRAME_ERR_PID;

	set_frame_margin(frame_info, margin);

	return SUCC;
}

static long ctrl_set_margin(int abi, void __user *uarg)
{
	struct proc_state_data state_data;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&state_data, uarg, sizeof(state_data))) {
		pr_err("[SCHED_RTG] CMD_ID_SET_MARGIN copy data failed\n");
		return -INVALID_ARG;
	}

	return set_margin(state_data.grp_id, state_data.state_param);
}

static void clear_rtg_frame_thread(struct frame_info *frame_info, bool reset)
{
	struct frame_thread_info frame_thread_info;
	int i;

	if (!reset && frame_info)
		frame_thread_info.prio = frame_info->prio;
	else
		frame_thread_info.prio = NOT_RT_PRIO;
	for (i = 0; i < MAX_TID_NUM; i++)
		frame_thread_info.thread[i] = -1;
	frame_thread_info.thread_num = MAX_TID_NUM;
	update_frame_thread_info(frame_info, &frame_thread_info);
	if (reset) {
		atomic_set(&frame_info->max_rt_thread_num, DEFAULT_MAX_RT_THREAD);
		atomic_set(&frame_info->frame_sched_state, 0);
		trace_rtg_frame_sched(frame_info->rtg->id, "FRAME_SCHED_ENABLE", 0);
	}
}

static void copy_proc_from_rsdata(struct rtg_proc_data *proc_info,
	const struct rtg_grp_data *rs_data)
{
	memset(proc_info, 0, sizeof(struct rtg_proc_data));
	proc_info->type = VIP;
	proc_info->rtcnt = DEFAULT_MAX_RT_THREAD;
	if ((rs_data->grp_type > 0) && (rs_data->grp_type < RTG_TYPE_MAX))
		proc_info->type = rs_data->grp_type;
	if ((rs_data->rt_cnt > 0) && (rs_data->rt_cnt < DEFAULT_MAX_RT_THREAD))
		proc_info->rtcnt = rs_data->rt_cnt;
}

static void init_frame_thread_info(struct frame_thread_info *frame_thread_info,
				   const struct rtg_proc_data *proc_info)
{
	int i;
	int type = proc_info->type;

	frame_thread_info->prio = (type == NORMAL_TASK ? NOT_RT_PRIO : (type + DEFAULT_RT_PRIO));
	for (i = 0; i < MAX_TID_NUM; i++)
		frame_thread_info->thread[i] = proc_info->thread[i];
	frame_thread_info->thread_num = MAX_TID_NUM;
}

static int parse_create_rtg_grp(const struct rtg_grp_data *rs_data)
{
	struct rtg_proc_data proc_info;
	struct frame_info *frame_info;
	struct frame_thread_info frame_thread_info;

	copy_proc_from_rsdata(&proc_info, rs_data);
	proc_info.rtgid = alloc_multi_frame_info();
	frame_info = rtg_frame_info(proc_info.rtgid);
	if (!frame_info) {
		pr_err("[SCHED_RTG] no free multi frame.\n");
		return -NO_FREE_MULTI_FRAME;
	}
	atomic_set(&frame_info->max_rt_thread_num, proc_info.rtcnt);
	if (update_rt_frame_num(frame_info, rs_data->grp_type, ADD_RTG_FRAME)) {
		release_multi_frame_info(proc_info.rtgid);
		return -NO_RT_FRAME;
	}
	init_frame_thread_info(&frame_thread_info, &proc_info);
	update_frame_thread_info(frame_info, &frame_thread_info);
	atomic_set(&frame_info->frame_sched_state, 1);
	pr_info("[SCHED_RTG] %s rtgid=%d, type=%d, prio=%d, threadnum=%d, rtnum=%d\n",
		__func__, proc_info.rtgid, rs_data->grp_type,
		frame_thread_info.prio, frame_thread_info.thread_num, proc_info.rtcnt);

	return proc_info.rtgid;
}

static int parse_add_rtg_thread(const struct rtg_grp_data *rs_data)
{
	struct rtg_proc_data proc_info;
	struct frame_info *frame_info;
	int add_index;
	int add_num;
	int prio;
	int fail_num = 0;
	int i;

	if ((rs_data->grp_id <= 0) || (rs_data->grp_id >= MAX_NUM_CGROUP_COLOC_ID))
		return -INVALID_ARG;
	copy_proc_from_rsdata(&proc_info, rs_data);
	frame_info = lookup_frame_info_by_grp_id(rs_data->grp_id);
	if (!frame_info) {
		pr_err("[SCHED_RTG] grp not created yet.\n");
		return -INVALID_ARG;
	}
	mutex_lock(&frame_info->lock);
	add_num = rs_data->tid_num;
	if ((frame_info->thread_num < 0) || (add_num < 0)) {
		mutex_unlock(&frame_info->lock);
		pr_err("[SCHED_RTG] Unexception err: frame_info num < 0.\n");
		return -INVALID_RTG_ID;
	}
	if (frame_info->thread_num + add_num > MAX_TID_NUM) {
		mutex_unlock(&frame_info->lock);
		return -INVALID_RTG_ID;
	}
	add_index = frame_info->thread_num;
	prio = (proc_info.type == NORMAL_TASK) ? NOT_RT_PRIO : frame_info->prio;
	for (i = 0; i < add_num; i++) {
		frame_info->thread[add_index] = update_frame_thread(frame_info, prio, prio,
								    rs_data->tids[i],
								    frame_info->thread[add_index]);
		if (frame_info->thread[add_index]) {
			atomic_set(&frame_info->thread_prio[add_index], prio);
			frame_info->thread_num++;
			add_index = frame_info->thread_num;
		} else {
			fail_num++;
		}
	}
	mutex_unlock(&frame_info->lock);

	return fail_num;
}

static int parse_remove_thread(const struct rtg_grp_data *rs_data)
{
	pr_err("[SCHED_RTG] frame rtg not support remove single yet.\n");

	return -INVALID_ARG;
}

static int do_clear_or_destroy_grp(const struct rtg_grp_data *rs_data, bool destroy)
{
	struct frame_info *frame_info;
	int type;
	int id = rs_data->grp_id;

	if (!is_frame_rtg(id)) {
		pr_err("[SCHED_RTG] Failed to destroy rtg group %d!\n", id);
		return -INVALID_ARG;
	}

	frame_info = rtg_frame_info(id);
	if (!frame_info) {
		pr_err("[SCHED_RTG] Failed to destroy rtg group %d: grp not exist.\n", id);
		return -INVALID_ARG;
	}

	type = frame_info->prio - DEFAULT_RT_PRIO;
	if (destroy) {
		clear_rtg_frame_thread(frame_info, true);
		release_multi_frame_info(id);
		update_rt_frame_num(frame_info, type, CLEAR_RTG_FRAME);
	} else {
		clear_rtg_frame_thread(frame_info, false);
	}
	pr_info("[SCHED_RTG] %s clear frame(id=%d)\n", __func__, id);

	return SUCC;
}

static int parse_clear_grp(const struct rtg_grp_data *rs_data)
{
	return do_clear_or_destroy_grp(rs_data, false);
}

static int parse_destroy_grp(const struct rtg_grp_data *rs_data)
{
	return do_clear_or_destroy_grp(rs_data, true);
}

long ctrl_set_rtg(int abi, void __user *uarg)
{
	struct rtg_grp_data rs_data;
	long ret;

	if (copy_from_user(&rs_data, uarg, sizeof(rs_data))) {
		pr_err("[SCHED_RTG] CMD_ID_SET_RTG  copy data failed\n");
		return -INVALID_ARG;
	}

	switch (rs_data.rtg_cmd) {
	case CMD_CREATE_RTG_GRP:
		ret = parse_create_rtg_grp(&rs_data);
		break;
	case CMD_ADD_RTG_THREAD:
		ret = parse_add_rtg_thread(&rs_data);
		break;
	case CMD_REMOVE_RTG_THREAD:
		ret = parse_remove_thread(&rs_data);
		break;
	case CMD_CLEAR_RTG_GRP:
		ret = parse_clear_grp(&rs_data);
		break;
	case CMD_DESTROY_RTG_GRP:
		ret = parse_destroy_grp(&rs_data);
		break;
	default:
		return -INVALID_ARG;
	}

	return ret;
}

static long ctrl_list_rtg(int abi, void __user *uarg)
{
	struct rtg_info rs_data;
	long ret;

	if (copy_from_user(&rs_data, uarg, sizeof(rs_data))) {
		pr_err("[SCHED_RTG] CMD_ID_LIST_RTG copy data failed\n");
		return -INVALID_ARG;
	}
	ret = list_rtg_group(&rs_data);
	if (copy_to_user(uarg, &rs_data, sizeof(rs_data))) {
		pr_err("[SCHED_RTG]] CMD_ID_LIST_RTG send data failed\n");
		return -INVALID_ARG;
	}

	return ret;
}

static int list_rtg_thread(struct rtg_grp_data *rs_data)
{
	int num = 0;
	int grp_id = rs_data->grp_id;
	struct frame_info *frame_info = NULL;
	int i;

	frame_info = lookup_frame_info_by_grp_id(grp_id);
	if (!frame_info) {
		pr_err("[SCHED_RTG] Look up for grp %d failed!\n", grp_id);
		return -INVALID_ARG;
	}
	for (i = 0; i < frame_info->thread_num; i++) {
		if (frame_info->thread[i]) {
			rs_data->tids[num] = frame_info->thread[i]->pid;
			num++;
		}
	}
	rs_data->tid_num = num;

	return num;
}

static long ctrl_list_rtg_thread(int abi, void __user *uarg)
{
	struct rtg_grp_data rs_data;
	long ret;

	if (copy_from_user(&rs_data, uarg, sizeof(rs_data))) {
		pr_err("[SCHED_RTG] CMD_ID_LIST_RTG_THREAD copy data failed\n");
		return -INVALID_ARG;
	}
	ret = list_rtg_thread(&rs_data);
	if (copy_to_user(uarg, &rs_data, sizeof(rs_data))) {
		pr_err("[SCHED_RTG]] CMD_ID_LIST_RTG_THREAD send data failed\n");
		return -INVALID_ARG;
	}

	return ret;
}

static long ctrl_search_rtg(int abi, void __user *uarg)
{
	struct proc_state_data search_data;

	if (copy_from_user(&search_data, uarg, sizeof(search_data))) {
		pr_err("[SCHED_RTG] CMD_ID_SEARCH_RTG copy data failed\n");
		return -INVALID_ARG;
	}

	return search_rtg(search_data.state_param);
}

#ifdef CONFIG_SCHED_RTG_AUTHORITY
/*
 * uid-based authority idr table
 */
static struct idr *ua_idr;

static DEFINE_RAW_SPINLOCK(ua_idr_lock);

static struct rtg_authority rtg_auth_super;

static void change_to_super(struct rtg_authority *auth)
{
	auth->flag = AF_RTG_ALL;
	auth->status = AUTH_STATUS_ENABLE;
}

static void init_rtg_authority_record(struct rtg_authority *auth)
{
#ifdef CONFIG_SCHED_RTG_QOS
	int i;
#endif

	auth->flag = 0;
	auth->status = AUTH_STATUS_CACHED;
	raw_spin_lock_init(&auth->auth_lock);
	refcount_set(&auth->usage, 1);
#ifdef CONFIG_SCHED_RTG_QOS
	for (i = 0; i <= NR_QOS; ++i) {
		INIT_LIST_HEAD(&auth->tasks[i]);
		auth->num[i] = 0;
	}
#endif
}

void get_rtg_auth(struct rtg_authority *auth)
{
	refcount_inc(&auth->usage);
}

#ifdef CONFIG_SCHED_RTG_QOS
static void remove_qos_tasks(struct rtg_authority *auth)
{
	int i;
	struct task_struct *tmp, *next;

	for (i = 0; i <= NR_QOS; ++i) {
		list_for_each_entry_safe(tmp, next, &auth->tasks[i], qos_list) {
			get_task_struct(tmp);
			tmp->in_qos = 0;
			list_del_init(&tmp->qos_list);
			put_task_struct(tmp);
		}
	}
}
#endif

static void __put_rtg_auth(struct rtg_authority *auth)
{
	WARN_ON(auth->status != AUTH_STATUS_DEAD);
	WARN_ON(refcount_read(&auth->usage));

#ifdef CONFIG_SCHED_RTG_QOS
	/* refcount is zero here, no contend, no lock. */
	remove_qos_tasks(auth);
#endif
	kfree(auth);
}

void put_rtg_auth(struct rtg_authority *auth)
{
	if (refcount_dec_and_test(&auth->usage))
		__put_rtg_auth(auth);
}

int init_rtg_authority_control(void)
{
	int ret;

	ua_idr = kzalloc(sizeof(*ua_idr), GFP_ATOMIC);
	if (ua_idr == NULL) {
		pr_err("[SCHED_RTG] rtg idr init failed, no memory!\n");
		return -ENOMEM;
	}

	idr_init(ua_idr);

	init_rtg_authority_record(&rtg_auth_super);
	change_to_super(&rtg_auth_super);

	ret = idr_alloc(ua_idr, &rtg_auth_super, UID_FOR_SUPER, UID_FOR_SUPER + 1, GFP_ATOMIC);
	if (ret != UID_FOR_SUPER) {
		pr_err("[SCHED_RTG] rtg authority for super init failed! ret=%d\n", ret);
		goto err;
	}

	return 0;

err:
	idr_destroy(ua_idr);
	kfree(ua_idr);

	return ret;
}

int authority_remove_handler(int id, void *p, void *para)
{
	struct rtg_authority *auth = (struct rtg_authority *)p;

	raw_spin_lock(&auth->auth_lock);
#ifdef CONFIG_SCHED_RTG_QOS
	qos_pause(auth);
#endif
	auth->status = AUTH_STATUS_DEAD;
	raw_spin_unlock(&auth->auth_lock);
	put_rtg_auth(auth);

	return 0;
}

void remove_rtg_authority_control(void)
{
	int ret;

	raw_spin_lock(&ua_idr_lock);
	ret = idr_for_each(ua_idr, authority_remove_handler, NULL);
	if (ret < 0)
		pr_err("[SCHED_RTG] rtg authority item remove failed\n");

	idr_destroy(ua_idr);
	kfree(ua_idr);

	raw_spin_unlock(&ua_idr_lock);
}

static int auth_trim(unsigned int ua_flag)
{
	return ua_flag & AF_RTG_DELEGATED;
}

static int auth_enable(struct rtg_auth_data *data)
{
	struct rtg_authority *auth_to_enable;
	unsigned int uid = data->uid;
	bool enable = (data->status == AUTH_STATUS_ENABLE);
	int ret;

	raw_spin_lock(&ua_idr_lock);
	auth_to_enable = idr_find(ua_idr, uid);
	/* auth exist, just resume the task's qos request */
	if (auth_to_enable) {
		get_rtg_auth(auth_to_enable);
		raw_spin_unlock(&ua_idr_lock);

		raw_spin_lock(&auth_to_enable->auth_lock);
		if (auth_to_enable->status == AUTH_STATUS_DEAD) {
			raw_spin_unlock(&auth_to_enable->auth_lock);
			put_rtg_auth(auth_to_enable);
			return -INVALID_AUTH;
		}

		auth_to_enable->flag = auth_trim(data->ua_flag);
#ifdef CONFIG_SCHED_RTG_QOS
		if (enable)
			qos_resume(auth_to_enable);
#endif
		raw_spin_unlock(&auth_to_enable->auth_lock);
		ret = 0;
		put_rtg_auth(auth_to_enable);
		goto out;
	}

	/* auth not exist, build a new auth, then insert to idr */
	auth_to_enable = kzalloc(sizeof(*auth_to_enable), GFP_ATOMIC);
	if (!auth_to_enable) {
		raw_spin_unlock(&ua_idr_lock);
		pr_err("[SCHED_RTG] alloc auth data failed, no memory!\n");
		ret = -ENOMEM;
		goto out;
	}

	init_rtg_authority_record(auth_to_enable);

	/* no one could get the auth from idr now, no need to lock */
	auth_to_enable->flag = auth_trim(data->ua_flag);
	if (enable)
		auth_to_enable->status = AUTH_STATUS_ENABLE;

	ret = idr_alloc(ua_idr, auth_to_enable, uid, uid + 1, GFP_ATOMIC);
	if (ret < 0) {
		pr_err("[SCHED_RTG] add auth to idr failed, no memory!\n");
		kfree(auth_to_enable);
	}

	raw_spin_unlock(&ua_idr_lock);

out:
	return ret;
}

static int auth_pause(struct rtg_auth_data *data)
{
	struct rtg_authority *auth_to_pause;
	unsigned int uid = data->uid;

	raw_spin_lock(&ua_idr_lock);
	auth_to_pause = idr_find(ua_idr, uid);
	if (!auth_to_pause) {
		raw_spin_unlock(&ua_idr_lock);
		pr_err("[SCHED_RTG] no auth data for this uid to pause=%d\n", uid);
		return UID_NOT_FOUND;
	}
	get_rtg_auth(auth_to_pause);
	raw_spin_unlock(&ua_idr_lock);

	raw_spin_lock(&auth_to_pause->auth_lock);
	if (auth_to_pause->status == AUTH_STATUS_DEAD) {
		raw_spin_unlock(&auth_to_pause->auth_lock);
		put_rtg_auth(auth_to_pause);
		return -INVALID_AUTH;
	}
#ifdef CONFIG_SCHED_RTG_QOS
	qos_pause(auth_to_pause);
#endif
	raw_spin_unlock(&auth_to_pause->auth_lock);

	put_rtg_auth(auth_to_pause);

	return 0;
}

static int auth_delete(struct rtg_auth_data *data)
{
	struct rtg_authority *auth_to_delete;
	unsigned int uid = data->uid;

	raw_spin_lock(&ua_idr_lock);
	auth_to_delete = (struct rtg_authority *)idr_remove(ua_idr, uid);
	if (!auth_to_delete) {
		raw_spin_unlock(&ua_idr_lock);
		pr_err("[SCHED_RTG] no auth data for this uid=%d, delete failed\n", uid);
		return -UID_NOT_FOUND;
	}
	raw_spin_unlock(&ua_idr_lock);

	raw_spin_lock(&auth_to_delete->auth_lock);
#ifdef CONFIG_SCHED_RTG_QOS
	qos_pause(auth_to_delete);
#endif
	auth_to_delete->status = AUTH_STATUS_DEAD;
	raw_spin_unlock(&auth_to_delete->auth_lock);

	put_rtg_auth(auth_to_delete);

	return 0;
}

static int auth_get(struct rtg_auth_data *data)
{
	struct rtg_authority *auth_to_get;
	unsigned int uid = data->uid;

	raw_spin_lock(&ua_idr_lock);
	auth_to_get = idr_find(ua_idr, uid);
	if (!auth_to_get) {
		raw_spin_unlock(&ua_idr_lock);
		pr_err("[SCHED_RTG] no auth data for this uid=%d to get\n", uid);
		return -UID_NOT_FOUND;
	}
	get_rtg_auth(auth_to_get);
	raw_spin_unlock(&ua_idr_lock);

	raw_spin_lock(&auth_to_get->auth_lock);
	if (auth_to_get->status == AUTH_STATUS_DEAD) {
		raw_spin_unlock(&auth_to_get->auth_lock);
		put_rtg_auth(auth_to_get);
		return -INVALID_AUTH;
	}
	data->ua_flag = auth_to_get->flag;
	data->status = auth_to_get->status;
	raw_spin_unlock(&auth_to_get->auth_lock);

	put_rtg_auth(auth_to_get);

	return 0;
}

typedef int (*rtg_auth_manipulate_func)(struct rtg_auth_data *data);

static rtg_auth_manipulate_func auth_func_array[AUTH_MAX_NR] = {
	NULL,
	auth_enable,  //1
	auth_pause,
	auth_delete,
	auth_get,
};

static long do_auth_manipulate(struct rtg_auth_data *data)
{
	long ret = 0;
	unsigned int type = data->type;

	if (type >= AUTH_MAX_NR) {
		pr_err("[SCHED_RTG] CMD_ID_AUTH_MANIPULATE type not valid\n");
		return -INVALID_ARG;
	}

	if (auth_func_array[type])
		ret = (long)(*auth_func_array[type])(data);

	return ret;
}

static long ctrl_auth_manipulate(int abi, void __user *uarg)
{
	struct rtg_auth_data auth_data;
	long ret;

	if (copy_from_user(&auth_data, uarg, sizeof(struct rtg_auth_data))) {
		pr_err("[SCHED_RTG] CMD_ID_AUTH_MANIPULATE copy data failed\n");
		return -INVALID_ARG;
	}

	ret = do_auth_manipulate(&auth_data);
	if (ret < 0) {
		pr_err("[SCHED_RTG]] CMD_ID_AUTH_MANIPULATE failed\n");
		return ret;
	}

	if (copy_to_user(uarg, &auth_data, sizeof(struct rtg_auth_data))) {
		pr_err("[SCHED_RTG]] CMD_ID_AUTH_MANIPULATE send data failed\n");
		return -INVALID_ARG;
	}

	return 0;
}

#define get_authority_flag(func_id)	(1 << (func_id - 1))

static inline unsigned int get_true_uid(struct task_struct *p)
{
	if (!p)
		return get_uid(current_user())->uid.val;

	return task_uid(p).val;
}

/*
 * Return 1000 for both SYSTEM and ROOT
 */
static inline unsigned int get_authority_uid(struct task_struct *p)
{
	unsigned int uid = get_true_uid(p);

	if (super_uid(uid))
		uid = UID_FOR_SUPER;

	return uid;
}

static bool rtg_check_authorized(unsigned int func_id)
{
	bool authorized = false;
	struct rtg_authority *auth;
	unsigned int af = get_authority_flag(func_id);
	unsigned int uid = get_authority_uid(NULL);

	raw_spin_lock(&ua_idr_lock);
	if (!ua_idr) {
		raw_spin_unlock(&ua_idr_lock);
		pr_err("[SCHED_RTG] authority idr table missed, auth failed\n");
		return authorized;
	}

	auth = (struct rtg_authority *)idr_find(ua_idr, uid);
	if (!auth) {
		raw_spin_unlock(&ua_idr_lock);
		pr_err("[SCHED_RTG] no auth data for this uid=%d\n", uid);
		return authorized;
	}
	get_rtg_auth(auth);
	raw_spin_unlock(&ua_idr_lock);

	raw_spin_lock(&auth->auth_lock);
	if (auth->status == AUTH_STATUS_DEAD) {
		raw_spin_unlock(&auth->auth_lock);
		pr_info("[SCHED_RTG] not valied auth for uid %d\n", uid);
		put_rtg_auth(auth);
		return authorized;
	}
	if (auth && (auth->flag & af))
		authorized = true;

	raw_spin_unlock(&auth->auth_lock);

	put_rtg_auth(auth);

	return authorized;
}

/*
 * Return RTG authority info for given task
 * return current's auth if p is NULL
 * recount will inc if this call return the valid auth
 * make sure to call put_rtg_auth before the calling end
 */
struct rtg_authority *get_authority(struct task_struct *p)
{
	unsigned int uid = get_authority_uid(NULL);
	struct rtg_authority *auth;

	raw_spin_lock(&ua_idr_lock);
	auth = idr_find(ua_idr, uid);
	if (auth)
		get_rtg_auth(auth);
	raw_spin_unlock(&ua_idr_lock);

	return auth;
}

#ifdef CONFIG_SCHED_RTG_QOS
static rtg_qos_manipulate_func qos_func_array[QOS_MAX_NR] = {
	NULL,
	qos_apply,  //1
	qos_leave,
};

static long do_qos_manipulate(struct rtg_qos_data *data)
{
	long ret = 0;
	unsigned int type = data->type;

	if (type >= QOS_MAX_NR) {
		pr_err("[SCHED_RTG] CMD_ID_QOS_MANIPULATE type not valid\n");
		return -INVALID_ARG;
	}

	if (qos_func_array[type])
		ret = (long)(*qos_func_array[type])(data);

	return ret;
}

static long ctrl_qos_manipulate(int abi, void __user *uarg)
{
	struct rtg_qos_data qos_data;

	if (copy_from_user(&qos_data, uarg, sizeof(struct rtg_qos_data))) {
		pr_err("[SCHED_RTG] CMD_ID_QOS_APPLY copy data failed\n");
		return -INVALID_ARG;
	}

	return do_qos_manipulate(&qos_data);
}
#endif
#endif /* CONFIG_SCHED_RTG_AUTHORITY */

static long do_proc_rtg_ioctl(int abi, struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)(uintptr_t)arg;
	unsigned int func_id = _IOC_NR(cmd);

	if (uarg == NULL) {
		pr_err("[SCHED_RTG] %s: invalid user uarg\n", __func__);
		return -EINVAL;
	}

#ifdef CONFIG_SCHED_RTG_AUTHORITY
	if (!rtg_check_authorized(func_id)) {
		pr_err("[SCHED_RTG] %s: uid not authorized\n", __func__);
		return -UID_NOT_AUTHORIZED;
	}
#endif

	if (_IOC_TYPE(cmd) != RTG_SCHED_IPC_MAGIC) {
		pr_err("[SCHED_RTG] %s: RTG_SCHED_IPC_MAGIC fail, TYPE=%d\n",
			__func__, _IOC_TYPE(cmd));
		return -INVALID_MAGIC;
	}

	if (!atomic_read(&g_rtg_enable) && (func_id != SET_ENABLE) && (func_id != GET_ENABLE)) {
		pr_err("[SCHED_RTG] CMD_ID %x error: Rtg not enabled yet.\n", cmd);
		return -RTG_DISABLED;
	}

	if (func_id >= RTG_CTRL_MAX_NR) {
		pr_err("[SCHED_RTG] %s: RTG_MAX_NR fail, _IOC_NR(cmd)=%d, MAX_NR=%d\n",
			__func__, _IOC_NR(cmd), RTG_CTRL_MAX_NR);
		return -INVALID_CMD;
	}

	if (g_func_array[func_id] != NULL)
		return (*g_func_array[func_id])(abi, uarg);

	return -EINVAL;
}

static void reset_frame_info(struct frame_info *frame_info)
{
	int i;
	clear_rtg_frame_thread(frame_info, true);
	atomic_set(&frame_info->frame_state, -1);
	atomic_set(&frame_info->curr_rt_thread_num, 0);
	atomic_set(&frame_info->max_rt_thread_num, DEFAULT_MAX_RT_THREAD);
	for (i = 0; i < MAX_TID_NUM; i++)
		atomic_set(&frame_info->thread_prio[i], 0);
}

static int do_init_proc_state(int rtgid, const int *config, int len)
{
	struct related_thread_group *grp = NULL;
	struct frame_info *frame_info = NULL;

	grp = lookup_related_thread_group(rtgid);
	if (unlikely(!grp))
		return -EINVAL;

	frame_info = (struct frame_info *)grp->private_data;
	if (!frame_info)
		return -EINVAL;

	reset_frame_info(frame_info);

	if ((config[RTG_FREQ_CYCLE] >= MIN_FREQ_CYCLE) &&
		(config[RTG_FREQ_CYCLE] <= MAX_FREQ_CYCLE))
		sched_set_group_freq_update_interval(rtgid,
				(unsigned int)config[RTG_FREQ_CYCLE]);
	else
		sched_set_group_freq_update_interval(rtgid,
				DEFAULT_FREQ_CYCLE);

	if (config[RTG_INVALID_INTERVAL] != INVALID_VALUE)
		sched_set_group_util_invalid_interval(rtgid,
				config[RTG_INVALID_INTERVAL]);
	else
		sched_set_group_util_invalid_interval(rtgid,
				DEFAULT_INVALID_INTERVAL);

	set_frame_max_util(frame_info, g_frame_max_util);

	return SUCC;
}

static int init_proc_state(const int *config, int len)
{
	int ret;
	int id;

	if ((config == NULL) || (len != RTG_CONFIG_NUM))
		return -INVALID_ARG;

	if ((config[RTG_FRAME_MAX_UTIL] > 0) &&
		(config[RTG_FRAME_MAX_UTIL] < DEFAULT_MAX_UTIL))
		g_frame_max_util = config[RTG_FRAME_MAX_UTIL];

	for (id = MULTI_FRAME_ID; id < (MULTI_FRAME_ID + MULTI_FRAME_NUM); id++) {
		ret = do_init_proc_state(id, config, len);
		if (ret) {
			pr_err("[SCHED_RTG] init proc state for FRAME_ID=%d failed, ret=%d\n",
			       id, ret);
			return ret;
		}
	}
	atomic_set(&g_rt_frame_num, 0);

	return SUCC;
}

static void deinit_proc_state(void)
{
	int id;
	struct frame_info *frame_info = NULL;
	struct related_thread_group *grp = NULL;

	for (id = MULTI_FRAME_ID; id < (MULTI_FRAME_ID + MULTI_FRAME_NUM); id++) {
		grp = lookup_related_thread_group(id);
		if (unlikely(!grp))
			return;

		frame_info = (struct frame_info *)grp->private_data;
		if (frame_info)
			reset_frame_info(frame_info);
	}
	clear_multi_frame_info();
	atomic_set(&g_rt_frame_num, 0);
}

int proc_rtg_open(struct inode *inode, struct file *filp)
{
	return SUCC;
}

static int proc_rtg_release(struct inode *inode, struct file *filp)
{
	return SUCC;
}

long proc_rtg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return do_proc_rtg_ioctl(IOCTL_ABI_AARCH64, file, cmd, arg);
}

#ifdef CONFIG_COMPAT
long proc_rtg_compat_ioctl(struct file *file,
				  unsigned int cmd, unsigned long arg)
{
	return do_proc_rtg_ioctl(IOCTL_ABI_ARM32, file, cmd,
		(unsigned long)(compat_ptr((compat_uptr_t)arg)));
}
#endif

static const struct file_operations rtg_ctrl_fops = {
	.open = proc_rtg_open,
	.release = proc_rtg_release,
	.unlocked_ioctl = proc_rtg_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= proc_rtg_compat_ioctl,
#endif
};

static struct miscdevice rtg_ctrl_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sched_rtg_ctrl",
	.fops = &rtg_ctrl_fops,
	.mode = 0666,
};

static int __init rtg_ctrl_dev_init(void)
{
	return misc_register(&rtg_ctrl_device);
}

static void __exit rtg_ctrl_dev_exit(void)
{
	misc_deregister(&rtg_ctrl_device);
#ifdef CONFIG_SCHED_RTG_AUTHORITY
	remove_rtg_authority_control();
#endif
}

module_init(rtg_ctrl_dev_init);
module_exit(rtg_ctrl_dev_exit);
