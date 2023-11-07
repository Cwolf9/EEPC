/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_spc.c
 *
 * Copyright (c) 2022-2023 ECNU BDIS Lab.
 */

#include "hmdfs_spc.h"
#include "hmdfs_spc_ext.h"
#include "hmdfs_client.h"
#include "comm/transport.h"
#include "comm/connection.h"

int pcache_mode;

// global
struct hmdfs_sb_info *spc_sbi;
spinlock_t spc_peer_lock;
// DEFINE_SPINLOCK(ft_info_list_lock);
struct spc_peer local_peer;
struct list_head spc_peer_list_head;
uint32_t spc_peer_list_len = -1;
struct timer_list net_timer;
struct timer_list scr_timer;
struct task_struct *comm_handler;
struct task_struct *cache_syncer;
int64_t delayed_req_size;
spinlock_t spc_log_lock;

struct list_head getattr_req_list_head;
int spc_coverage;

// static
static bool g_is_init = false;
static int timer_expire_tmp;
static int readpage_expire;
static int active_polling_period;
static int flag_getattr_use_cache = 0;
static char tmpbuf[128];
static struct file *logfilep;
static loff_t logpos;


int spc_rand_int(int flag) 
{
    int ret;

    get_random_bytes(&ret, sizeof(ret));
    if(flag == 0 && ret < 0) ret = -ret;

    return ret;
}

void msock_release(struct socket **sock) 
{
    if (*sock)
        sock_release(*sock);
    *sock = NULL;
}

int safely_quit_kthread(struct task_struct **task) 
{
    int err;
    int tsk1_state;
    struct task_struct *ktask = *task;
    if (!IS_ERR_OR_NULL(ktask)) {
        tsk1_state = ktask->state;
        spc_info(
            "pid, tsk1_state, exit_state, exit_code, exit_signal:"
            " %d %d %d %d %d\n",
            ktask->pid, tsk1_state,  // TASK_DEAD 128 TASK_WAKEKILL
            ktask->exit_state,       // EXIT_DEAD 16
            ktask->exit_code,        // 0 normal
            ktask->exit_signal);     // SIGCHLD 17; 被置为-1表示是某个线程组中的一元。只有当线程组最后一个成员终止时，才会产生一个信号，以通知线程组的领头进程的父进程。
        // CSDN huzai9527 https://dude6.com/article/390309.html
        if (tsk1_state >= 0 && tsk1_state <= 8 && ktask->exit_state == 0 && ktask->exit_signal != -1) {
            //调用stop前，线程必须还在。如果新创建的进程没有调用函数wake_up_process( )唤醒，则此函数返回-EINTR
            err = kthread_stop(ktask);  // err 返回值 9 11
            //进程退出状态码 11 SIGSEGV https://winddoing.github.io/post/7653.html
            spc_info("kthread_stop: %d", err);
            *task = NULL;
            return err;
        }
        // put_task_struct(ktask);
        *task = NULL;
    }
    return -2;
}

struct task_struct * spc_pid_get_task_struct(int dst_pid) {
    struct task_struct *dst_task;
    if (dst_pid <= 0)
        return NULL;
    rcu_read_lock();
    dst_task = pid_task(find_vpid(dst_pid), PIDTYPE_PID);
    rcu_read_unlock();
    if(IS_ERR_OR_NULL(dst_task)) return NULL;
    return dst_task;
}

// include/linux/inet.h: inet_pton_with_scope => inet4_pton
// net/core/utils.c
// 219.228.60.52 <-> 876405979
int tv_inet4_pton(const char *src, u16 port_num, struct sockaddr_storage *addr) 
{
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
    int srclen = strlen(src);
    if (srclen > INET_ADDRSTRLEN)
        return -EINVAL;
    if (in4_pton(src, srclen, (u8 *)&addr4->sin_addr.s_addr,
                 '\n', NULL) == 0)
        return -EINVAL;
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port_num);
    return 0;
}



// 注意释放内存
char *connect_str_name(const char *prename, const char *ipaddr, unsigned short port)
{
    int slen = strlen(prename);
    int iplen = strlen(ipaddr);
    int ilen = 0;
    char *task_name = kzalloc(64, GFP_KERNEL);
    memcpy(task_name, prename, slen);
    ilen += slen;
    memcpy(task_name + ilen, ipaddr, iplen);
    ilen += iplen;
    memcpy(task_name + ilen, ":", 1);
    ilen += 1;
    int idst = ilen;
    while (port > 0) {
        char c = port % 10 + '0';
        task_name[ilen] = c;
        ilen += 1;
        port /= 10;
    }
    ilen -= 1;
    while (idst < ilen) {
        char c = task_name[idst];
        task_name[idst] = task_name[ilen];
        task_name[ilen] = c;
        idst++;
        ilen--;
    }
    return task_name;
}

void resolve_ipport_str(const char *str, char *ipaddr, unsigned short *port)
{
    int slen = strlen(str), idx = 0, ipi = 0;
    while (idx < slen && str[idx] != ':') idx++;
    idx++;
    while (idx < slen && str[idx] != ':') {
        ipaddr[ipi] = str[idx];
        ipi += 1;
        idx++;
    }
    idx++;
    *port = 0;
    while (idx < slen) {
        *port = (*port) * 10 + str[idx] - '0';
        idx++;
    }
}

void get_ipport_by_sock(struct socket *dst_sock, char *dst_ipaddr, int *dst_port) 
{
    struct sockaddr_in caddr;

    if(!dst_sock || !dst_ipaddr) {
        return ;
    }
    // 876405979 219.228.60.52
    kernel_getpeername(dst_sock, (struct sockaddr *)&caddr);
    sprintf(dst_ipaddr, "%pI4", &caddr.sin_addr);
    if(dst_port) {
        *dst_port = ntohs(caddr.sin_port);
    }
}

int sync_device_cache(int did, int clear) 
{
    int ret = 0;
    int err = 0;
    struct spc_peer *dst_peer;
    struct spc_peer *sp_node = NULL, *sp_node_next = NULL;
    struct spc_delayed_req *req = NULL, *req_next = NULL;
    struct file *filep = NULL;
    uint32_t req_size;

    spin_lock(&spc_peer_lock);
    list_for_each_entry_safe(sp_node, sp_node_next, &spc_peer_list_head, spcp_node) {
        if(did == 0 || did == sp_node->device_id) {
            spc_change_state_by_did_test(sp_node->device_id, 1);

            dst_peer = sp_node;
            spin_lock(&dst_peer->req_lock);
            list_for_each_entry_safe(req, req_next, &dst_peer->sdr_list_head, dreq_node) {
                uint8_t type = req->type;
                uint32_t spc_did = req->spc_did;
                struct spc_client_writepage_request *wp_req = NULL;

                err = 0;
                req_size = sizeof(struct spc_delayed_req) + sizeof(struct spc_client_writepage_request);
                switch (req->type) {
                case F_WRITEPAGE:
                    // 真正的延迟处理，其实需要从 open 开始到 release 都要造假，用本地结果返回，否则需要构造上层请求，因为这个下层请求发过去时，远端文件已经关闭了
                    // 还不知道为什么不清理写回处理时，close文件时会被阻塞
                    {
                        wp_req = req->req;
                        req_size += strlen(wp_req->filepath) + strlen(wp_req->buf);
                        /*
                        struct hmdfs_peer *con = wp_req->con;
                        struct hmdfs_writepage_context *param = wp_req->param;
                        struct inode *inode = param->page->mapping->host;
                    	struct hmdfs_inode_info *info = hmdfs_i(inode);

                        // ohosAll/sourceCode/ohosv32B2hmdfs/kernel/linux/linux-5.10/include/linux/pagemap.h
                        lock_page(param->page);
                        // ohosAll/sourceCode/ohosv32B2hmdfs/kernel/linux/linux-5.10/include/linux/page-flags.h
                        // ClearPageUptodate(param->page); // https://blog.csdn.net/zhang_shuai_2011/article/details/7107835
                        param->rsem_held = down_read_trylock(&info->wpage_sem);
                        // set_page_dirty(param->page);
                        set_page_writeback(param->page);
                        spc_info("F_WRITEPAGE: page %ld of file %u ", param->page->index, param->fid.id);
                        err = hmdfs_client_writepage(con, param);
                        */
                        int i, len = HMDFS_PAGE_SIZE, pre = 0, firstlen = 0;
                        for(i = 0; i < len; ++i) {
                            if(wp_req->buf[i]) {
                                pre = i;
                                break;
                            }
                        }
                        // 不考虑空洞文件的存在
                        for(i = pre; i < len; ++i) {
                            if(!wp_req->buf[i]) {
                                break;
                            }
                            firstlen += 1;
                        }
                        spc_info("filepath, count, pos, hash: %s %d %d %u, len1, pre: %d %d", wp_req->filepath, wp_req->count, wp_req->pos, req->hashval, firstlen, pre);
                        spc_info("data buf: %s", wp_req->buf);
                        filep = filp_open(wp_req->filepath, O_RDWR | O_CREAT, 0666);
                        if (IS_ERR_OR_NULL(filep)) {
                            err = PTR_ERR(filep);
                            spc_err("open fail %ld", PTR_ERR(filep));
                            goto conti;
                        }
                        err = kernel_write(filep, wp_req->buf, wp_req->count, &wp_req->pos);
                        filp_close(filep, NULL);
                        if (err != wp_req->count) {
                            spc_err("kernel_write error: %d/%d", err, wp_req->count);
                            err = -EIO;
                            // goto conti;
                        }
                        err = 0;
                        ret += 1;
                        kfree(wp_req->filepath);
                        kfree(wp_req->buf);
                        kfree(wp_req);
                        list_del_rcu(&req->dreq_node);
                        kfree(req);
                        dst_peer->sdr_list_len -= 1;
                        delayed_req_size -= req_size;
                    }
                    break;
                case F_SETATTR:
                    break;
                default:
                    break;
                }
                conti:
                    spc_info("sync device %d request %d ret: %d", spc_did, type, err);
                    if(err != 0 && clear == 1) {
                        switch (req->type) {
                        case F_WRITEPAGE:
                        {
                            kfree(wp_req->filepath);
                            kfree(wp_req->buf);
                            kfree(wp_req);
                        }
                            break;
                        case F_SETATTR:
                            break;
                        default:
                            break;
                        }
                        list_del_rcu(&req->dreq_node);
                        kfree(req);
                        dst_peer->sdr_list_len -= 1;
                        delayed_req_size -= req_size;
                    }
            }
            if(clear == 0) {
                mod_timer(&dst_peer->wb_timer, jiffies + (WRITEBACK_EXPIRE_SECOND) * HZ);
            }
            spin_unlock(&dst_peer->req_lock);
        }
    }
    spin_unlock(&spc_peer_lock);
    if(delayed_req_size < 0) delayed_req_size = 0;
    return ret;
}


static void cache_sync_tasker(struct timer_list *tl) 
{
    int err;
    struct spc_peer *dst_peer;

    spc_info("pid: %d, comm: %s", current->pid, current->comm);
    dst_peer = get_a_from_b_field_c(dst_peer, tl, wb_timer);
    sync_device_cache(dst_peer->device_id, 0);
}

struct spc_peer *create_insert_spc_peer(struct socket *dst_sock, char *dst_ipaddr, unsigned short dst_port) 
{
    struct spc_peer *dst_peer = NULL;
    int str_len;
    dst_peer = kmalloc(sizeof(struct spc_peer), GFP_KERNEL);
    if (IS_ERR_OR_NULL(dst_peer)) {
        spc_err("create_insert_spc_peer kmalloc error");
        return NULL;
    }
    dst_peer->state = false;
    dst_peer->device_id = spc_rand_int(0);
    dst_peer->sock = dst_sock;
    dst_peer->ipaddr = kzalloc(64, GFP_KERNEL);
    if (IS_ERR_OR_NULL(dst_peer->ipaddr)) {
        kfree(dst_peer);
        spc_err("create_insert_spc_peer kzalloc error");
        return NULL;
    }
    if (dst_ipaddr) {
        str_len = strlen(dst_ipaddr);
        memcpy(dst_peer->ipaddr, dst_ipaddr, str_len);
    }else {
        get_ipport_by_sock(dst_sock, dst_peer->ipaddr, &dst_port);
        spc_info("create_insert_spc_peer find ip: %s, port: %d", dst_peer->ipaddr, dst_port);
    }
    dst_peer->port = dst_port;
    INIT_LIST_HEAD(&dst_peer->sdr_list_head);
    dst_peer->sdr_list_len = 0;
    timer_setup(&dst_peer->wb_timer, cache_sync_tasker, 0);
    dst_peer->wb_timer.expires = jiffies + (WRITEBACK_EXPIRE_SECOND) * HZ;
    add_timer(&dst_peer->wb_timer);
    
    mutex_init(&dst_peer->send_mutex);
    spin_lock_init(&dst_peer->req_lock);

    INIT_LIST_HEAD(&dst_peer->spcp_node);
    list_add_tail_rcu(&dst_peer->spcp_node, &spc_peer_list_head);
    spc_peer_list_len += 1;

    return dst_peer;
}


int out_spc_peer_info(void) 
{
    int ret = 0;

    spc_info("local_peer, lo state: %d, lo_did: %d, lo_ip: %s, lo_port: %d", local_peer.state, local_peer.device_id, local_peer.ipaddr, local_peer.port);
    spc_info("out_spc_peer_info, list_len: %d", spc_peer_list_len);
    struct spc_peer *sp_node = NULL;
    rcu_read_lock();
    list_for_each_entry_rcu(sp_node, &spc_peer_list_head, spcp_node) {
        spc_info("sp_info, state: %d, de_id: %d, sock: %lX, ip: %s, port: %d, hdid: %lld",
            sp_node->state, sp_node->device_id, (long unsigned int)sp_node->sock, sp_node->ipaddr, sp_node->port, sp_node->hmdfs_device_id);
        // ret += 1;
        ret = sp_node->device_id;
    }
    rcu_read_unlock();
    return ret;
}

int spc_peer_list_task_kill(void) 
{
    int err = 0;
    struct spc_peer *sp_node = NULL, *sp_node_next = NULL;

    spin_lock(&spc_peer_lock);
    list_for_each_entry_safe(sp_node, sp_node_next, &spc_peer_list_head, spcp_node) {
        err = safely_quit_kthread(&sp_node->caller);
    }
    spin_unlock(&spc_peer_lock);
    return err;
}

int spc_peer_list_destory(void) 
{
    int err = 0;
    struct spc_peer *sp_node = NULL, *sp_node_next = NULL;

    sync_device_cache(0, 1);
    spin_lock(&spc_peer_lock);
    list_for_each_entry_safe(sp_node, sp_node_next, &spc_peer_list_head, spcp_node) {
        // TODO:
        del_timer_sync(&sp_node->wb_timer);
        kfree(sp_node->ipaddr);
        msock_release(&sp_node->sock);
        err = safely_quit_kthread(&sp_node->caller);
        list_del_rcu(&sp_node->spcp_node);
        kfree(sp_node);
        spc_peer_list_len -= 1;
    }
    spc_peer_list_len = 0;
    spin_unlock(&spc_peer_lock);
    return err;
}

struct spc_peer *find_spc_peer_by_did(uint64_t did) 
{
    struct spc_peer *sp_node = NULL, *ret = NULL;
    rcu_read_lock();
    list_for_each_entry_rcu(sp_node, &spc_peer_list_head, spcp_node) {
        if(sp_node->device_id == did) {
            ret = sp_node;
        }
    }
    rcu_read_unlock();
    return ret;
}

struct spc_peer *find_spc_peer_by_hdid(uint64_t hdid) 
{
    struct spc_peer *sp_node = NULL, *ret = NULL;
    rcu_read_lock();
    list_for_each_entry_rcu(sp_node, &spc_peer_list_head, spcp_node) {
        if(sp_node->hmdfs_device_id == hdid) {
            ret = sp_node;
        }
    }
    rcu_read_unlock();
    return ret;
}

struct spc_peer *find_spc_peer_by_ipport(char *ipaddr, unsigned short port) 
{
    struct spc_peer *sp_node = NULL, *ret = NULL;
    if(ipaddr == NULL) 
        return ret;
    rcu_read_lock();
    list_for_each_entry_rcu(sp_node, &spc_peer_list_head, spcp_node) {
        if(sp_node->port == port && strncmp(sp_node->ipaddr, ipaddr, strlen(ipaddr)) == 0) {
            ret = sp_node;
        }
    }
    rcu_read_unlock();
    return ret;
}

struct spc_peer *find_spc_peer_by_ip(char *ipaddr) 
{
    struct spc_peer *sp_node = NULL, *ret = NULL;
    if(ipaddr == NULL) 
        return ret;
    rcu_read_lock();
    list_for_each_entry_rcu(sp_node, &spc_peer_list_head, spcp_node) {
        if(strncmp(sp_node->ipaddr, ipaddr, strlen(ipaddr)) == 0) {
            ret = sp_node;
        }
    }
    rcu_read_unlock();
    return ret;
}

char *get_ipaddr_by_con(struct hmdfs_peer *con) 
{
    struct connection *connect = NULL;
    struct tcp_handle *tcph;
    struct socket *dst_sock;
    char *dst_ipaddr = NULL;

    connect = get_conn_impl(con, CONNECT_TYPE_TCP);
    if (!connect) {
        goto out;
    }
    tcph = connect->connect_handle;
    dst_sock = tcph->sock;
    dst_ipaddr = kzalloc(64, GFP_KERNEL);
    if (IS_ERR_OR_NULL(dst_ipaddr)) {
        spc_err("dst_ipaddr kzalloc error");
        dst_ipaddr = NULL;
        return dst_ipaddr;
    }
    get_ipport_by_sock(dst_sock, dst_ipaddr, NULL);
    spc_info("get_ipaddr_by_con: %s, %llu", dst_ipaddr, con->device_id);
out:
    return dst_ipaddr;
}

struct spc_peer *find_spc_peer_by_con(int res, struct hmdfs_peer *con) 
{
    struct spc_peer *snode = NULL;
    struct connection *connect = NULL;
    struct tcp_handle *tcph;
    struct socket *dst_sock;
    char *dst_ipaddr;

    connect = get_conn_impl(con, CONNECT_TYPE_TCP);
    if (!connect) {
        goto out;
    }
    tcph = connect->connect_handle;
    dst_sock = tcph->sock;
    dst_ipaddr = kzalloc(64, GFP_KERNEL);
    if (IS_ERR_OR_NULL(dst_ipaddr)) {
        spc_err("dst_ipaddr kzalloc error");
        return snode;
    }
    get_ipport_by_sock(dst_sock, dst_ipaddr, NULL);
    // spc_info("find_spc_peer_by_con find ip : %s, from: %d", dst_ipaddr, res);
    snode = find_spc_peer_by_ip(dst_ipaddr);
    kfree(dst_ipaddr);
out:
    return snode;
}

struct spc_peer *find_spc_peer_by_idx(uint64_t idx) 
{
    struct spc_peer *sp_node = NULL, *ret = NULL;
    rcu_read_lock();
    list_for_each_entry_rcu(sp_node, &spc_peer_list_head, spcp_node) {
        if(idx == 1) {
            ret = sp_node;
            break;
        }else {
            idx -= 1;
        }
    }
    rcu_read_unlock();
    return ret;
}

struct spc_client_getattr_request *find_getattr_req(uint32_t spc_did, char *send_buf) 
{
    struct spc_client_getattr_request *gr_node = NULL, *ret = NULL;
    if(send_buf == NULL) 
        return ret;
    rcu_read_lock();
    list_for_each_entry_rcu(gr_node, &getattr_req_list_head, req_node) {
        if(strlen(send_buf) == strlen(gr_node->send_buf) && strncmp(gr_node->send_buf, send_buf, strlen(send_buf)) == 0 && gr_node->spc_did == spc_did) {
            ret = gr_node;
            // spc_debug("find getattr: %s %s", gr_node->send_buf, send_buf);
        }
    }
    rcu_read_unlock();
    return ret;
}


int spc_getattr_req_destory(void) 
{
    int err = 0;
    struct spc_client_getattr_request *gr_node = NULL, *gr_node_next = NULL;

    list_for_each_entry_safe(gr_node, gr_node_next, &getattr_req_list_head, req_node) {
        kfree(gr_node->send_buf);
        list_del_rcu(&gr_node->req_node);
        kfree(gr_node);
    }
    return err;
}




static int recvmsg_nofs(struct socket *sock, struct msghdr *msg,
			struct kvec *vec, size_t num, size_t size, int flags)
{
	unsigned int nofs_flags;
	int ret;

	/* enable NOFS for memory allocation */
	nofs_flags = memalloc_nofs_save();
	ret = kernel_recvmsg(sock, msg, vec, num, size, flags);
	memalloc_nofs_restore(nofs_flags);

	return ret;
}

static int sendmsg_nofs(struct socket *sock, struct msghdr *msg,
			struct kvec *vec, size_t num, size_t size)
{
	unsigned int nofs_flags;
	int ret;

	/* enable NOFS for memory allocation */
	nofs_flags = memalloc_nofs_save();
	ret = kernel_sendmsg(sock, msg, vec, num, size);
	memalloc_nofs_restore(nofs_flags);

	return ret;
}

int spc_sendmessage(struct spc_peer *node, struct spc_send_data *msg) 
{
    int send_len = 0;
    struct msghdr tcp_msg;
	struct kvec iov[2];

	memset(&tcp_msg, 0, sizeof(tcp_msg));
    iov[0].iov_base = msg->head;
	iov[0].iov_len = msg->head_len;
    // aeadcipher_encrypt_buffer
    iov[1].iov_base = msg->data;
	iov[1].iov_len = msg->data_len;
    mutex_lock(&node->send_mutex);
    send_len = sendmsg_nofs(node->sock, &tcp_msg, iov, 2, msg->head_len + msg->data_len);
    mutex_unlock(&node->send_mutex);
    return send_len;
}

// hmdfs_sendmessage
int spc_sendmessage_request(struct spc_peer *node, int msg_id, void *data, size_t data_len) 
{
    int err;
    struct spc_head_cmd head;
    struct spc_send_data msg;

    head.magic = HMDFS_MSG_MAGIC;
    head.data_len = data_len;
    head.msg_id = msg_id;
    head.reserved = 0;

    msg.head = &head;
	msg.head_len = sizeof(struct spc_head_cmd);
	msg.data = data;
	msg.data_len = data_len;
    err = spc_sendmessage(node, &msg);
    return err;
}

static int spc_tcp_read_head_from_socket(struct socket *sock, void *buf,
				     unsigned int to_read)
{
	int rc = 0;
	struct msghdr hmdfs_msg;
	struct kvec iov;

	iov.iov_base = buf;
	iov.iov_len = to_read;
	memset(&hmdfs_msg, 0, sizeof(hmdfs_msg));
	hmdfs_msg.msg_flags = MSG_WAITALL;
	hmdfs_msg.msg_control = NULL;
	hmdfs_msg.msg_controllen = 0;
	rc = recvmsg_nofs(sock, &hmdfs_msg, &iov, 1, to_read,
			  hmdfs_msg.msg_flags);
	if (rc == -EAGAIN || rc == -ETIMEDOUT || rc == -EINTR ||
	    rc == -EBADMSG) {
		usleep_range(1000, 2000);
		return -EAGAIN;
	}
	// error occurred
	if (rc != to_read) {
		spc_err("tcp recv error %d", rc);
		return -ESHUTDOWN;
	}
	return 0;
}

static int spc_tcp_read_buffer_from_socket(struct socket *sock, void *buf,
				       unsigned int to_read)
{
	int read_cnt = 0;
	int retry_time = 0;
	int rc = 0;
	struct msghdr hmdfs_msg;
	struct kvec iov;

	do {
		iov.iov_base = (char *)buf + read_cnt;
		iov.iov_len = to_read - read_cnt;
		memset(&hmdfs_msg, 0, sizeof(hmdfs_msg));
		hmdfs_msg.msg_flags = MSG_WAITALL;
		hmdfs_msg.msg_control = NULL;
		hmdfs_msg.msg_controllen = 0;
		rc = recvmsg_nofs(sock, &hmdfs_msg, &iov, 1,
				  to_read - read_cnt, hmdfs_msg.msg_flags);
		if (rc == -EBADMSG) {
			usleep_range(1000, 2000);
			continue;
		}
		if (rc == -EAGAIN || rc == -ETIMEDOUT || rc == -EINTR) {
			retry_time++;
			hmdfs_info("read again %d", rc);
			usleep_range(1000, 2000);
			continue;
		}
		// error occurred
		if (rc <= 0) {
			hmdfs_err("tcp recv error %d", rc);
			return -ESHUTDOWN;
		}
		read_cnt += rc;
		if (read_cnt != to_read)
			hmdfs_info("read again %d/%d", read_cnt, to_read);
	} while (read_cnt < to_read && retry_time < MAX_RECV_RETRY_TIMES);
	if (read_cnt == to_read)
		return 0;
	return -ESHUTDOWN;
}


int spc_change_device_status(struct spc_peer *node, int new_state) 
{
    int ret;
    struct spc_status_sync_request data;

    data.new_state = new_state;
    if(node->sock == NULL) {
        ret = -1;
    }else {
        ret = spc_sendmessage_request(node, F_STATUS_FORCE_CHANGE, &data, sizeof(struct spc_status_sync_request));
    }
    return ret;
}

int spc_status_sync(struct spc_peer *node) 
{
    int ret;
    struct spc_status_sync_request data;

    data.new_state = local_peer.state;
    if(node->sock == NULL) {
        ret = -1;
    }else {
        ret = spc_sendmessage_request(node, F_STATUS_SYNC, &data, sizeof(struct spc_status_sync_request));
    }
    return ret;
}

int spc_status_sync_all(void) 
{
    int ret = 0;
    struct spc_peer *sp_node = NULL;
    rcu_read_lock();
    list_for_each_entry_rcu(sp_node, &spc_peer_list_head, spcp_node) {
        ret = spc_status_sync(sp_node);
        spc_info("call spc_status_sync ret: %d, remote_ip: %s", ret, sp_node->ipaddr);
    }
    rcu_read_unlock();
    return ret;
}


static int spc_tcp_receive_from_sock(struct spc_peer *dst_peer) 
{
    struct socket *nsock = dst_peer->sock;
    struct spc_head_cmd *recv = NULL;
	int ret = 0;
	__u8 *rdata = NULL;
	__u32 recv_len;

    recv = kmalloc(sizeof(struct spc_head_cmd), GFP_KERNEL);
	if (!recv) {
		spc_err("tcp recv kmalloc error");
		return -1;
	}
    ret = spc_tcp_read_head_from_socket(nsock, recv, sizeof(struct spc_head_cmd));
    if (ret)
		goto out;
    if (recv->magic != HMDFS_MSG_MAGIC) {
		spc_info("tcp recv fd wrong magic. drop message");
		goto out;
	}
    recv_len = le32_to_cpu(recv->data_len);
    rdata = kzalloc(recv_len, GFP_KERNEL);
	if (!rdata) {
		spc_err("kzalloc error");
		return -1;
	}
    ret = spc_tcp_read_buffer_from_socket(nsock, rdata, recv_len);
    if (ret)
		goto out_recv;
    if(recv->msg_id == F_STATUS_SYNC) {
        struct spc_status_sync_request *req = rdata;
        spc_info("recv_message from %u %llu, F_STATUS_SYNC ns: %d, old state: %d", dst_peer->device_id, dst_peer->hmdfs_device_id, req->new_state, dst_peer->state);
        dst_peer->state = req->new_state;
    }
    else if(recv->msg_id == F_STATUS_FORCE_CHANGE) {
        struct spc_status_sync_request *req = rdata;
        spc_info("recv_message from %u %llu, F_STATUS_FORCE_CHANGE ns: %d, old state: %d", dst_peer->device_id, dst_peer->hmdfs_device_id, req->new_state, local_peer.state);
        local_peer.state = req->new_state;
        spc_status_sync_all();
        if(local_peer.state == false) {
            del_timer_sync(&net_timer);
            // del_timer_sync(&scr_timer);
        }
    }
    else {
        spc_info("recv_message from %u %llu, msgid: %d, ", dst_peer->device_id, dst_peer->hmdfs_device_id, recv->msg_id);
    }
out_recv:
    kfree(rdata);
out:
    kfree(recv);
    return ret;
}










void state_jump_net(struct timer_list *tl) 
{
    int type = 0;
    int period = TIMER_EXPIRE_SECOND;

    if(tl == (&net_timer)) {
        type = 1;
        period = timer_expire_tmp;
    }else if(tl == (&scr_timer)) {
        type = 2;
        period = TIMER_EXPIRE_SECOND + timer_expire_tmp;
    }
    spc_info("pid: %d, comm: %s, l_s: %d, type: %d, period: %d", current->pid, current->comm, local_peer.state, type, period);
    if(local_peer.state == true) {
        local_peer.state = false;
    }else if(local_peer.state == false) { // 不可能执行，false变成true不会由定时器自动触发
        local_peer.state = true;
    }
    spc_status_sync_all();
    if(local_peer.state == false) {
        if(type == 1) {
            // del_timer_sync(&scr_timer);
        }else if(type == 2) {
            del_timer_sync(&net_timer);
        }
    }
}

// 到底是 request 还是 response , 0: send, 1: request, 2: response
void spc_network_transceive(int msg_id, int sr, struct spc_request_info *sri) 
{
    int ret;
    struct timespec64 cts;
    int loglen;
    int hours, minutes, seconds, milsec, micsec;

    spin_lock(&spc_log_lock);
    jiffies_to_timespec64(jiffies, &cts);
    hours = (cts.tv_sec / 3600) % 24;
    minutes = (cts.tv_sec / 60) % 60;
    seconds = cts.tv_sec % 60;
    milsec = cts.tv_nsec / 1000000;
    micsec = (cts.tv_nsec / 1000) % 1000;
    if(!sri) {
        snprintf(tmpbuf, sizeof(tmpbuf), "sec: %lld , time: %d %d %d %d %d , req: %d %d x , ls: %d\n", cts.tv_sec, hours, minutes, seconds, milsec, micsec, msg_id, sr, local_peer.state);
    } else {
        snprintf(tmpbuf, sizeof(tmpbuf), "sec: %lld , time: %d %d %d %d %d , req: %d %d %llu , ls: %d\n", cts.tv_sec, hours, minutes, seconds, milsec, micsec, msg_id, sr, sri->i_ino, local_peer.state);
    }
    loglen = strlen(tmpbuf);

    if(!logfilep) {
        logfilep = filp_open(LOG_FILE, O_RDWR | O_CREAT | O_APPEND, 0666); // O_APPEND O_TRUNC
    }
    if (IS_ERR_OR_NULL(logfilep)) {
        spc_err("log file open fail");
        logfilep = NULL;
        ret = loglen = 0;
    } else {
        ret = kernel_write(logfilep, tmpbuf, loglen, &logpos);
    }
    spin_unlock(&spc_log_lock);

    switch (msg_id) {
	case F_WRITEPAGE: // 3
	case F_READPAGE: // 2
	case F_READPAGES: // 26
        {
            spc_info("essential/necessary request: %d, sr: %d, l_s: %d, %d %d", msg_id, sr, local_peer.state, loglen, ret);
            if(msg_id == F_READPAGE && sr == 1) {
                if(local_peer.state == false) {
                    local_peer.state = true;
                    spc_status_sync_all();
                    mod_timer(&net_timer, jiffies + (readpage_expire) * HZ);
                    if(readpage_expire > 60) readpage_expire -= 60;
                } else {
                    // 主动执行数据收发时，更新计时器（心跳包不在内）
                    mod_timer(&net_timer, jiffies + (timer_expire_tmp) * HZ);
                    // mod_timer(&scr_timer, jiffies + (TIMER_EXPIRE_SECOND + timer_expire_tmp) * HZ);
                }
            }
        }
		break;
    // spc 和 cpc 的区别之一是元数据操作是否会唤醒远端设备
    case F_SETATTR: // 14
	case F_GETATTR: // 20
	case F_ITERATE: // 4 : ls涉及，写得太复杂了太耦合了，没法改实现 .lookup
        {
            if(msg_id != 4)
                spc_info("essential/necessary request: %d, sr: %d, l_s: %d, %d %d ", msg_id, sr, local_peer.state, loglen, ret);
        }
		break;
	default:
    // F_CREATE = 11
    // F_OPEN = 0
    // F_RELEASE = 1
        spc_info("non-essential/unnecessary request: %d, sr: %d, l_s: %d, %d %d ", msg_id, sr, local_peer.state, loglen, ret);
		break;
	}
    
}




void spc_wakeup_screen(void) 
{
    if(local_peer.state == false) {
        local_peer.state = true;
        spc_status_sync_all();
    }
    mod_timer(&net_timer, jiffies + (timer_expire_tmp) * HZ);
    // mod_timer(&scr_timer, jiffies + (TIMER_EXPIRE_SECOND + timer_expire_tmp) * HZ);
}

int get_file_device_state(struct file *filp, struct hmdfs_inode_info *iinfo, struct hmdfs_peer *con, uint32_t *res) 
{
    int ret = -2;
    struct inode *inode = NULL;
    struct hmdfs_inode_info *info = NULL;
    struct spc_peer *snode = NULL;

    if(filp) {
        inode = file_inode(filp);
        info = hmdfs_i(inode);
    }else if(iinfo) {
        info = iinfo;
    }
    if(info) {
        snode = find_spc_peer_by_con(1, info->conn);
    }
    if(con) {
        snode = find_spc_peer_by_con(1, con);
    }
    if(snode) {
        ret = snode->state;
        if(res) {
            *res = snode->device_id;
        }
    }
    return ret;
}

int get_local_device_state(void) 
{
    return local_peer.state;
}





uint32_t calculate_hash_value(int msg_id, void *vreq) 
{
    uint32_t ans = 0;

    switch(msg_id) {
    case F_WRITEPAGE:
    {
        struct spc_client_writepage_request *wp_req = vreq;
        int i, len = strlen(wp_req->filepath);
        for(i = 0; i < len; ++i) {
            ans = ans * 23333 + wp_req->filepath[i];
        }
        ans = ans * 100000 + wp_req->pos;
    }
        break;
    case F_SETATTR:
        break;
    default:
        break;
    }
    return ans;
}

struct spc_delayed_req * spc_create_insert_delayed_req(uint32_t spc_did, int msg_id, void *vreq) 
{
    struct spc_delayed_req *dreq = NULL;
    struct spc_peer *dst_peer = NULL;
    
    dreq = kmalloc(sizeof(struct spc_delayed_req), GFP_KERNEL);
    if (!dreq) {
		spc_err("spc_create_insert_delayed_req kmalloc error");
		return dreq;
	}
    dreq->type = msg_id;
    dreq->spc_did = spc_did;
    dreq->req = vreq;
    dreq->hashval = calculate_hash_value(msg_id, vreq);

    dst_peer = find_spc_peer_by_did(spc_did);
    INIT_LIST_HEAD(&dreq->dreq_node);
    list_add_tail_rcu(&dreq->dreq_node, &dst_peer->sdr_list_head);
    dst_peer->sdr_list_len += 1;

    return dreq;
}

struct spc_delayed_req * spc_find_delayed_req(uint32_t spc_did, int msg_id, void *vreq) 
{
    struct spc_peer *dst_peer;
    struct spc_delayed_req *ret = NULL, *req = NULL;
    uint32_t res = calculate_hash_value(msg_id, vreq);

    dst_peer = find_spc_peer_by_did(spc_did);
    rcu_read_lock();
    list_for_each_entry_rcu(req, &dst_peer->sdr_list_head, dreq_node) {
        if(req->spc_did == spc_did && req->type == msg_id && req->hashval == res) {
            ret = req;
        }
    }
    rcu_read_unlock();
    return ret;
}

int spc_merge_delayed_req(struct spc_delayed_req *req, void *vreq) 
{
    int real_size = 0;
    struct spc_peer *dst_peer;

    dst_peer = find_spc_peer_by_did(req->spc_did);
    spin_lock(&dst_peer->req_lock);
    switch(req->type) {
    case F_WRITEPAGE:
    {
        struct spc_client_writepage_request *req1 = req->req;
        struct spc_client_writepage_request *req2 = vreq;
        int i, len = HMDFS_PAGE_SIZE;
        for(i = 0; i < len; ++i) {
            if(req2->buf[i]) req1->buf[i] = req2->buf[i];
            if(req1->buf[i]) real_size += 1;
        }
        req1->count = max(req1->count, req2->count);
        // i_size_read 对空洞文件会返回什么
    }
        break;
    case F_SETATTR:
        break;
    default:
        break;
    }
    spin_unlock(&dst_peer->req_lock);
    return real_size;
}

int spc_capture_client_request(uint32_t spc_did, int msg_id, void *vreq) 
{
    int ret = 0;
    int real_size = 0;
    struct spc_delayed_req *dreq = NULL;

    switch (msg_id) {
    case F_WRITEPAGE:
    {
        struct spc_client_writepage_request *req1;

        dreq = spc_find_delayed_req(spc_did, msg_id, vreq);
        if(dreq) {
            req1 = dreq->req;
            delayed_req_size -= sizeof(struct spc_delayed_req) + sizeof(struct spc_client_writepage_request) + strlen(req1->filepath) + strlen(req1->buf);
            real_size = spc_merge_delayed_req(dreq, vreq);
        }else {
            dreq = spc_create_insert_delayed_req(spc_did, msg_id, vreq);
            real_size = -1;
        }
        req1 = dreq->req;
        delayed_req_size += sizeof(struct spc_delayed_req) + sizeof(struct spc_client_writepage_request) + strlen(req1->filepath) + strlen(req1->buf);
        ret = 1;
    }
        break;
    case F_SETATTR: // hmdfs 目前的实现不太完善 
        // .setattr -> notify_change -> chmod_common chown_common vfs_truncate -> vfs_fchmod -> fchmod fchown truncate ftruncate
        // hmdfs_send_setattr -> hmdfs_setattr_remote -> struct setattr_info -> {size, valid, mtime, mtime_nsec}
        break;
    default:
        break;
    }

    spc_info("delayed_req_size: %lld, %d", delayed_req_size, real_size);

    if(delayed_req_size >= WRITEBACK_CACHE_SIZEB) {
        sync_device_cache(0, 1);
    }
    return ret;
}

static void hmdfs_update_getattr_ret2(struct getattr_response *resp,
				     struct hmdfs_getattr_ret *result)
{
	struct kstat *stat = &result->stat;

	stat->result_mask = le32_to_cpu(resp->result_mask);
	if (stat->result_mask == 0)
		return;

	stat->ino = le64_to_cpu(resp->ino);
	stat->mode = le16_to_cpu(resp->mode);
	stat->nlink = le32_to_cpu(resp->nlink);
	stat->uid.val = le32_to_cpu(resp->uid);
	stat->gid.val = le32_to_cpu(resp->gid);
	stat->size = le64_to_cpu(resp->size);
	stat->blocks = le64_to_cpu(resp->blocks);
	stat->blksize = le32_to_cpu(resp->blksize);
	stat->atime.tv_sec = le64_to_cpu(resp->atime);
	stat->atime.tv_nsec = le32_to_cpu(resp->atime_nsec);
	stat->mtime.tv_sec = le64_to_cpu(resp->mtime);
	stat->mtime.tv_nsec = le32_to_cpu(resp->mtime_nsec);
	stat->ctime.tv_sec = le64_to_cpu(resp->ctime);
	stat->ctime.tv_nsec = le32_to_cpu(resp->ctime_nsec);
	stat->btime.tv_sec = le64_to_cpu(resp->crtime);
	stat->btime.tv_nsec = le32_to_cpu(resp->crtime_nsec);
	result->fsid = le64_to_cpu(resp->fsid);
	/* currently not used */
	result->i_flags = 0;
}

static void update_getattr_response2(struct inode *inode,
				    struct kstat *ks,
				    struct getattr_response *resp)
{
	/* if getattr for link, get ino and mode from actual lower inode */
	resp->ino = cpu_to_le64(
		generate_u64_ino(inode->i_ino, inode->i_generation));
	resp->mode = cpu_to_le16(inode->i_mode);

	/* get other information from vfs_getattr() */
	resp->result_mask = cpu_to_le32(STATX_BASIC_STATS | STATX_BTIME);
	resp->fsid = cpu_to_le64(ks->dev);
	resp->nlink = cpu_to_le32(ks->nlink);
	resp->uid = cpu_to_le32(ks->uid.val);
	resp->gid = cpu_to_le32(ks->gid.val);
	resp->size = cpu_to_le64(ks->size);
	resp->blocks = cpu_to_le64(ks->blocks);
	resp->blksize = cpu_to_le32(ks->blksize);
	resp->atime = cpu_to_le64(ks->atime.tv_sec);
	resp->atime_nsec = cpu_to_le32(ks->atime.tv_nsec);
	resp->mtime = cpu_to_le64(ks->mtime.tv_sec);
	resp->mtime_nsec = cpu_to_le32(ks->mtime.tv_nsec);
	resp->ctime = cpu_to_le64(ks->ctime.tv_sec);
	resp->ctime_nsec = cpu_to_le32(ks->ctime.tv_nsec);
	resp->crtime = cpu_to_le64(ks->btime.tv_sec);
	resp->crtime_nsec = cpu_to_le32(ks->btime.tv_nsec);
}

int spc_getattr(uint32_t spc_did, char *send_buf, unsigned int lookup_flags, struct hmdfs_getattr_ret *attr)
{
    int err = -2;
    char *new_buf;
    int buf_len;
    struct getattr_response *resp = NULL;
    struct path root_path, dst_path;
    struct kstat ks;
    struct inode *inode;
    struct hmdfs_inode_info *info = NULL;
    struct spc_client_getattr_request *vreq = NULL;

    vreq = find_getattr_req(spc_did, send_buf);
    if(flag_getattr_use_cache == -1) {
        return -1;
    } else if(vreq) {
        *attr = vreq->attr;
        return 0;
    } else if(flag_getattr_use_cache == 0) {
        return -2;
    }

    if(!spc_sbi) {
        spc_err("spc_sbi null");
        goto out;
    }
    resp = kzalloc(sizeof(struct getattr_response), GFP_KERNEL);
	if (!resp) {
		err = -ENOMEM;
        spc_err("kzalloc 1 failed err = %d", err);
		goto out;
	}
    buf_len = 1 + strlen(PPCACHE_ROOT) + strlen(send_buf) + 1;
    new_buf = kzalloc(buf_len, GFP_KERNEL);
    if (!new_buf) {
		err = -ENOMEM;
        spc_err("kzalloc 2 failed err = %d", err);
		goto out;
	}
    snprintf(new_buf, buf_len, "/%s%s", PPCACHE_ROOT, send_buf);
    spc_info("send_buf: %s, new_buf: %s, local_dst: %s", send_buf, new_buf, spc_sbi->local_dst);
    // send_buf: /files/a.txt, new_buf: /hmdfs_pcache/files/a.txt, local_dst: /mnt/hmdfs/100/account/device_view/local/
    err = kern_path(spc_sbi->local_dst, 0, &root_path);
    if (err) {
		spc_err("kern_path failed err = %d", err);
		goto out;
	}

    err = vfs_path_lookup(root_path.dentry, root_path.mnt, new_buf,
			      lookup_flags, &dst_path);
	if (err) {
        spc_err("vfs path lookup err = %d", err);
		goto out_put_root;
    }
    
    inode = d_inode(dst_path.dentry);
    if (inode->i_sb != spc_sbi->sb) {
		spc_err("super block do not match");
	}
    info = hmdfs_i(inode);
	if (info->lower_inode)
		inode = info->lower_inode;
    else {
        spc_info("lower inode is NULL, is remote file: %d", info->conn != NULL);
    }
    err = vfs_getattr(&dst_path, &ks, STATX_BASIC_STATS | STATX_BTIME, 0);
	if (err) {
        spc_err("vfs getattr err = %d", err);
		goto out_put_dst;
    }
    update_getattr_response2(inode, &ks, resp);
    hmdfs_update_getattr_ret2(resp, attr);
out_put_dst:
	path_put(&dst_path);
out_put_root:
    path_put(&root_path);
out:
    if(resp) kfree(resp);
    if(new_buf) kfree(new_buf);
    return err;
}

int spc_record_getattr(uint32_t spc_did, char *send_buf, unsigned int lookup_flags, struct hmdfs_getattr_ret *attr) 
{
    int err = 0;
    int buflen;
    struct spc_client_getattr_request *vreq = NULL;

    vreq = find_getattr_req(spc_did, send_buf);
    if(vreq) {
        vreq->attr = *attr;
        return err;
    }

    vreq = kmalloc(sizeof(struct spc_client_getattr_request), GFP_KERNEL);
    if (!vreq) {
		spc_err("spc_record_getattr kmalloc error");
        err = -1;
		return err;
	}
    buflen = strlen(send_buf);
    vreq->send_buf = kzalloc(buflen + 1, GFP_KERNEL);
    if (!vreq->send_buf) {
        spc_err("spc_record_getattr kzalloc error");
		kfree(vreq);
        err = -2;
        return err;
    }
    memcpy(vreq->send_buf, send_buf, buflen);
    vreq->spc_did = spc_did;
    vreq->lookup_flags = lookup_flags;
    vreq->attr = *attr;

    INIT_LIST_HEAD(&vreq->req_node);
    list_add_tail_rcu(&vreq->req_node, &getattr_req_list_head);

    return err;
}


int spc_delay_setattr(uint32_t spc_did, char *send_buf, struct setattr_info *ssi) 
{
    int err = 0;

    return err;
}








static int comm_caller_run(void *data) 
{
    int err;
    Kthread_data *ktargp;
    char *dst_ipaddr;
    unsigned short dst_port;
    struct spc_peer *dst_peer;
    int wt_ret;
    struct socket *nsock;

    spc_info("pid: %d, comm: %s", current->pid, current->comm);
    ktargp = (Kthread_data *)data;
    if(!ktargp) {
        spc_err("comm_caller_run ktargp is NULL");
        err = -1;
        return err;
    }
    dst_ipaddr = kzalloc(strlen(ktargp->taskd_name) + 1, GFP_KERNEL);
    resolve_ipport_str(ktargp->taskd_name, dst_ipaddr, &dst_port);
    kfree(ktargp->taskd_name);
    kfree(ktargp);
    dst_peer = find_spc_peer_by_ipport(dst_ipaddr, dst_port);
    kfree(dst_ipaddr);
    if (dst_peer == NULL) {
        spc_err("comm_caller_run error, dst_peer is NULL");
        err = -1;
        return err;
    }
    spc_info("comm_caller_run begin task: %s %d ######## ", dst_peer->ipaddr, dst_peer->port);
    nsock = dst_peer->sock;
    while (!kthread_should_stop()) {
        wt_ret = wait_event_interruptible(*sk_sleep(nsock->sk), !skb_queue_empty(&nsock->sk->sk_receive_queue) || kthread_should_stop());
        spc_info("comm_caller_run: %s, wt_ret: %d, message is coming", dst_peer->ipaddr, wt_ret);
        if (wt_ret >= 0 && !skb_queue_empty(&nsock->sk->sk_receive_queue)) {
            spc_tcp_receive_from_sock(dst_peer);
        } else if (wt_ret >= 0) {  // 该结束了 stop 或者 时间到了
            spc_info("comm_caller_run stop or time out");
            msock_release(&dst_peer->sock);
            break;
        } else if (wt_ret < 0) {  // wt_ret != 0, ERESTARTSYS 512 信号唤醒的
            spc_info("Socket Thread pid: %d get a signal, maybe should_stop", current->pid);
            if (kthread_should_stop()) {
                msock_release(&dst_peer->sock);
                break;
            }
        }
    }
    spc_warn("###### func over: %s , %d \n\n", __func__, __LINE__);
    return 0;
}

struct task_struct *establish_connection(char *dst_ipaddr, unsigned short dst_port) 
{
    int err;
    struct socket *dst_sock;
    struct sockaddr_in loc_addr, dst_addr;
    struct spc_peer *new_dst_peer;
    char *dst_caller_name;
    Kthread_data *ktargp;

    //建立套接字
    err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &dst_sock);
    if (err < 0) {
        spc_err("sock_create_kern error: %d", err);
        return NULL;
    }
    //构造本地端口并绑定
    memset(&loc_addr, '\0', sizeof(loc_addr));
    err = tv_inet4_pton(local_peer.ipaddr, 0, (void *)&loc_addr);
    if (err < 0) {
        spc_err("tv_inet4_pton error: %d", err);
        msock_release(&dst_sock);
        return NULL;
    }
    loc_addr.sin_family = AF_INET;
    loc_addr.sin_port = htons(0);
    spc_info("bind: ip: %pI4, port: %d", &loc_addr.sin_addr.s_addr, ntohs(loc_addr.sin_port));
    err = kernel_bind(dst_sock, (struct sockaddr *)&loc_addr, sizeof(loc_addr));
    if (err < 0) {
        spc_err("kernel_bind error: %d", err);
        msock_release(&dst_sock);
        return NULL;
    }
    //构造远端端口并连接
    memset(&dst_addr, '\0', sizeof(dst_addr));
    err = tv_inet4_pton(dst_ipaddr, 0, (void *)&dst_addr);
    if (err < 0) {
        spc_err("tv_inet4_pton error: %d", err);
        msock_release(&dst_sock);
        return NULL;
    }
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    
    err = kernel_connect(dst_sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr), 0);
    if (err < 0) {
        spc_err("kernel_connect error: %d", err);
        /*
        -111
        */
        msock_release(&dst_sock);
        return NULL;
    }
    spc_debug("success connect");
    new_dst_peer = create_insert_spc_peer(dst_sock, dst_ipaddr, dst_port);
    if (!new_dst_peer) {
        spc_err("create_insert_spc_peer error");
        msock_release(&dst_sock);
        return NULL;
    }
    out_spc_peer_info();

    dst_caller_name = connect_str_name("spc_caller:", new_dst_peer->ipaddr, new_dst_peer->port);
    spc_info("dst_caller_name: %s", dst_caller_name);
    ktargp = kmalloc(sizeof(Kthread_data), GFP_KERNEL);
    ktargp->taskd_name = dst_caller_name;
    new_dst_peer->caller = kthread_run(comm_caller_run, ktargp, dst_caller_name);
    if(IS_ERR_OR_NULL(new_dst_peer->caller)) {
        spc_err("kthread_run error ###############");
        new_dst_peer->caller = NULL;
    }else {
        spc_debug("kthread_run success");
    }
    return new_dst_peer->caller;
}

int spc_check_hmdfs_con(struct hmdfs_sb_info *sbi)
{
    int ret = -2;
	struct hmdfs_peer *con = NULL;
    // struct connection *connect;
    // struct tcp_handle *tcph;
    // struct socket *dst_sock;
    struct spc_peer *snode;
    char *dst_ipaddr;
    struct task_struct *dst_caller;

	if (!sbi) {
        ret = -1;
    	return ret;
    }
    spc_info("spc_check_hmdfs_con periodly");
	mutex_lock(&sbi->connections.node_lock);
	list_for_each_entry(con, &sbi->connections.node_list, list) {
		if (con->status != NODE_STAT_ONLINE)
			continue;
        if(ret == -2) ret = 0;
        snode = find_spc_peer_by_hdid(con->device_id);
        if(snode == NULL) {
            dst_ipaddr = get_ipaddr_by_con(con);
            if(dst_ipaddr) {
                snode = find_spc_peer_by_ip(dst_ipaddr);
                if(snode == NULL) {
                    dst_caller = establish_connection(dst_ipaddr, LOCAL_SERVER_PORT);
                    if(dst_caller) {
                        snode = get_a_from_b_field_c(snode, &dst_caller, caller);
                        snode->hmdfs_device_id = con->device_id;
                        ret += 1;
                    }
                }else {
                    snode->hmdfs_device_id = con->device_id;
                }
                kfree(dst_ipaddr);
            }
        }
    }
	mutex_unlock(&sbi->connections.node_lock);
	return ret;
}



static int comm_handler_run(void *data) 
{
    int err;
    struct sockaddr_in src_addr;
    struct __kernel_sock_timeval acce_timeout;
    sockptr_t optval;
    struct socket *dst_sock;
    int err11_times;
    int acc_count;
    int loops;
    struct spc_peer *new_dst_peer;
    char *dst_caller_name;
    Kthread_data *ktargp;

    // \x0a -> '\n' 的16进制
retry:
    spc_info("pid: %d, comm: %s", current->pid, current->comm);
    if(!local_peer.ipaddr) {
        memset(local_peer.ipaddr, 0, 64);
        strcpy(local_peer.ipaddr, "127.0.0.1");
    }
    while(local_peer.ipaddr == NULL || strstr(local_peer.ipaddr, "127.0.0.1")) {
        schedule_timeout_interruptible(msecs_to_jiffies(10 * 1000));
    }
    spc_info("local_ipaddr: %s", local_peer.ipaddr);
    //建立套接字
    err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &local_peer.sock);
    if (err < 0) {
        spc_err("sock_create_kern error: %d", err);
        goto retry;
    }
    //构造端口
    memset(&src_addr, '\0', sizeof(src_addr));
    err = tv_inet4_pton(local_peer.ipaddr, 0, (void *)&src_addr);
    if (err < 0) {
        spc_err("tv_inet4_pton error: %d", err);
        msock_release(&local_peer.sock);
        goto retry;
    }
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(local_peer.port);
    //绑定端口
    spc_info("bind: ip: %pI4, port: %d", &src_addr.sin_addr.s_addr, ntohs(src_addr.sin_port));
    err = kernel_bind(local_peer.sock, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if (err < 0) {
        spc_err("kernel_bind error: %d", err);
        /*
        -22: 
        -99:
        */
        msock_release(&local_peer.sock);
        goto retry;
    }
    //监听端口
    err = kernel_listen(local_peer.sock, 1024);
    if (err < 0) {
        spc_err("kernel_listen error: %d", err);
        msock_release(&local_peer.sock);
        goto retry;
    }
    // 配置
    local_peer.sock->sk->sk_reuse = SK_CAN_REUSE;
    acce_timeout.tv_sec = 30;
    acce_timeout.tv_usec = 0;
    optval = KERNEL_SOCKPTR((char *)&acce_timeout);
    err = sock_setsockopt(local_peer.sock, SOL_SOCKET, SO_RCVTIMEO_NEW, optval, sizeof(acce_timeout));
    if (err < 0) {
        spc_err("sock_setsockopt error: %d", err);
        // EINVAL		22	Invalid argument
        msock_release(&local_peer.sock);
        goto retry;
    }
    err11_times = acc_count = loops = 0;
    while (!kthread_should_stop()) {
        loops += 1;
        spc_info("wait connect: %d, loops: %d, l_s: %d", spc_peer_list_len, loops, local_peer.state);
        err = kernel_accept(local_peer.sock, &dst_sock, 0);  // SOCK_NONBLOCK
        if(kthread_should_stop()) {
            break;
        }
        if (err < 0) {
            spc_err("kernel_accept error: %d, period: %d, err11: %d", err, active_polling_period, err11_times);
            // EAGAIN 11 Try again 可能是因为超时的问题吧，超时超过 360 (6h) 次就结束吧
            if (err == -11 && err11_times < 2 * 360) {
                err11_times += 1;
                if(err11_times % active_polling_period == 0) {
                    err = spc_check_hmdfs_con(spc_sbi);
                    spc_info("spc_check_hmdfs_con: %d", err);
                }
                continue;
            }
            break;
        }
        acc_count += 1;
        spc_debug("success connect accept: %d", acc_count);
        new_dst_peer = create_insert_spc_peer(dst_sock, NULL, 0);
        if (!new_dst_peer) {
            spc_err("create_insert_spc_peer error");
            continue;
        }
        out_spc_peer_info();

        dst_caller_name = connect_str_name("spc_caller:", new_dst_peer->ipaddr, new_dst_peer->port);
        spc_info("dst_caller_name: %s", dst_caller_name);
        ktargp = kmalloc(sizeof(Kthread_data), GFP_KERNEL);
        ktargp->taskd_name = dst_caller_name;
        new_dst_peer->caller = kthread_run(comm_caller_run, ktargp, dst_caller_name);
        if(IS_ERR_OR_NULL(new_dst_peer->caller)) {
            spc_err("kthread_run error");
            new_dst_peer->caller = NULL;
        }else {
            spc_debug("kthread_run success");
        }
    }
    msock_release(&local_peer.sock);    
    spc_warn("###### func over: %s , %d \n\n", __func__, __LINE__);
    return 0;
}

void timer_init(void) 
{
    //定时器, linux5.10 新版 https://blog.csdn.net/ZHONGCAI0901/article/details/120484815
    timer_setup(&net_timer, state_jump_net, 0);
    net_timer.expires = jiffies + (timer_expire_tmp) * HZ;
    add_timer(&net_timer);

    timer_setup(&scr_timer, state_jump_net, 0);
    scr_timer.expires = jiffies + (TIMER_EXPIRE_SECOND + timer_expire_tmp) * HZ;
    // add_timer(&scr_timer);
}

int spc_cross_device_connect(struct task_struct **chp) 
{
    int err = 0;

    *chp = kthread_run(comm_handler_run, "spc_comm_handler_data", "spc_comm_handler_name");
    spc_info("comm_handler: %p %lX", *chp, (long unsigned int)(*chp));
    if (IS_ERR(*chp)) {
        spc_err("comm_handler address PTR_ERR: %ld", PTR_ERR(*chp));
        err = PTR_ERR(*chp);
        if(err > 0) err = -err;
        *chp = NULL;
    }
    if (*chp) {
        spc_info("comm_handler pid: %d", (*chp)->pid);
    }
    return err;
}


static int cache_syncer_run(void *data) 
{
    int err;

    return 0;
}

int spc_cache_synchronizer(struct task_struct **csp) 
{
    int err = 0;

    *csp = kthread_run(cache_syncer_run, "spc_cache_syncer_data", "spc_cache_syncer_name");
    spc_info("cache_syncer: %p %lX", *csp, (long unsigned int)(*csp));
    if (IS_ERR(*csp)) {
        spc_err("cache_syncer address PTR_ERR: %ld", PTR_ERR(*csp));
        err = PTR_ERR(*csp);
        if(err > 0) err = -err;
        *csp = NULL;
    }
    if (*csp) {
        spc_info("cache_syncer pid: %d", (*csp)->pid);
    }
    return err;
}

int spc_client_init(char *localip) 
{
    int err = -1;
    int lolen;
    
    if (localip != NULL) {
        if(local_peer.ipaddr == NULL) {
            local_peer.ipaddr = kzalloc(64, GFP_KERNEL);
            if (IS_ERR_OR_NULL(local_peer.ipaddr)) {
                spc_err("local_peer.ipaddr kzalloc error");
                local_peer.ipaddr = NULL;
                goto out;
            }
        }
        lolen = strlen(localip);
        memcpy(local_peer.ipaddr, localip, sizeof(char) * lolen);
        spc_info("spc_client_init localip: %s", local_peer.ipaddr);
        err = 0;
    }
out:
    return err;
}

int spc_local_init(void *sbi) 
{
    int err = 0;

    spc_info("pid: %d, comm: %s", current->pid, current->comm);
    
    if(sbi) 
        spc_sbi = (struct hmdfs_sb_info *) sbi;
    pcache_mode = 0;
    local_peer.state = false;
    local_peer.device_id = spc_rand_int(0);
    local_peer.ipaddr = kzalloc(64, GFP_KERNEL);
    if (IS_ERR_OR_NULL(local_peer.ipaddr)) {
        spc_err("local_peer.ipaddr kzalloc error");
        local_peer.ipaddr = NULL;
        err = -1;
        goto out;
    }
    strcpy(local_peer.ipaddr, "127.0.0.1");
    local_peer.port = LOCAL_SERVER_PORT;
    
    timer_expire_tmp = spc_rand_int(0);
    timer_expire_tmp %= 100;
    timer_expire_tmp += 500;
    readpage_expire = 240;
    timer_init();
    active_polling_period = local_peer.device_id % 20;
    if(active_polling_period < 0) active_polling_period = -active_polling_period;
    if(active_polling_period < 10) active_polling_period += 10;
    spc_info("local_peer.device_id: %d, timer_expire_tmp: %d, active_polling_period: %d", local_peer.device_id, timer_expire_tmp, active_polling_period);

    spin_lock_init(&spc_peer_lock);
    INIT_LIST_HEAD(&spc_peer_list_head);
    spc_peer_list_len = 0;
    spin_lock_init(&spc_log_lock);

    INIT_LIST_HEAD(&getattr_req_list_head);
    delayed_req_size = 0;

    spc_cross_device_connect(&comm_handler);
    // spc_cache_synchronizer(&cache_syncer);

    logfilep = filp_open(LOG_FILE, O_RDWR | O_CREAT | O_APPEND, 0666); // O_APPEND O_TRUNC
    if (IS_ERR_OR_NULL(logfilep)) {
        spc_err("log file open fail");
        logfilep = NULL;
    }
    logpos = 0;
    spc_coverage = 0;
    
    out_spc_peer_info();
    g_is_init = true;
out:
    return err;
}

int spc_local_exit(void) 
{
    int err = 0;
    int chpid = 0;
    int wait_times = 0;

    spc_info("pid: %d, comm: %s", current->pid, current->comm);

    if (spc_peer_list_len >= 0) {
        spc_peer_list_task_kill();
        schedule_timeout_interruptible(msecs_to_jiffies((spc_peer_list_len + 3) * 1000));
    }
    if (!IS_ERR_OR_NULL(comm_handler)) {
        chpid = comm_handler->pid;
        err = safely_quit_kthread(&comm_handler);
        spc_info("comm_handler kthread_stop: %d", err);
    }

    while (chpid && spc_pid_get_task_struct(chpid)) {
        wait_times += 1;
        schedule_timeout_interruptible(msecs_to_jiffies(5 * 1000));
    }

    // INIT_LIST_HEAD();
    if(spc_peer_list_len >= 0) {
        spc_peer_list_destory(); // spc节点链表，延迟的写请求链表
    }
    spc_getattr_req_destory(); // 缓存的元数据查询请求链表，目录查询请求链表

    del_timer_sync(&net_timer);
    // del_timer_sync(&scr_timer);
    if(local_peer.ipaddr) 
        kfree(local_peer.ipaddr);

    if(logfilep) {
        filp_close(logfilep, NULL);
        logfilep = NULL;
    }
    g_is_init = false;
    spc_warn("###### func over: %s , %d , wait_times: %d \n\n", __func__, __LINE__, wait_times);
    return err;
}



int spc_cat_peer_info_test(void) 
{
    return out_spc_peer_info();
}

int spc_change_state_by_did_test(uint32_t d_id, int new_state) 
{
    int err = -2;
    struct spc_peer *sp_node = NULL, *sp_node_next = NULL;
    int get_lock = 0;

    if(new_state < 0 || new_state > 1) {
        spc_err("new_state %d out of range [0, 1]", new_state);
        err = -1;
        return err;
    }
    // spin_lock(&spc_peer_lock);
    get_lock = spin_trylock(&spc_peer_lock);
    list_for_each_entry_safe(sp_node, sp_node_next, &spc_peer_list_head, spcp_node) {
        if(sp_node->device_id == d_id) {
            if(sp_node->state != new_state) {
                sp_node->state = new_state;
                err = spc_change_device_status(sp_node, new_state);
                spc_info("change device_id %d status to %d, ret: %d", d_id, new_state, err);
            }
            err = new_state;
        }
    }
    if(get_lock) {
        spin_unlock(&spc_peer_lock);
    }
    return err;
}

int spc_status_sync_test(int cnt) 
{
    int ret = -2;
    struct spc_peer *node;
    
    if(cnt < 1) cnt = 1;
    spc_info("find %d device:", cnt);
    node = find_spc_peer_by_idx(cnt);
    if(node) {
        spc_info("did: %u, ip: %s", node->device_id, node->ipaddr);
        ret = spc_status_sync(node);
        spc_info("spc_status_sync_test ret: %d, de_id: %u", ret, node->device_id);
    }else {
        spc_info("spc_status_sync_test: no connected device");
    }
    return ret;
}

int establish_connection_test(char *dst_ipaddr, unsigned short dst_port) 
{
    struct task_struct *ret = establish_connection(dst_ipaddr, dst_port);

    if(ret) return 1;
    return 0;
}

void spc_client_attr_set(int flag, int a, int b, int c, int d) 
{
    switch(flag) {
    case 0:
        flag_getattr_use_cache = a;
        spc_info("flag_getattr_use_cache: %d", flag_getattr_use_cache);
        break;
    case 10:
    {
        logpos = 0;
        if(logfilep) {
            filp_close(logfilep, NULL);
            logfilep = NULL;
        }
        logfilep = filp_open(LOG_FILE, O_RDWR | O_CREAT | O_APPEND, 0666); // O_APPEND O_TRUNC
        if (IS_ERR_OR_NULL(logfilep)) {
            spc_err("log file open fail");
            logfilep = NULL;
        }
        if(logfilep) {
            spc_info("filp_open: %s success", LOG_FILE);
        }
    }
        break;
    case 11:
    {
        spc_coverage = a;
        spc_info("spc_coverage: %d", spc_coverage);
    }
        break;
    case 90:
    {
        if(spc_sbi) {
            if(a == 0) {
                spc_sbi->persist_cache_limit = 0;
                update_pcache_size(spc_sbi, 0, 0);
            } else if(a == 1) {
                spc_sbi->persist_cache_limit = (2048LL * 1024 * 1024);
            }
            spc_info("persist_cache_limit: %lld", spc_sbi->persist_cache_limit);
        } else {
            spc_info("spc_sbi is null");
        }
    }
        break;
    case 50:
    {
        spc_info("pcache_mode: %d", pcache_mode);
        pcache_mode = a;
        spc_info("pcache_mode: %d", pcache_mode);
    }
        break;
    default:
        break;
    }
}


EXPORT_SYMBOL(spc_cat_peer_info_test);
EXPORT_SYMBOL(spc_change_state_by_did_test);
EXPORT_SYMBOL(spc_status_sync_test);
EXPORT_SYMBOL(establish_connection_test);
EXPORT_SYMBOL(sync_device_cache);
EXPORT_SYMBOL(spc_client_init);
EXPORT_SYMBOL(spc_local_init);
EXPORT_SYMBOL(spc_local_exit);
EXPORT_SYMBOL(spc_client_attr_set);
