/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "lb_ctrl_service.h"

#if 0
static void *lb_channel_server_recv_cb(void *arg)
{
    int fd = (uint64_t)arg;
    int buf_len = 0, cur_buf_len = 0, ret;
    char buff[LB_CTRL_BUFF_LEN << 1];
    struct timeval timeout = {.tv_sec = 3};
    fd_set read_set;

    for (;;) {
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);

        switch (select(fd + 1, &read_set, NULL, NULL, &timeout)) {
            case 0:
                /* 0 means timeout */
                break;

            case -1:
                LOG(LB, ERR, "recv fail, errno:%s", strerror(errno));
                close(fd);
                return NULL;

            default:
                if (FD_ISSET(fd, &read_set)) {
                    buf_len = recv(fd, &buff[cur_buf_len], sizeof(buff) - cur_buf_len, 0);
                    if (likely(buf_len > 0)) {
                        cur_buf_len += buf_len;

                        ret = comm_msg_cmd_entry(arg, buff, cur_buf_len);
                        if (ret > 0 && cur_buf_len > ret) {
                            cur_buf_len -= ret;
                            memmove(buff, &buff[ret], cur_buf_len);
                        } else if (ret == -1) {
                            cur_buf_len = 0;
                        }
                    } else {
                        LOG(LB, ERR, "recv fail, errno:%s", strerror(errno));
                        close(fd);
                        return NULL;
            		}
                }
                break;
        }
	}

    return NULL;
}

static void *lb_channel_server_task(void *arg)
{
    struct lb_ctrl_channel_server *setp = (struct lb_ctrl_channel_server *)arg;
	struct sockaddr_in remote;
	socklen_t len = sizeof(struct sockaddr_in);
    int fd;
    cpu_set_t cpuset;
    pthread_attr_t attr1;
    pthread_t thr_id;
    uint64_t cb_arg;

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    CPU_SET(setp->cpu_id, &cpuset);

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(LB, ERR, "pthread_attr_setaffinity_np fail on core(%d)", setp->cpu_id);
        close(setp->sock);
        return NULL;
    }

	while (setp->work_flag) {
		fd = accept(setp->sock, (struct sockaddr*)&remote, &len);
		if (fd < 0) {
            LOG(LB, ERR, "accept fail, errno:%s", strerror(errno));
			continue;
		}

        LOG(LB, DEBUG, "accept %s:%d success", inet_ntoa(remote.sin_addr), remote.sin_port);

        cb_arg = fd;
        if (pthread_create(&thr_id, &attr1, lb_channel_server_recv_cb, (void *)cb_arg) != 0) {
    		LOG(LB, ERR, "Fail to create pthread, errno:%s", strerror(errno));
            close(fd);
            continue;
    	}
	}

    if (setp->sock > 0)
        close(setp->sock);

    return NULL;
}

int lb_create_channel_server(struct lb_ctrl_channel_server *setp, uint16_t port, uint16_t bound_cpu_id)
{
    struct sockaddr_in local;
	socklen_t len = sizeof(struct sockaddr_in);
    int on = 1, nagle_flag = 1, keepalive_flag = 3;
    cpu_set_t cpuset;
    pthread_attr_t attr1;

    if (unlikely(NULL == setp)) {
        LOG(LB, ERR, "Incorrect input parameters, setp(%p)", setp);
        return -1;
    }
    LOG(LB, DEBUG, "Server listen port: %hu", port);

    setp->sock = 0;
    setp->cpu_id = bound_cpu_id;
    setp->work_flag = TRUE;

    setp->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (setp->sock < 0) {
		LOG(LB, ERR, "socket fail, errno:%s", strerror(errno));
		goto fail_free;
	}

    if (0 > setsockopt(setp->sock, SOL_SOCKET, SO_REUSEADDR,
        (void*)&on, sizeof(on))) {
        LOG(LB, ERR, "setsocket fail, errno:%s", strerror(errno));
		goto fail_free;
    }

    if (setsockopt(setp->sock, IPPROTO_TCP, TCP_NODELAY,
                        &nagle_flag, sizeof(nagle_flag)) < 0) {
    	LOG(LB, ERR, "setsockopt fail:%s", strerror(errno));
        goto fail_free;
	}

    if (setsockopt(setp->sock, SOL_SOCKET, SO_KEEPALIVE,
                        &keepalive_flag, sizeof(keepalive_flag)) < 0) {
    	LOG(LB, ERR, "setsockopt fail:%s", strerror(errno));
        goto fail_free;
	}

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(setp->sock, (struct sockaddr*)&local ,len) < 0) {
		LOG(LB, ERR, "bind fail, errno:%s", strerror(errno));
		goto fail_free;
	}

	if (listen(setp->sock, LB_MAX_LISTEN_NUMBER) < 0)	{
		LOG(LB, ERR, "listen fail, errno:%s", strerror(errno));
		goto fail_free;
	}

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    CPU_SET(bound_cpu_id, &cpuset);

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(LB, ERR, "Pthread set affinity fail on core(%d)", bound_cpu_id);
        goto fail_free;
    }

	if (pthread_create(&setp->thread_id, &attr1, lb_channel_server_task, setp) != 0)    {
		LOG(LB, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
        goto fail_free;
	}

    return 0;

fail_free:

    if (0 < setp->sock)
        close(setp->sock);

	return -1;
}

static void *lb_channel_client_recv_cb(void *arg)
{
    struct lb_ctrl_channel_client *setp = (struct lb_ctrl_channel_client *)arg;
    int fd = setp->fd;
    uint64_t arg_fd = fd;
    int buf_len = 0, cur_buf_len = 0, ret;
    char buff[LB_CTRL_BUFF_LEN << 1];
    struct timeval timeout = {.tv_sec = 3};
    fd_set read_set;

    for (;;) {
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);

        switch (select(fd + 1, &read_set, NULL, NULL, &timeout)) {
            case 0:
                /* 0 means timeout */
                break;

            case -1:
                LOG(LB, ERR, "recv fail, errno:%s", strerror(errno));
                close(fd);
                setp->fd = -1;
                setp->work_flag = FALSE;
                return NULL;

            default:
                if (FD_ISSET(fd, &read_set)) {
                    buf_len = recv(fd, &buff[cur_buf_len], sizeof(buff) - cur_buf_len, 0);
                    if (likely(buf_len > 0)) {
                        cur_buf_len += buf_len;

                        ret = comm_msg_cmd_entry((void *)arg_fd, buff, cur_buf_len);
                        if (ret > 0 && cur_buf_len > ret) {
                            cur_buf_len -= ret;
                            memmove(buff, &buff[ret], cur_buf_len);
                        } else if (ret == -1) {
                            cur_buf_len = 0;
                        }
                    } else {
                        LOG(LB, ERR, "recv fail, errno:%s", strerror(errno));
                        close(fd);
                        setp->fd = -1;
                        setp->work_flag = FALSE;
                        return NULL;
            		}
                }
                break;
        }
	}

    return NULL;
}

static int lb_connect_service(uint32_t ip, uint16_t port)
{
	int reuse_flag = 1, nagle_flag = 1, keepalive_flag = 3;
	struct sockaddr_in sin = {0};
    socklen_t len = sizeof(struct sockaddr_in);
    int fd = 0;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    	LOG(LB, ERR, "socket fail:%s", strerror(errno));
        return -1;
	}

	/* Set socket option */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                        &reuse_flag, sizeof(reuse_flag)) < 0) {
    	LOG(LB, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                        &nagle_flag, sizeof(nagle_flag)) < 0) {
    	LOG(LB, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                        &keepalive_flag, sizeof(keepalive_flag)) < 0) {
    	LOG(LB, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

    sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(ip);
	sin.sin_port = htons(port);

	if (connect(fd, (struct sockaddr*)&sin, len) < 0) {
        LOG(LB, ERR, "Connect IP: %s, port: %hu failed, error: %s.",
            inet_ntoa(sin.sin_addr), port, strerror(errno));
        close(fd);
        return -1;
	}
    LOG(LB, RUNNING, "Connect IP: %s, port: %hu success", inet_ntoa(sin.sin_addr), port);

    return fd;
}

static void *lb_channel_client_task(void *arg)
{
    struct lb_ctrl_channel_client *setp = (struct lb_ctrl_channel_client *)arg;
    cpu_set_t cpuset;
    pthread_attr_t attr1;
    pthread_t thr_id;
    uint8_t cnt, connect_fail_times;

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    CPU_SET(setp->cpu_id, &cpuset);

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(LB, ERR, "pthread_attr_setaffinity_np fail on core(%d)", setp->cpu_id);
        return NULL;
    }

	for (cnt = 0; ; cnt = (cnt + 1) % setp->remote_ips_num) {
	    if (setp->work_flag) {
            sleep(LB_CHANNEL_CLIENT_CHECK_INTERVAL);
            continue;
	    }

        LOG(LB, RUNNING, "Client connect 0x%08x, port: %hu.", setp->remote_ips[cnt], setp->remote_port);
        setp->fd = lb_connect_service(setp->remote_ips[cnt], setp->remote_port);
        if (setp->fd < 0) {
            /* 如果失败了先立即确认是否所有连接都不可用 */
            if (connect_fail_times < setp->remote_ips_num) {
                ++connect_fail_times;
            } else {
                sleep(LB_CHANNEL_CLIENT_CHECK_INTERVAL);
            }

            continue;
        }
        connect_fail_times = 0;
        setp->work_flag = TRUE;

        if (pthread_create(&thr_id, &attr1, lb_channel_client_recv_cb, setp) != 0) {
			LOG(LB, ERR, "Fail to create pthread, errno:%s", strerror(errno));
            close(setp->fd);
            setp->work_flag = FALSE;
			continue;
		}
	}

    return NULL;
}

int lb_create_channel_client(struct lb_ctrl_channel_client *setp, uint32_t *remote_ips, uint8_t remote_ips_num,
    uint16_t remote_port, uint16_t bound_cpu_id)
{
    char print_str[512];
    uint16_t str_len = 0, cnt;
    cpu_set_t cpuset;
    pthread_attr_t attr1;

    if (unlikely(NULL == setp|| NULL == remote_ips || 0 == remote_ips_num)) {
        LOG(LB, ERR, "Incorrect input parameters, setp(%p), remote_ips(%p), remote_ips_num: %d.",
            setp, remote_ips, remote_ips_num);
        return -1;
    }

    for (cnt = 0; cnt < remote_ips_num; ++cnt) {
        str_len += sprintf(&print_str[str_len], "0x%08x ", remote_ips[cnt]);
    }

    LOG(LB, DEBUG, "Client connect IP: %s, port: %hu", print_str, remote_port);

    memcpy(setp->remote_ips, remote_ips, sizeof(uint32_t) * remote_ips_num);
    setp->remote_ips_num    = remote_ips_num;
    setp->remote_port       = remote_port;
    setp->work_flag         = FALSE;
    setp->cpu_id            = bound_cpu_id;
    ros_rwlock_init(&setp->rw_lock);

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    CPU_SET(bound_cpu_id, &cpuset);

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(LB, ERR, "Pthread set affinity fail on core(%d)", bound_cpu_id);
        return -1;
    }

	if (pthread_create(&setp->thread_id, &attr1, lb_channel_client_task, setp) != 0)    {
		LOG(LB, ERR, "Fail to create tcp client pthread, errno:%s", strerror(errno));
		return -1;
	}

    return 0;
}

int32_t lb_channel_client_send(struct lb_ctrl_channel_client *chnl_cli, char *buf, uint32_t len)
{
    ros_rwlock_write_lock(&chnl_cli->rw_lock); /* lock */
    if (send(chnl_cli->fd, buf, len, MSG_NOSIGNAL) < 0) {
        ros_rwlock_write_unlock(&chnl_cli->rw_lock); /* unlock */
        LOG(LB, ERR, "Channel send failed(%s).", strerror(errno));
        return ERROR;
    }
    ros_rwlock_write_unlock(&chnl_cli->rw_lock); /* unlock */

    return OK;
}

int32_t lb_channel_reply(int fd, char *buf, uint32_t len)
{
    if (send(fd, buf, len, MSG_NOSIGNAL) < 0) {
        LOG(LB, ERR, "Channel send failed(%s).", strerror(errno));
        return ERROR;
    }

    return OK;
}

void lb_channel_server_shutdown(struct lb_ctrl_channel_server *server)
{
    if (server != NULL) {
        server->work_flag = FALSE;

        if (server->sock > 0)
            close(server->sock);

        if (server->thread_id)
            pthread_cancel(server->thread_id);
    }
}

void lb_channel_client_shutdown(struct lb_ctrl_channel_client *client)
{
    if (client != NULL) {
        client->work_flag = FALSE;

        if (client->fd > 0)
            close(client->fd);

        if (client->thread_id)
            pthread_cancel(client->thread_id);
    }
}
#endif

