/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "comm_msg.h"

CVMX_SHARED COMM_PROCESS_MSG_CALLBACK comm_msg_cmd_callback;
CVMX_SHARED COMM_PROCESS_MSG_COMMID_ERR comm_msg_cmd_commid_err;

CVMX_SHARED uint16_t comm_msg_comm_id;

/* If -1 is returned, there is no buff to save */
int comm_msg_cmd_entry(void *token, char *inbuf, uint32_t inlen)
{
    comm_msg_header_t   *cmd_header;
    comm_msg_ie_t       *ie;
    int32_t             offset, ie_len, msg_offset = 0;
    uint32_t            ret = EN_COMM_ERRNO_OK;
    int32_t             reminder_len;
    uint8_t             *pos;

    if ((inbuf == NULL) || (inlen < 1)) {
        LOG(COMM, ERR, "Incorrect parameter input");
        return -1;
    }

    LOG(COMM, PERIOD, "Recv msg inbuf(%p), inlen: %u.", inbuf, inlen);

    while (msg_offset < (int32_t)inlen) {
        cmd_header = (comm_msg_header_t *)(inbuf + msg_offset);

        if (msg_offset  > (int32_t)inlen) {
            LOG(COMM, ERR, "Incomplete buf data, offset: %u, input length: %u.",
                msg_offset, inlen);
            return msg_offset;
        }
        if (cmd_header->magic_word != ntohl(COMM_MSG_MAGIC_WORD))
        {
            LOG(COMM, ERR,
                "protocol error in magic word(%x).",
                ntohl(cmd_header->magic_word));
            return -1;
        }

        msg_offset += ntohl(cmd_header->total_len);
        if (msg_offset > (int32_t)inlen) {
            LOG(COMM, ERR, "Abnormal buf length, offset: %u, msg total_len: %u.",
                (msg_offset - ntohl(cmd_header->total_len)), ntohl(cmd_header->total_len));
            return (msg_offset - ntohl(cmd_header->total_len));
        }

        LOG(COMM, PERIOD,
            "get packet len %d magic %08x, len %d, comm_id %d",
            inlen, ntohl(cmd_header->magic_word), ntohl(cmd_header->total_len),
            htons(cmd_header->comm_id));


        if (cmd_header->major_version != COMM_MSG_MAJOR_VERSION)
        {
            LOG(COMM, ERR,
                "protocol error in major version(%d).",
                cmd_header->major_version);
            return -1;
        }
        if (cmd_header->minor_version != COMM_MSG_MINOR_VERSION)
        {
            LOG(COMM, ERR,
                "protocol error in minor version(%d).",
                cmd_header->minor_version);
            return -1;
        }
        if ((cmd_header->comm_id != ntohs(comm_msg_comm_id)))
        {
            if (comm_msg_cmd_commid_err) {
                LOG(COMM, ERR,
                    "protocol error in comm id(peer %d, local %d).",
                    ntohs(cmd_header->comm_id), comm_msg_comm_id);

                ie = (comm_msg_ie_t *)(cmd_header->payload);

                ret = comm_msg_cmd_commid_err(token, ie, htons(cmd_header->comm_id));

                if (ret != EN_COMM_ERRNO_OK) {
                    continue;
                }
            }
        }
        if (ntohl(cmd_header->total_len) < COMM_MSG_HEADER_LEN)
        {
            LOG(COMM, ERR,
                "protocol error in packet length(%d).",
                ntohl(cmd_header->total_len));
            return -1;
        }
        reminder_len = ntohl(cmd_header->total_len) - COMM_MSG_HEADER_LEN;

        pos = (uint8_t *)(cmd_header->payload);
        offset = 0;

        //print_data(pos, reminder_len);
        while(offset < reminder_len)
        {
            ie = (comm_msg_ie_t *)(pos + offset);
            ie->cmd   = ntohs(ie->cmd);
            ie->len   = ntohs(ie->len);
            ie->index = ntohl(ie->index);
            ie_len    = ie->len;

            LOG(COMM, PERIOD,
                "recv msg, total len %d, ie cmd(%x) len(%d), cur offset(%d).",
                ntohl(cmd_header->total_len), ie->cmd, ie->len, offset);

            if (comm_msg_cmd_callback) {
                ret = comm_msg_cmd_callback(token, ie);
            }

            LOG(COMM, PERIOD,
                "msg (%x) process finished, return value %x.\r\n",
                ie->cmd, ret);

            if (ie_len != 0) {
                offset += ie_len;
            } else {
                break;
            }
        }
    }

    return -1;
}

#ifndef ENABLE_OCTEON_III
int comm_msg_parse_ip_addr(comm_msg_ip_address *dst_cfg, char *src)
{
    char out_str[2][PCF_STR_LEN] = {{0}};
    int ret = -1;

    if (NULL == dst_cfg || NULL == src) {
        LOG(COMM, ERR, "Parameters error, dst_cfg(%p), src(%p).", dst_cfg, src);
        return -1;
    }

    if (!strlen(src) || strlen(src) >= PCF_STR_LEN) {
        LOG(COMM, ERR, "Abnormal parameters, src string too long.");
        return -1;
    }

    ret = pcf_str_split(src, '/', out_str, 2);
    if (ret < 2) {
        LOG(COMM, ERR, "split string: %s failed, ret:%d.", src, ret);
        return -1;
    }

    if (strchr(out_str[0], ':')) {
        if (1 != inet_pton(AF_INET6, out_str[0], dst_cfg->ipv6)) {
            LOG(COMM, ERR, "inet_pton failed, error: %s.",
                strerror(errno));
            return -1;
        }
        dst_cfg->ip_version |= 2;
        dst_cfg->ipv6_prefix = atoi(out_str[1]);
        if (dst_cfg->ipv6_prefix > 128) {
            LOG(COMM, ERR, "Ipv6 prefix %d error.",
                dst_cfg->ipv6_prefix);
            return -1;
        }
    } else {
        if (1 != inet_pton(AF_INET, out_str[0], &dst_cfg->ipv4)) {
            LOG(COMM, ERR, "inet_pton failed, error: %s.",
                strerror(errno));
            return -1;
        }
        dst_cfg->ipv4 = ntohl(dst_cfg->ipv4);
        dst_cfg->ip_version |= 1;
        dst_cfg->ipv4_prefix = atoi(out_str[1]);
        if (dst_cfg->ipv4_prefix > 32) {
            LOG(COMM, ERR, "Ipv4 prefix %d error.",
                dst_cfg->ipv4_prefix);
            return -1;
        }
    }

    return 0;
}
#endif

int comm_msg_parse_ie(void *trans_mng, uint8_t *first_ie, int32_t reminder_len, uint16_t commid)
{
    comm_msg_ie_t       *ie;
    int32_t             offset, ie_len, ie_cnt = 0;
    uint8_t             *pos;

    if ((!trans_mng)||(!first_ie)) {
        LOG(COMM, ERR, "incorrect parameter input");
        return ERROR;
    }

    LOG(COMM, PERIOD, "parse ie(%p), length: %u.", first_ie, reminder_len);

    /* 2. parse IE */

    pos = (uint8_t *)first_ie;
    offset = 0;

    //print_data(pos, reminder_len);
    while(offset < reminder_len)
    {
        ie = (comm_msg_ie_t *)(pos + offset);
        ie->cmd   = ntohs(ie->cmd);
        ie->len   = ntohs(ie->len);
        ie->index = ntohl(ie->index);
        ie_len    = ie->len;

        LOG(COMM, PERIOD, "cur offset(%d), cmd(%x) len(%d), receive comm_id(%04x) local comm_id(%04x).",
            offset, ie->cmd, ie->len, commid, comm_msg_comm_id);

        if ((commid != comm_msg_comm_id)&&(comm_msg_cmd_commid_err)) {
            comm_msg_cmd_commid_err(trans_mng, ie, commid);
        }
        else {
            if (comm_msg_cmd_callback) {
                comm_msg_cmd_callback(trans_mng, ie);
            }
        }
        ie_cnt++;

        if (ie_len != 0) {
            offset += ie_len;
        }
        else {
            break;
        }
    }

    LOG(COMM, PERIOD, "processed %d ie.\r\n", ie_cnt);

    return OK;
}

int is_file_exist(const char *file_name)
{
	if (NULL == file_name)
		return -1;

	if (access(file_name, F_OK) == 0)
		return 0;

	return -1;
}

int write_wireshark_head(const char *file_name)
{
	FILE*fp;
	int ret = 0;
	struct pcap_file_header pcap;

	pcap.magic = 0xa1b2c3d4;
	pcap.version_major = 2;
	pcap.version_minor = 4;
	pcap.thiszone = 0;
	pcap.sigfigs = 0;
	pcap.snaplen = 0xffff;
	pcap.linktype = 1;

	if((fp=fopen(file_name, "a+"))==NULL) {
		LOG(COMM, ERR, "fopen error");
		return -1;
	}

	ret = fwrite((char *)&pcap, sizeof(pcap), 1, fp);
	if(ret < 0)
	{
		LOG(COMM, ERR, "fwrite error, ret %d", ret);
		fclose(fp);
		return -1;
	}

	fclose(fp);

	return 0;
}

#ifndef ENABLE_OCTEON_III
static void *comm_msg_channel_server_recv_cb(void *arg)
{
    comm_msg_channel_server *setp = (comm_msg_channel_server *)arg;
    int fd = setp->temp_fd;
    uint64_t arg_fd = fd;
    int buf_len = 0, cur_buf_len = 0, ret;
    char buff[COMM_MSG_CTRL_BUFF_LEN << 2];
    struct timeval timeout;
    fd_set read_set;

    ros_atomic16_set(&setp->accept_state, TRUE);

    for (; TRUE == setp->work_flag;) {
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        switch (select(fd + 1, &read_set, NULL, NULL, &timeout)) {
            case 0:
                /* 0 means timeout */
                break;

            case -1:
                LOG(COMM, ERR, "recv fail, errno:%s", strerror(errno));
                close(fd);
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
                    } else if (0 > buf_len) {
                        LOG(COMM, ERR, "recv fail, errno:%s", strerror(errno));
                        close(fd);
                        return NULL;
                    }
                }
                break;
        }
	}
    close(fd);

    return NULL;
}

static void *comm_msg_channel_server_task(void *arg)
{
    comm_msg_channel_server *setp = (comm_msg_channel_server *)arg;
	struct sockaddr_in remote;
	socklen_t len = sizeof(struct sockaddr_in);
    cpu_set_t cpuset;
    pthread_attr_t attr1, *attr;
    pthread_t thr_id;
    uint8_t cnt;

    if (setp->cpu_num > 0) {
        pthread_attr_init(&attr1);
        CPU_ZERO(&cpuset);
        for (cnt = 0; cnt < setp->cpu_num; ++cnt) {
            CPU_SET(setp->cpu_id[cnt], &cpuset);
        }

        if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
            LOG(COMM, ERR, "Pthread set affinity fail.");
            close(setp->sock);
            return NULL;
        }
        attr = &attr1;
    } else {
        attr = NULL;
    }

    ros_atomic16_set(&setp->accept_state, TRUE);
    setp->work_flag = TRUE;

	while (setp->work_flag) {
        if (FALSE == ros_atomic16_read(&setp->accept_state)) {
            usleep(10000);
        }
		setp->temp_fd = accept(setp->sock, (struct sockaddr*)&remote, &len);
		if (setp->temp_fd < 0) {
            LOG(COMM, ERR, "accept fail, errno:%s", strerror(errno));
			continue;
		}
        ros_atomic16_set(&setp->accept_state, FALSE);

        LOG(COMM, MUST, "accept %s:%d success", inet_ntoa(remote.sin_addr), remote.sin_port);

        if (pthread_create(&thr_id, attr, comm_msg_channel_server_recv_cb, (void *)setp) != 0) {
    		LOG(COMM, ERR, "Fail to create pthread, errno:%s", strerror(errno));
            close(setp->temp_fd);
            ros_atomic16_set(&setp->accept_state, TRUE);
            continue;
    	}
	}

    if (attr)
        pthread_attr_destroy(attr);

    if (setp->sock > 0)
        close(setp->sock);

    return NULL;
}

int comm_msg_create_channel_server(comm_msg_channel_server *setp, uint16_t port,
    uint8_t *bound_cpu_ids, uint8_t bound_cpu_num)
{
    struct sockaddr_in local;
	socklen_t len = sizeof(struct sockaddr_in);
    int on = 1;
    struct timeval send_timeout = {.tv_sec = 2};
    cpu_set_t cpuset;
    pthread_attr_t attr1, *attr = NULL;
    uint8_t cnt;

    if (unlikely(NULL == setp)) {
        LOG(COMM, ERR, "Incorrect input parameters, setp(%p)", setp);
        return -1;
    }
    LOG(COMM, DEBUG, "Server listen port: %hu", port);

    setp->sock = -1;
    if (bound_cpu_num > 0 && NULL != bound_cpu_ids) {
        memcpy(setp->cpu_id, bound_cpu_ids, sizeof(bound_cpu_ids[0]) * bound_cpu_num);
        setp->cpu_num       = bound_cpu_num;
    } else {
        setp->cpu_num       = 0;
    }
    setp->work_flag         = FALSE;
    setp->temp_fd           = -1;
    ros_rwlock_init(&setp->rw_lock);

    setp->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (setp->sock < 0) {
		LOG(COMM, ERR, "socket fail, errno:%s", strerror(errno));
		goto fail_free;
	}

    if (0 > setsockopt(setp->sock, SOL_SOCKET, SO_REUSEADDR,
        (void*)&on, sizeof(on))) {
        LOG(COMM, ERR, "setsocket fail, errno:%s", strerror(errno));
		goto fail_free;
    }

    if (0 > setsockopt(setp->sock, SOL_SOCKET, SO_SNDTIMEO,
            &send_timeout, sizeof(send_timeout))) {
        LOG(COMM, ERR, "setsockopt fail, errno:%s", strerror(errno));
        goto fail_free;
    }

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(setp->sock, (struct sockaddr*)&local ,len) < 0) {
		LOG(COMM, ERR, "bind fail, errno:%s", strerror(errno));
		goto fail_free;
	}

	if (listen(setp->sock, COMM_MSG_MAX_LISTEN_NUMBER) < 0)	{
		LOG(COMM, ERR, "listen fail, errno:%s", strerror(errno));
		goto fail_free;
	}

    if (setp->cpu_num > 0) {
        pthread_attr_init(&attr1);
        CPU_ZERO(&cpuset);
        for (cnt = 0; cnt < setp->cpu_num; ++cnt) {
            CPU_SET(setp->cpu_id[cnt], &cpuset);
        }

        if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
            LOG(COMM, ERR, "Pthread set affinity fail.");
            goto fail_free;
        }

        attr = &attr1;
    } else {
        attr = NULL;
    }

	if (pthread_create(&setp->thread_id, attr, comm_msg_channel_server_task, setp) != 0)    {
		LOG(COMM, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
        goto fail_free;
	}

    if (attr)
        pthread_attr_destroy(attr);

    return 0;

fail_free:

    if (0 < setp->sock)
        close(setp->sock);

	return -1;
}

static void *comm_msg_channel_client_recv_cb(void *arg)
{
    comm_msg_channel_client *setp = (comm_msg_channel_client *)arg;
    int fd = setp->fd;
    uint64_t arg_fd = fd;
    int buf_len = 0, cur_buf_len = 0, ret;
    char buff[COMM_MSG_CTRL_BUFF_LEN << 2];
    struct timeval timeout;
    fd_set read_set;

    for (; TRUE == setp->work_flag;) {
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        switch (select(fd + 1, &read_set, NULL, NULL, &timeout)) {
            case 0:
                /* 0 means timeout */
                break;

            case -1:
                LOG(COMM, ERR, "recv fail, errno:%s", strerror(errno));
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
                    } else if (0 > buf_len) {
                        LOG(COMM, ERR, "recv fail, errno:%s", strerror(errno));
                        close(fd);
                        setp->fd = -1;
                        setp->work_flag = FALSE;
                        return NULL;
                    }
                }
                break;
        }
	}
    close(fd);
    setp->fd = -1;

    return NULL;
}

static int comm_msg_connect_service(uint32_t ip, uint16_t port)
{
    int reuse_flag = 1, keepalive_flag = 3;
    struct sockaddr_in sin = {0};
    socklen_t len = sizeof(struct sockaddr_in);
    int fd = -1;
    int flags;
    struct timeval timeout = {.tv_sec = 3};
    struct timeval send_timeout = {.tv_sec = 2};
    fd_set wirt_set, read_set;
    int ret, error;
    //int syncnt = 4;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOG(COMM, ERR, "socket fail:%s", strerror(errno));
        return -1;
    }

    /* Set socket option */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                &reuse_flag, sizeof(reuse_flag)) < 0) {
        LOG(COMM, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                &keepalive_flag, sizeof(keepalive_flag)) < 0) {
        LOG(COMM, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) < 0) {
        LOG(COMM, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
    }

    /*if (setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syncnt, sizeof(syncnt)) < 0) {
        LOG(COMM, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
    }*/

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(ip);
    sin.sin_port = htons(port);

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    error = 0;
    ret = connect(fd, (struct sockaddr*)&sin, len);
    if (ret < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            LOG(COMM, ERR, "Connect IP: %s, port: %hu failed, error: %s.",
                inet_ntoa(sin.sin_addr), port, strerror(errno));
            return -1;
        }
    }

    if (ret == 0) {
        goto done;
    }

    FD_ZERO(&wirt_set);
    FD_SET(fd, &wirt_set);
    read_set = wirt_set;

    if (0 == (ret = select(fd + 1, &read_set, &wirt_set, NULL, &timeout))) {
        close(fd);
        LOG(COMM, ERR, "Connect IP: %s, port: %hu failed, error: %s.",
            inet_ntoa(sin.sin_addr), port, strerror(errno));
        errno = ETIMEDOUT;
        return -1;
    }

    if (FD_ISSET(fd, &wirt_set) || FD_ISSET(fd, &read_set)) {
        len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            close(fd);
            LOG(COMM, ERR, "Connect IP: %s, port: %hu failed, error: %s.",
                inet_ntoa(sin.sin_addr), port, strerror(errno));
            return -1;
        }
    } else {
        close(fd);
        LOG(COMM, ERR, "Connect IP: %s, port: %hu failed, error: %s.",
            inet_ntoa(sin.sin_addr), port, strerror(errno));
        return -1;
    }

done:
    fcntl(fd, F_SETFL, flags);

    if (error) {
        close(fd);
        errno = error;
        LOG(COMM, ERR, "Connect IP: %s, port: %hu failed, error: %s.",
            inet_ntoa(sin.sin_addr), port, strerror(errno));
        return -1;
    }
    LOG(COMM, MUST, "Connect IP: %s, port: %hu success", inet_ntoa(sin.sin_addr), port);

    return fd;
}

static void *comm_msg_channel_client_task(void *arg)
{
    comm_msg_channel_client *setp = (comm_msg_channel_client *)arg;
    cpu_set_t cpuset;
    pthread_attr_t attr1, *attr;
    pthread_t thr_id;
    uint8_t cnt, connect_fail_times = 0;

    if (setp->cpu_num > 0) {
        pthread_attr_init(&attr1);
        CPU_ZERO(&cpuset);
        for (cnt = 0; cnt < setp->cpu_num; ++cnt) {
            CPU_SET(setp->cpu_id[cnt], &cpuset);
        }

        if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
            LOG(COMM, ERR, "Pthread set affinity fail.");
            return NULL;
        }
        attr = &attr1;
    } else {
        attr = NULL;
    }

	for (cnt = 0; ; cnt = (cnt + 1) % setp->remote_ips_num) {
	    if (TRUE == setp->work_flag) {
            sleep(COMM_MSG_CHANNEL_CLIENT_CHECK_INTERVAL);
            continue;
	    }

        LOG(COMM, RUNNING, "Client connect 0x%08x, port: %hu.", setp->remote_ips[cnt], setp->remote_port);
        setp->fd = comm_msg_connect_service(setp->remote_ips[cnt], setp->remote_port);
        if (setp->fd < 0) {
            /* 如果失败了先立即确认是否所有连接都不可用 */
            if (connect_fail_times < setp->remote_ips_num) {
                ++connect_fail_times;
            } else {
                sleep(COMM_MSG_CHANNEL_CLIENT_CHECK_INTERVAL);
            }

            continue;
        }
        connect_fail_times = 0;
        setp->work_flag = TRUE;

        if (pthread_create(&thr_id, attr, comm_msg_channel_client_recv_cb, setp) != 0) {
			LOG(COMM, ERR, "Fail to create pthread, errno:%s", strerror(errno));
            close(setp->fd);
            setp->fd = -1;
            setp->work_flag = FALSE;
			continue;
		}
	}

    return NULL;
}

int comm_msg_create_channel_client(comm_msg_channel_client *setp, uint32_t *remote_ips, uint8_t remote_ips_num,
    uint16_t remote_port, uint8_t *bound_cpu_ids, uint8_t bound_cpu_num)
{
    char print_str[512];
    uint16_t str_len = 0, cnt;
    cpu_set_t cpuset;
    pthread_attr_t attr1, *attr;

    if (unlikely(NULL == setp|| NULL == remote_ips || 0 == remote_ips_num)) {
        LOG(COMM, ERR, "Incorrect input parameters, setp(%p), remote_ips(%p), remote_ips_num: %d.",
            setp, remote_ips, remote_ips_num);
        return -1;
    }

    for (cnt = 0; cnt < remote_ips_num; ++cnt) {
        str_len += sprintf(&print_str[str_len], "0x%08x ", remote_ips[cnt]);
    }

    LOG(COMM, DEBUG, "Client connect IP: %s, port: %hu", print_str, remote_port);

    memcpy(setp->remote_ips, remote_ips, sizeof(uint32_t) * remote_ips_num);
    setp->remote_ips_num    = remote_ips_num;
    setp->remote_port       = remote_port;
    setp->work_flag         = FALSE;
    if (bound_cpu_num > 0 && NULL != bound_cpu_ids) {
        memcpy(setp->cpu_id, bound_cpu_ids, sizeof(bound_cpu_ids[0]) * bound_cpu_num);
        setp->cpu_num       = bound_cpu_num;
    } else {
        setp->cpu_num       = 0;
    }
    setp->fd                = -1;
    ros_rwlock_init(&setp->rw_lock);

    if (setp->cpu_num > 0) {
        pthread_attr_init(&attr1);
        CPU_ZERO(&cpuset);
        for (cnt = 0; cnt < setp->cpu_num; ++cnt) {
            CPU_SET(setp->cpu_id[cnt], &cpuset);
        }

        if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
            LOG(COMM, ERR, "Pthread set affinity fail.");
            return -1;
        }
        attr = &attr1;
    } else {
        attr = NULL;
    }

	if (pthread_create(&setp->thread_id, attr, comm_msg_channel_client_task, setp) != 0)    {
		LOG(COMM, ERR, "Fail to create tcp client pthread, errno:%s", strerror(errno));
		return -1;
	}

    if (attr)
        pthread_attr_destroy(attr);

    return 0;
}

int32_t comm_msg_channel_client_send(comm_msg_channel_common *chnl, char *buf, uint32_t len)
{
    if (chnl->fd < 0)
        return -1;

    ros_rwlock_write_lock(&chnl->rw_lock); /* lock */
    if (send(chnl->fd, buf, len, MSG_NOSIGNAL) < 0) {
        close(chnl->fd);
        chnl->fd = -1;
        chnl->work_flag = FALSE;
        ros_rwlock_write_unlock(&chnl->rw_lock); /* unlock */
        LOG(COMM, ERR, "Channel send failed(%s).", strerror(errno));
        return -1;
    }
    ros_rwlock_write_unlock(&chnl->rw_lock); /* unlock */

    return 0;
}

int32_t comm_msg_channel_reply(int fd, char *buf, uint32_t len)
{
    if (fd < 0)
        return -1;

    if (send(fd, buf, len, MSG_NOSIGNAL) < 0) {
        LOG(COMM, ERR, "Channel send failed(%s).", strerror(errno));
        return -1;
    }

    return 0;
}

void comm_msg_channel_server_shutdown(comm_msg_channel_server *server)
{
    if (server != NULL) {
        server->work_flag = FALSE;

        if (server->sock > 0) {
            close(server->sock);
            server->sock = -1;
        }

        if (server->thread_id)
            pthread_cancel(server->thread_id);
    }
}

void comm_msg_channel_client_shutdown(comm_msg_channel_client *client)
{
    if (client != NULL) {
        client->work_flag = FALSE;

        if (client->fd > 0) {
            close(client->fd);
            client->fd = -1;
        }

        if (client->thread_id)
            pthread_cancel(client->thread_id);
    }
}

#endif

