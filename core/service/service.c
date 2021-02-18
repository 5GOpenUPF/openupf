/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include <net/ethernet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/un.h>


#ifdef SERVICE_USE_RQUEUE_RECV
static void *service_udp_read_rqueue_task(void *arg)
{
    struct service_udp *sdp = (struct service_udp *)arg;
    rqueue_node_t *rq_node;
    rqueue_cb_t *rq_cb;
    service_process_cb_t ssct = sdp->ssct;
    size_t sa_len;
    uint8_t cnt;

    if (sdp->is_ipv4) {
        sa_len = sizeof(struct sockaddr_in);
    } else {
        sa_len = sizeof(struct sockaddr_in6);
    }

    pthread_barrier_wait(&sdp->start_barrier);
    for (cnt = 0; cnt < sdp->core_num; ++cnt) {
        if (sched_getcpu() == sdp->cpus[cnt]) {
            rq_cb = &sdp->rq[cnt];
            break;
        }
    }
    if (cnt >= sdp->core_num) {
        LOG(SERVER, ERR, "Get rqueue fail, CPU ID %d invalid.", sched_getcpu());
        return NULL;
    }
    LOG(SERVER, RUNNING, "Rqueue task use core: %d, rq_index: %d, rq_cb(%p), srw->rq(%p).",
        sched_getcpu(), cnt, rq_cb, sdp->rq);

    for (;;) {
        rq_node = rqueue_consume_always_s(rq_cb);

        if (likely(rq_node->data_len > 0)) {
            ssct(rq_node->data + sa_len, rq_node->data_len, (void *)rq_node->data);
        }
        rqueue_set_consume_flag(rq_node);
	}

    return NULL;
}
#endif

void *service_udp_server_task(void *arg)
{
    struct service_udp *sdp = (struct service_udp *)arg;
	struct ifreq opt;
	int flag = 1;
    rqueue_node_t *rq_node;
	char *ethname = sdp->ethname;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr *sa;
    int af = AF_INET;
    socklen_t sa_len;

    if (sdp == NULL) {
		LOG(SERVER, ERR, "Incorrect input parameters!");
		return NULL;
    }

    if (sdp->is_ipv4) {
        sin.sin_family = AF_INET;
    	sin.sin_addr.s_addr = htonl(INADDR_ANY);
    	sin.sin_port = htons(sdp->port);

        sa_len = sizeof(sin);
        sa = (struct sockaddr *)&sin;
        af = AF_INET;
    } else {
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_any;
        sin6.sin6_port = htons(sdp->port);

        sa_len = sizeof(sin6);
        sa = (struct sockaddr *)&sin6;
        af = AF_INET6;
    }

	/* Create endpoint */
	if ((sdp->fd = socket(af, SOCK_DGRAM, 0)) < 0) {
    	LOG(SERVER, ERR, "socket fail!");
        ros_free(sdp);
        sdp = NULL;
        return NULL;
	}

	/* Set socket option */
	if (setsockopt(sdp->fd, SOL_SOCKET, SO_REUSEADDR,
                        &flag, sizeof(int)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail!");
        close(sdp->fd);
        sdp->fd = -1;
        ros_free(sdp);
        sdp = NULL;
        return NULL;
	}

	/* socket bind interface */
	strncpy(opt.ifr_ifrn.ifrn_name, ethname, strlen(ethname) + 1);
	if (setsockopt(sdp->fd, SOL_SOCKET, SO_BINDTODEVICE,
                        (char *)&opt, sizeof(opt)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail!");
        close(sdp->fd);
        sdp->fd = -1;
        ros_free(sdp);
        sdp = NULL;
        return NULL;
	}

	/* Bind */
	if (bind(sdp->fd, sa, sa_len) < 0) {
    	LOG(SERVER, ERR, "bind()");
        close(sdp->fd);
        sdp->fd = -1;
        ros_free(sdp);
        sdp = NULL;
        return NULL;
	} else {
    	LOG(SERVER, DEBUG, "bind success port:%u", sdp->port);
	}

	while(sdp->work_flag) {
#ifdef SERVICE_USE_RQUEUE_RECV
        rq_node = rqueue_produce_always_m(sdp->rq);

        /* |__struct sockaddr__|________________Packet___________________| */
        rq_node->data_len = recvfrom(sdp->fd, rq_node->data + sa_len, SERVICE_BUF_MAX_LEN, 0,
                        (struct sockaddr *)rq_node->data, &sa_len);

        /* 任何情况下取出来的节点都要去设置为FULL状态 */
        rqueue_set_produce_flag(rq_node);
#else
        struct sockaddr_in cli_sin;
        struct sockaddr_in6 cli_sin6;
        struct sockaddr *cli_sa;

        if (sdp->is_ipv4) {
            cli_sa = (struct sockaddr *)&cli_sin;
            sa_len = sizeof(struct sockaddr_in);
        } else {
            cli_sa = (struct sockaddr *)&cli_sin6;
            sa_len = sizeof(struct sockaddr_in6);
        }

		sdp->buflen = recvfrom(sdp->fd, sdp->buf, SERVICE_BUF_MAX_LEN, 0,
                    cli_sa, &sa_len);
        if (sdp->buflen > 0) {
            sdp->ssct(sdp->buf, sdp->buflen, cli_sa);
        }
#endif
	}

    if (sdp->fd > 0)
        close(sdp->fd);
    sdp->fd = -1;

    return NULL;
}

struct service_udp *
service_register_udp(uint8_t cpus[], uint8_t core_num,
    uint16_t port, char *ethname, uint8_t is_ipv4, service_process_cb_t ssct)
{
    struct service_udp *sdp = NULL;
    socklen_t sa_len;

    if (unlikely((ssct == NULL) || (core_num > SERVICE_CORE_NUM_MAX))) {
        LOG(SERVER, ERR, "Incorrect input parameters, ssct(%p), core_num: %d.", ssct, core_num);
        return NULL;
    }

    sdp = ros_calloc(1, sizeof(struct service_udp));
    if (unlikely(sdp == NULL)) {
		LOG(SERVER, ERR, "Not enough storage!");
        return NULL;
    }
    sdp->ssct = ssct;
    sdp->port = port;
    sdp->work_flag = 1;
    sdp->sock_type = 0;
    sdp->is_ipv4 = is_ipv4;
    memcpy(sdp->cpus, cpus, core_num);
    sdp->core_num = core_num;
	strcpy(sdp->ethname, ethname);

    if (is_ipv4) {
        sa_len = sizeof(struct sockaddr_in);
    } else {
        sa_len = sizeof(struct sockaddr_in6);
    }

#ifdef SERVICE_USE_RQUEUE_RECV
    pthread_barrier_init(&sdp->start_barrier, NULL, sdp->core_num + 1);

    sdp->rq = rqueue_create(core_num, SERVICE_BUF_MAX_LEN + sa_len, SERVICE_RQ_NODE_NUM);
    if (unlikely(NULL == sdp->rq)) {
        LOG(SERVER, ERR, "Create ring queue failed.");
        return NULL;
    }

    if (ERROR == rqueue_create_mul_affipthr(sdp->rq_thr_id, service_udp_read_rqueue_task,
        sdp, sdp->cpus, sdp->core_num)) {
        rqueue_destroy(sdp->rq);
        LOG(SERVER, ERR, "Fail to create multiple pthread.");
        close(sdp->fd);
        sdp->fd = -1;
		return NULL;
    }

    pthread_barrier_wait(&sdp->start_barrier);
    pthread_barrier_destroy(&sdp->start_barrier);
#endif

	if (pthread_create(&sdp->thread_id, NULL,
                    service_udp_server_task, sdp) != 0)    {
		LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
        close(sdp->fd);
        ros_free(sdp);
        sdp = NULL;
        return NULL;
	}

    return sdp;
}

void service_unregister_udp(struct service_udp *sdp)
{
    if (likely(sdp != NULL)) {
        uint32_t cnt;

        sdp->work_flag = 0;

        if (sdp->thread_id)
            pthread_cancel(sdp->thread_id);

        if (sdp->fd > 0)
            close(sdp->fd);
        sdp->fd = -1;

        for (cnt = 0; cnt < sdp->core_num; ++cnt) {
#ifdef SERVICE_USE_RQUEUE_RECV
            pthread_cancel(sdp->rq_thr_id[cnt]);
#endif
        }
        ros_free(sdp);
        sdp = NULL;
    }
}

#ifdef SERVICE_USE_RQUEUE_RECV
static void *service_raw_read_rqueue_task(void *arg)
{
    struct service_raw *srw = (struct service_raw *)arg;
    rqueue_node_t *rq_node;
    rqueue_cb_t *rq_cb;
    service_process_cb_t ssct = srw->ssct;
    uint8_t cnt;

    pthread_barrier_wait(&srw->start_barrier);
    for (cnt = 0; cnt < srw->core_num; ++cnt) {
        if (sched_getcpu() == srw->cpus[cnt]) {
            rq_cb = &srw->rq[cnt];
            break;
        }
    }
    if (cnt >= srw->core_num) {
        LOG(SERVER, ERR, "Get rqueue fail, CPU ID %d invalid.", sched_getcpu());
        return NULL;
    }

    LOG(SERVER, RUNNING, "Rqueue task use core: %d, rq_index: %d, rq_cb(%p), srw->rq(%p).",
        sched_getcpu(), cnt, rq_cb, srw->rq);
    for (;;) {
        rq_node = rqueue_consume_always_s(rq_cb);

        if (likely(rq_node->data_len > 0)) {
            ssct(rq_node->data, rq_node->data_len, srw->param);
        }
        rqueue_set_consume_flag(rq_node);
	}

    return NULL;
}
#endif

void *service_raw_wraper(void *arg)
{
#ifdef SERVICE_USE_RQUEUE_RECV
    rqueue_node_t *rq_node;
#endif
    struct service_raw *srw = (struct service_raw *)arg;
    int fd = srw->fd;

    LOG(SERVER, DEBUG, "Enter channel raw recv task, work flag %d, fd %d, srw->rq->rq_num: %d.",
        srw->work_flag, srw->fd, srw->rq->rq_num);

    while(srw->work_flag) {
#ifdef SERVICE_USE_RQUEUE_RECV
        rq_node = rqueue_produce_always_m(srw->rq);

        rq_node->data_len = recvfrom(fd, rq_node->data,
                        srw->rq->db_size, 0, 0, 0);

        /* 任何情况下取出来的节点都要去设置为FULL状态 */
        rqueue_set_produce_flag(rq_node);

        if (srw->buflen < 0) {
            if (likely(srw->sdct))
                srw->sdct(srw->sdarg);
            srw->work_flag = FALSE;
            close(fd);
            srw->fd = -1;
            return NULL;
        }
#else
        srw->buflen = recvfrom(fd, srw->buf, SERVICE_BUF_TOTAL_LEN, 0, 0, 0);
        if (srw->buflen > 0) {
            srw->ssct(srw->buf, srw->buflen, (void *)srw->param);
        } else if (srw->buflen < 0) {
            if (srw->sdct)
                srw->sdct(srw->sdarg);
            srw->work_flag = 0;
            close(fd);
            srw->fd = -1;
            return NULL;
        }
#endif
	}

    return NULL;
}

int32_t service_raw_create(struct service_raw *srw)
{
    struct sockaddr_ll ll;
    struct ifreq ifr;
    int ret;
    char *ethname = srw->ethname;
    cpu_set_t cpuset;
    pthread_attr_t attr1;
    uint8_t cnt;

	/* Create endpoint */
	if ((srw->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
	    srw->fd = -1;
    	return ERROR;
	}

    memset((char *)&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ethname, strlen(ethname) + 1);
    memcpy(srw->ethname, ethname, strlen(ethname) + 1);

    /* Get interface index */
    ret = ioctl(srw->fd, SIOCGIFINDEX, &ifr);
    if (ret != 0) {
        LOG(SERVER, ERR, "No such interface: %s, create raw socket failed.", ethname);
        close(srw->fd);
	    srw->fd = -1;
    	return ERROR;
    }

    /* Bind the index */
    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_ifindex = ifr.ifr_ifindex;
    ll.sll_protocol = htons(ETH_P_ALL);
    if (bind(srw->fd, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
        close(srw->fd);
	    srw->fd = -1;
    	return ERROR;
    }

    /* Set interface up promisc */
	ifr.ifr_flags = IFF_UP | IFF_PROMISC;
	ret = ioctl(srw->fd, SIOCSIFFLAGS, &ifr);
    if (ret != 0) {
        close(srw->fd);
	    srw->fd = -1;
    	return ERROR;
    }

    srw->work_flag = TRUE;

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    for (cnt = 0; cnt < srw->core_num; ++cnt) {
        CPU_SET(srw->cpus[cnt], &cpuset);
    }

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(SERVER, ERR, "Pthread set affinity fail.");
        close(srw->fd);
        srw->fd = -1;
        srw->work_flag = FALSE;
        return ERROR;
    }

	if (pthread_create(&srw->thread_id, &attr1,
                    service_raw_wraper, srw) != 0)    {
		LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
        close(srw->fd);
        srw->fd = -1;
        srw->work_flag = FALSE;
		return ERROR;
	}

    return OK;
}

void *service_raw_task(void *arg)
{
    struct service_raw *srw = (struct service_raw *)arg;

    if (srw == NULL) {
		LOG(SERVER, ERR, "Incorrect input parameters!");
		return NULL;
    }

	for (;;) {

        if (srw->work_flag == FALSE) {
            if (srw->fd != -1) {
                close(srw->fd);
                srw->fd = -1;
            }

            service_raw_create(srw);
        }

        sleep(3);
	}

    return NULL;
}

int service_raw_set_trans(struct service_raw *srw, void *trans_mng)
{
    if (unlikely((srw == NULL) || (trans_mng == NULL))) {
        LOG(SERVER, ERR, "Incorrect input parameters, srw(%p), trans_mng: %p.", srw, trans_mng);
        return ERROR;
    }
    srw->param = trans_mng;

    return OK;
}

struct service_raw *
service_register_raw(uint8_t cpus[], uint8_t core_num,
    char *ethname, service_process_cb_t ssct, service_disconnect_cb_t sdct, void *sdarg)
{
    struct service_raw *srw = NULL;
    cpu_set_t cpuset;
    pthread_attr_t attr1;

    if (unlikely((ssct == NULL) || (core_num > SERVICE_CORE_NUM_MAX))) {
        LOG(SERVER, ERR, "Incorrect input parameters, ssct(%p), core_num: %d.", ssct, core_num);
        return NULL;
    }

    srw = ros_calloc(1, sizeof(struct service_raw));
    if (unlikely(srw == NULL)) {
		LOG(SERVER, ERR, "Not enough storage!");
        return NULL;
    }

    srw->ssct           = ssct;
    srw->sdct           = sdct;
    srw->sdarg          = sdarg;
    srw->work_flag      = 0;
    srw->sock_type      = 1;     /* raw socket */
    srw->fd             = -1;
    strcpy(srw->ethname, ethname);
    memcpy(srw->cpus, cpus, core_num);
    srw->core_num       = core_num;

#ifdef SERVICE_USE_RQUEUE_RECV
    pthread_barrier_init(&srw->start_barrier, NULL, srw->core_num + 1);

    srw->rq = rqueue_create(core_num, SERVICE_BUF_TOTAL_LEN, SERVICE_RQ_NODE_NUM);
    if (unlikely(NULL == srw->rq)) {
        LOG(SERVER, ERR, "Create ring queue failed.");
        return NULL;
    }

    if (ERROR == rqueue_create_mul_affipthr(srw->rq_thr_id, service_raw_read_rqueue_task,
        srw, srw->cpus, srw->core_num)) {
        rqueue_destroy(srw->rq);
        LOG(SERVER, ERR, "Fail to create multiple pthread.");
        close(srw->fd);
        srw->fd = -1;
		return NULL;
    }

    pthread_barrier_wait(&srw->start_barrier);
    pthread_barrier_destroy(&srw->start_barrier);
#endif

    pthread_attr_init(&attr1);
    CPU_ZERO(&cpuset);
    CPU_SET(srw->cpus[0], &cpuset);

    if (pthread_attr_setaffinity_np(&attr1, sizeof(cpu_set_t), &cpuset) != 0) {
        LOG(SERVER, ERR, "pthread_attr_setaffinity_np fail on core(%d)", srw->cpus[0]);
        return NULL;
    }

    if (pthread_create(&srw->thread_id, &attr1,
                    service_raw_task, srw) != 0)    {
        LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
        ros_free(srw);
        srw = NULL;
        return NULL;
    }

    return srw;
}

void service_unregister_raw(struct service_raw *srw)
{
    if (likely(srw != NULL)) {
        uint32_t cnt;
        /* kill this thread, the socket will not recreate */
        if (srw->thread_id)
            pthread_cancel(srw->thread_id);

        for (cnt = 0; cnt < srw->core_num; ++cnt) {
#ifdef SERVICE_USE_RQUEUE_RECV
            pthread_cancel(srw->rq_thr_id[cnt]);
#endif
        }

        /* set flag to 0, exit receive task */
        srw->work_flag = G_FALSE;

        /* close socket */
        if (srw->fd)
            close(srw->fd);

        /* free buffer */
        ros_free(srw);
        srw = NULL;
    }
}

void *service_tcp_server_recv(void *arg)
{
    struct service_tcp_server *setp = (struct service_tcp_server *)arg;
    int fd = setp->fd;
    int buf_len = 0;
    char buff[SERVICE_BUF_MAX_LEN];
    struct timeval timeout;
    fd_set read_set;

    LOG(SERVER, DEBUG, "Enter TCP receive task, work flag %d, fd %d.",
        setp->work_flag, fd);

    for (;;) {
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        switch (select(fd + 1, &read_set, NULL, NULL, &timeout)) {
            case 0:
                /* 0 means timeout */
                break;

            case -1:
                LOG(SERVER, ERR, "recv fail, errno:%s", strerror(errno));
                close(fd);
                setp->fd = -1;
                return NULL;

            default:
                if (FD_ISSET(fd, &read_set)) {
            		buf_len = recv(fd, buff, SERVICE_BUF_MAX_LEN, 0);
                    if (0 < buf_len) {
                        setp->ssct(buff, buf_len, arg);
                    } else {
                        LOG(SERVER, ERR, "recv fail, errno:%s", strerror(errno));
                        close(fd);
                        setp->fd = -1;
            			return NULL;
            		}
                }
                break;
        }
	}

    return NULL;
}

void *service_tcp_server_task(void *arg)
{
    struct service_tcp_server *setp = (struct service_tcp_server *)arg;
	int sock = 0;
	struct sockaddr_in remote, local;
	socklen_t len = sizeof(struct sockaddr_in);
    pthread_t thr_id = 0;
    int on = 1, nagle_flag = 1, cork_flag = 0;

    if (setp == NULL) {
		LOG(SERVER, ERR, "Incorrect input parameters!");
		return NULL;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		LOG(SERVER, ERR, "socket fail, errno:%s", strerror(errno));
		return NULL;
	}

    /*if (0 > setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
        (void*)&on, sizeof(on))) {
        LOG(SERVER, ERR, "setsocket fail, errno:%s", strerror(errno));
		return NULL;
    }*/

    if (0 > setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
        (void*)&on, sizeof(on))) {
        LOG(SERVER, ERR, "setsocket fail, errno:%s", strerror(errno));
		return NULL;
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                        &nagle_flag, sizeof(nagle_flag)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(sock);
        return NULL;
	}

    if (setsockopt(sock, SOL_TCP, TCP_CORK,
                        &cork_flag, sizeof(cork_flag)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(sock);
        return NULL;
	}

	local.sin_family = AF_INET;
	local.sin_port = htons(setp->port);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock,(struct sockaddr*)&local , len) < 0) {
		LOG(SERVER, ERR, "bind fail, errno:%s", strerror(errno));
		return NULL;
	}

	if (listen(sock, SERVICE_LISTEN_MAX) < 0)	{
		LOG(SERVER, ERR, "listen fail, errno:%s", strerror(errno));
		return NULL;
	}

	while (setp->work_flag) {
		setp->fd = accept(sock, (struct sockaddr*)&remote, &len);
		if(setp->fd < 0) {
            LOG(SERVER, ERR, "accept fail, errno:%s", strerror(errno));
			continue;
		}

        LOG(SERVER, DEBUG, "accept %s:%d success",
                    inet_ntoa(remote.sin_addr), remote.sin_port);

        if (pthread_create(&thr_id, NULL,
                        service_tcp_server_recv, setp) != 0) {
			LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                    strerror(errno));
            close(setp->fd);
			continue;
		}
	}

    if (sock)
        close(sock);

    return NULL;
}

struct service_tcp_server *
service_register_tcp_server(uint16_t port, service_process_cb_t ssct)
{
    struct service_tcp_server *setp = NULL;

    if (unlikely(ssct == NULL)) {
        LOG(SERVER, ERR, "Incorrect input parameters!");
        return NULL;
    }

    setp = ros_calloc(1, sizeof(struct service_tcp_server));
    if (unlikely(setp == NULL)) {
		LOG(SERVER, ERR, "Not enough storage!");
        return NULL;
    }
    setp->ssct = ssct;
    setp->port = port;
    setp->work_flag = G_TRUE;
    setp->sock_type = 0;

	if (pthread_create(&setp->thread_id, NULL,
                    service_tcp_server_task, setp) != 0)    {
		LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
        ros_free(setp);
        setp = NULL;
		return NULL;
	}

    return setp;
}

void service_unregister_tcp_server(struct service_tcp_server *setp)
{
    if (likely(setp != NULL)) {
        setp->work_flag = 0;

        if (setp->thread_id)
            pthread_cancel(setp->thread_id);

        if (setp->fd)
            close(setp->fd);

        ros_free(setp);
        setp = NULL;
    }
}

int service_register_tcp_client(uint16_t port, uint32_t ip)
{
	int reuse_flag = 1, nagle_flag = 1, cork_flag = 0, keepalive_flag = 5;
	struct sockaddr_in sin = {0};
    socklen_t len = sizeof(struct sockaddr_in);
    int fd = 0;
    struct timeval timeout = {60, 0}; //60s

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    	LOG(SERVER, ERR, "socket fail:%s", strerror(errno));
        return -1;
	}

	/* Set socket option */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                        &reuse_flag, sizeof(reuse_flag)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                        &nagle_flag, sizeof(nagle_flag)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

    if (setsockopt(fd, SOL_TCP, TCP_CORK,
                        &cork_flag, sizeof(cork_flag)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                        &keepalive_flag, sizeof(keepalive_flag)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

    if (0 > setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, sizeof(timeout))) {
        LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(ip);
	sin.sin_port = htons(port);

	if (connect(fd, (struct sockaddr*)&sin, len) < 0) {
        LOG(SERVER, ERR, "ip:%x, port:%d", ip, port);
        LOG(SERVER, ERR, "connect fail:%s", strerror(errno));
        close(fd);
        return -1;
	}
    LOG(SERVER, DEBUG, "connect %s:%d success",
                            inet_ntoa(sin.sin_addr), port);
    return fd;
}

void *service_channel_server_task(void *arg)
{
    struct service_channel_token *setp = (struct service_channel_token *)arg;
	int sock = 0;
	struct sockaddr_in remote, local;
	socklen_t len = sizeof(struct sockaddr_in);
    pthread_t thr_id = 0;
    int on = 1, keepalive_flag = 3;

    if (setp == NULL) {
		LOG(SERVER, ERR, "Incorrect input parameters!");
		return NULL;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		LOG(SERVER, ERR, "socket fail, errno:%s", strerror(errno));
		return NULL;
	}

    if (0 > setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
        (void*)&on, sizeof(on))) {
        LOG(SERVER, ERR, "setsocket fail, errno:%s", strerror(errno));
        close(sock);
		return NULL;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
                        &keepalive_flag, sizeof(keepalive_flag)) < 0) {
    	LOG(SERVER, ERR, "setsockopt fail:%s", strerror(errno));
        close(sock);
        return NULL;
	}

	local.sin_family = AF_INET;
	local.sin_port = htons(setp->port);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock,(struct sockaddr*)&local , len) < 0) {
		LOG(SERVER, ERR, "bind fail, errno:%s", strerror(errno));
		return NULL;
	}

	if (listen(sock, SERVICE_LISTEN_MAX) < 0)	{
		LOG(SERVER, ERR, "listen fail, errno:%s", strerror(errno));
		return NULL;
	}

	for (;;) {
		setp->fd = accept(sock, (struct sockaddr*)&remote, &len);
		if(setp->fd < 0) {
            LOG(SERVER, ERR, "accept fail, errno:%s", strerror(errno));
            sleep(3);
			continue;
		}
        setp->work_flag = TRUE;

        /* call reconnect callback */
        if (setp->scct) {
            setp->scct(setp->scarg);
        }

        LOG(SERVER, DEBUG, "accept %s:%d success",
                    inet_ntoa(remote.sin_addr), remote.sin_port);

        if (pthread_create(&thr_id, NULL,
                        service_channel_recv_wraper, setp) != 0) {
			LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                    strerror(errno));
            close(setp->fd);
			continue;
		}
	}

    return NULL;
}

void *service_channel_client_task(void *arg)
{
    struct service_channel_token *token = (struct service_channel_token *)arg;
    pthread_t thr_id = 0;

    if (token == NULL) {
		LOG(SERVER, ERR, "Incorrect input parameters!");
		return NULL;
    }

	for (;;) {
	    if (token->work_flag) {
            sleep(3);
            continue;
	    }

        token->fd = service_register_tcp_client(token->port, token->peerip);
        if (token->fd < 0) {
            /* Check connection every 3 seconds */
            sleep(3);
            continue;
        }
        token->work_flag = TRUE;

        /* call reconnect callback */
        if (token->scct) {
            token->scct(token->scarg);
        }

		LOG(SERVER, DEBUG, "Create channel receive task!");
        if (pthread_create(&thr_id, NULL,
                        service_channel_recv_wraper, token) != 0) {
			LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                    strerror(errno));
            close(token->fd);
            token->work_flag = FALSE;
			continue;
		}
	}

    return NULL;
}

struct service_channel_token *
service_channel_server_register(uint16_t port, service_process_cb_t ssct,
    service_connect_cb_t scct, void *scarg)
{
    struct service_channel_token *setp = NULL;

    if (unlikely(ssct == NULL)) {
        LOG(SERVER, ERR, "Incorrect input parameters!");
        return NULL;
    }

    setp = ros_calloc(1, sizeof(struct service_channel_token));
    if (unlikely(setp == NULL)) {
		LOG(SERVER, ERR, "Not enough storage!");
        return NULL;
    }
    setp->ssct      = ssct;
    setp->port      = port;
    setp->work_flag = G_FALSE;
    setp->sock_type = 0;
    setp->fd        = -1;
    setp->scct      = scct;
    setp->scarg     = scarg;

	if (pthread_create(&setp->thread_id, NULL,
                    service_channel_server_task, setp) != 0)    {
		LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                strerror(errno));
        ros_free(setp);
        setp = NULL;
		return NULL;
	}

    return setp;
}

struct service_channel_token *
service_channel_client_register(uint32_t peerip, uint16_t port, service_process_cb_t ssct,
    service_connect_cb_t scct, void *scarg)
{
    struct service_channel_token *setp = NULL;

    if (unlikely(ssct == NULL)) {
        LOG(SERVER, ERR, "Incorrect input parameters!");
        return NULL;
    }

    setp = ros_calloc(1, sizeof(struct service_channel_token));
    if (unlikely(setp == NULL)) {
		LOG(SERVER, ERR, "Not enough storage!");
        return NULL;
    }
    setp->ssct      = ssct;
    setp->peerip    = peerip;
    setp->port      = port;
    setp->work_flag = G_FALSE;
    setp->sock_type = 0;
    setp->scct      = scct;
    setp->scarg     = scarg;
    ros_rwlock_init(&setp->lock);

	if (pthread_create(&setp->thread_id, NULL,
                    service_channel_client_task, setp) != 0)    {
		LOG(SERVER, ERR, "Fail to create tcp client pthread, errno:%s",
                                strerror(errno));
        ros_free(setp);
        setp = NULL;
		return NULL;
	}

    return setp;
}

void *service_channel_recv_wraper(void *arg)
{
    struct service_channel_token *setp = (struct service_channel_token *)arg;
    int fd = setp->fd;
    int buf_len = 0;
    struct timeval timeout;
    fd_set read_set;
    char buff[SERVICE_BUF_MAX_LEN];

    LOG(SERVER, DEBUG, "Enter channel receive task, work flag %d, fd %d.",
        setp->work_flag, fd);

    while(setp->work_flag) {
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        switch (select(fd + 1, &read_set, NULL, NULL, &timeout)) {
            case 0:
                /* 0 means timeout */
                break;

            case -1:
                LOG(SERVER, ERR, "recv fail, errno:%s", strerror(errno));
                close(fd);
                setp->fd = -1;
                setp->work_flag = FALSE;
                return NULL;

            default:
                if (FD_ISSET(fd, &read_set)) {
            		buf_len = recv(fd, buff, SERVICE_BUF_MAX_LEN, 0);
                    if (0 < buf_len) {
                        setp->ssct(buff, buf_len, arg);
                    } else {
                        LOG(SERVER, ERR, "recv fail, errno:%s", strerror(errno));
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

int32_t service_channel_send(void *token, char *buf, uint32_t len)
{
    struct service_header *channel = (struct service_header *)token;

    if (FALSE == channel->work_flag) {
        LOG(SERVER, ERR, "Connection was broken.");
        return ERROR;
    }

    if (channel->sock_type == 0) {
        ros_rwlock_write_lock(&channel->lock); /* lock */
        if (send(channel->fd, buf, len, MSG_NOSIGNAL) < 0) {
            channel->work_flag = FALSE;
            ros_rwlock_write_unlock(&channel->lock); /* unlock */
            LOG(SERVER, ERR, "Send failed(%s).", strerror(errno));
            return ERROR;
        }
        ros_rwlock_write_unlock(&channel->lock); /* unlock */
    }
    else {
        ros_rwlock_write_lock(&channel->lock); /* lock */
        if (sendto(channel->fd, buf, len, 0, 0, 0) < 0) {
            channel->work_flag = FALSE;
            ros_rwlock_write_unlock(&channel->lock); /* unlock */
            LOG(SERVER, ERR, "Send failed(%s).", strerror(errno));
            LOG(SERVER, ERR, "channel fd: %d, buf(%p), len: %u\n", channel->fd, buf, len);
            return ERROR;
        }
        ros_rwlock_write_unlock(&channel->lock); /* unlock */
    }
    return OK;
}

struct service_channel_token *
service_channel_register(uint32_t peerip, uint16_t port, service_process_cb_t ssct,
     service_connect_cb_t scct, void *scarg)
{
    struct service_channel_token *token;

    /* If no peer ip, it is server */
    if (!peerip) {
        token = service_channel_server_register(port, ssct, scct, scarg);
    }
    else {
        token = service_channel_client_register(peerip, port, ssct, scct, scarg);
    }

    return token;
}

void service_channel_unregister(struct service_channel_token *token)
{
    if (likely(token != NULL)) {
        token->work_flag = 0;

        if (token->thread_id)
            pthread_cancel(token->thread_id);

        if (token->fd)
            close(token->fd);

        ros_free(token);
        token = NULL;
    }
}

void service_channel_show(void *token1)
{
    struct service_channel_token *token;

    if (!token1) {
        return;
    }
    token = (struct service_channel_token *)token1;

    printf("token %p:\r\n", token);
    printf("  socket fd %d\r\n", token->fd);
    printf("  thread id %d\r\n", (uint32_t)token->thread_id);
    printf("  ip        %x\r\n", token->peerip);
    printf("  port      %d\r\n", token->port);
    printf("  work flag %d\r\n", token->work_flag);
    printf("  scct      %lx\r\n", *(uint64_t *)token->scct);
    printf("  scarg     %lx\r\n", *(uint64_t *)token->scarg);
    printf("\r\n");
}

void *service_local_recv(void *arg)
{
    struct service_local *sl = (struct service_local *)arg;
    int fd = sl->fd;
    int buf_len = 0;
    char buff[SERVICE_BUF_MAX_LEN];
    for ( ; ; ) {
        buf_len = recv(fd, buff, SERVICE_BUF_MAX_LEN, 0);
        if (buf_len > 0) {
            sl->ssct(buff, buf_len, (void *)&fd);
        } else {
            LOG(SERVER, ERR, "recv fail, errno:%s", strerror(errno));
            close(fd);
			break;
		}
	}

    return NULL;
}

int service_register_local_client(char *path_name)
{
	int fd;
	struct sockaddr_un local;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		LOG(SERVER, ERR, "socket errno:%s\n", strerror(errno));
		return -1;
	}

	local.sun_family = AF_LOCAL;
    local.sun_path[0] = 0;
	strcpy(local.sun_path + 1, path_name);

    if (connect(fd, (struct sockaddr*)&local, sizeof(local)) < 0) {
        LOG(SERVER, ERR, "connect fail:%s", strerror(errno));
        close(fd);
        return -1;
	}

	return fd;
}

struct service_local *service_register_local_server(char *path_name, service_process_cb_t ssct)
{
	int fd;
	struct sockaddr_un servaddr = {0}, cliaddr = {0};
    pthread_t thread_id;
    struct service_local *sl = NULL;
    socklen_t clilen = sizeof(cliaddr);

    if (NULL == path_name) {
        LOG(SERVER, ERR, "Abnormal parameter, path_name(%p).", path_name);
        return NULL;
    }

    sl = ros_calloc(1, sizeof(struct service_local));
    if (unlikely(sl == NULL)) {
		LOG(SERVER, ERR, "Not enough storage!");
        return NULL;
    }

    sl->ssct = ssct;


	unlink(path_name);
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return NULL;
	}
    sl->fd = fd;
    sl->work_flag = 1;
    ros_rwlock_init(&sl->lock);

    bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
    servaddr.sun_path[0] = 0;
	strcpy(servaddr.sun_path + 1, path_name);

	if (bind(fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		LOG(SERVER, ERR, "bind fail, errno:%s", strerror(errno));
        close(fd);
		return NULL;
	}

	if (listen(fd, SERVICE_LISTEN_MAX) < 0) {
		LOG(SERVER, ERR, "listen fail, errno:%s", strerror(errno));
		close(fd);
		return NULL;
	}

	for ( ; ; ) {
		sl->fd = accept(fd, &cliaddr, &clilen);
		if (sl->fd < 0) {
			LOG(SERVER, ERR, "accept fail, errno:%s", strerror(errno));
			continue;
		}

        LOG(SERVER, RUNNING, "accept success.");

        if (pthread_create(&thread_id, NULL,
                        service_local_recv, sl) != 0) {
			LOG(SERVER, ERR, "Fail to create pthread, errno:%s",
                                    strerror(errno));
            close(sl->fd);
			continue;
		}
	}

	return NULL;
}

int32_t service_init(struct pcf_file *conf)
{
#if (defined(PRODUCT_IS_fpu))
    if (fp_init_prepare(conf) < 0)
        return -1;

    if (G_SUCCESS != ros_init(conf))
        return -1;

    if (fp_init_phaseI() < 0)
        return -1;
#elif (defined(PRODUCT_IS_lbu))
    if (0 > lb_init_prepare(conf))
        return -1;

    if (G_SUCCESS != ros_init(conf))
        return -1;

    if (lb_init() < 0)
        return -1;
#elif (defined(PRODUCT_IS_smu))
    if (G_SUCCESS != ros_init(conf))
        return -1;

    if (upc_init(conf) < 0)
        return -1;
#elif (defined(PRODUCT_IS_stub))
    if (G_SUCCESS != ros_init(conf))
        return -1;

    if (stub_init(conf) < 0)
        return -1;
#endif

    return 0;
}

void service_deinit(void)
{
    #if (defined(PRODUCT_IS_fpu))
        fp_deinit();
    #elif (defined(PRODUCT_IS_smu))
        upc_deinit();
    #elif (defined(PRODUCT_IS_stub))
        stub_deinit();
    #elif (defined(PRODUCT_IS_lbu))
        lb_deinit();
    #endif
}

