/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "fp_msg.h"
#include "fp_frag.h"

fp_frag_cb *fp_frag_alloc_cb()
{
    fp_frag_cb *cb;
    int32_t  iloop;

    cb = (fp_frag_cb *)fp_pure_buff_alloc(fp_frag_buff_get());
    if (!cb) {
        return NULL;
    }

    cb->cur_len   = 0;
    cb->last_flag = FALSE;

    for (iloop = 0; iloop < FP_FRAG_MAX; iloop++) {
        cb->desc[iloop].valid = 0;
    }

    return cb;
}

/* return:
   NULL,         continue to do more
   fp_frag_cb *, don't need more process, directly return */
fp_frag_cb *fp_frag_entry(void *head1, struct pro_ipv4_hdr *ipheader)
{
    uint32_t                aux_info;
    fp_frag_cb              *frag_cb;
    fp_fast_table           *head = (fp_fast_table *)head1;

    /* Hash ip to get auxinfo */
    aux_info = hash16_by_long(0, PktGetIpv4Long(ipheader));
    frag_cb = fp_frag_table_match(head, ipheader->id, aux_info);
    if (unlikely(!frag_cb)) {
        fp_frag_table_add(head, ipheader->id, aux_info);
    }

    fp_frag_defrag(frag_cb, ipheader);

    /* Check frag bit, if zero, it is last fragment */
    if (!(ipheader->frag_off & IP_PRO_FRAG_MORE)) {
        frag_cb->last_flag = TRUE;
    }

    if (fp_frag_check_full(frag_cb) == OK) {
        return frag_cb;
    }

    return NULL;
}

/* return:
   pkt,  received all fragments, need send all out
   NULL, wait more, release current packet */
int32_t fp_frag_defrag(fp_frag_cb *cb, struct pro_ipv4_hdr *ipheader)
{
    int32_t  iloop = 0;
    uint32_t frag_off, ipheader_len;
    uint8_t  match_flag;
    fp_frag_desc tgt, swap;

    /* calc frag offset */
    frag_off = (ipheader->frag_off << 3);

    /* first packet */
    if (cb->cur_len == 0) {
        match_flag  = 0;
    }
    else {

        /* set default */
        match_flag = 0;

        /* set tgt unit */
        tgt.length = ipheader->tot_len;
        tgt.offset = frag_off;
        tgt.valid  = 1;

        /* search and order */
        for (iloop = 0; iloop < FP_FRAG_MAX; iloop++) {
            if (!cb->desc[iloop].valid) {
                break;
            }

            /* combine next */
            if (cb->desc[iloop].offset + cb->desc[iloop].length == frag_off) {
                cb->desc[iloop].length += ipheader->tot_len;
                match_flag = 1;
                break;
            }

            if (cb->desc[iloop].offset < frag_off) {
                continue;
            }

            /* combine prev */
            if (cb->desc[iloop].offset == frag_off + ipheader->tot_len) {
                cb->desc[iloop].offset = frag_off;
                match_flag = 1;
                break;
            }

            /* insert */
            memcpy(&swap, &cb->desc[iloop], sizeof(fp_frag_desc));
            memcpy(&cb->desc[iloop], &tgt, sizeof(fp_frag_desc));
            memcpy(&tgt, &swap, sizeof(fp_frag_desc));
        }
    }

    /* save metadata */
    if (match_flag == 0) {
        memcpy(&cb->desc[iloop], &tgt, sizeof(fp_frag_desc));
    }

    /* calculate ip header length */
    ipheader_len = (ipheader->ihl << 2);

    /* if first packet, copy header */
    if (cb->cur_len == 0) {
        memcpy(cb->buff + FP_FRAG_SPARE - ipheader_len, (char *)ipheader, ipheader_len);
    }

    /* copy payload */
    memcpy(cb->buff + FP_FRAG_SPARE + frag_off, (char *)ipheader + ipheader_len,
        ntohs(ipheader->tot_len) - ipheader_len);

    /* save current max length */
    if (frag_off + ipheader->tot_len > cb->cur_len) {
        cb->cur_len = frag_off + ipheader->tot_len;
    }

    return OK;
}

int32_t fp_frag_check_full(fp_frag_cb *cb)
{
    int32_t  iloop;
    uint32_t cur_off = 0;

    if (!cb->last_flag) {
        return ERROR;
    }

    /*  */
    for (iloop = 0; iloop < FP_FRAG_MAX; iloop++) {

        if (!cb->desc[iloop].valid) {
            /* not to max length, but no more section */
            return ERROR;
        }

        if (cb->desc[iloop].offset != cur_off) {
            /* not receive expected fragment */
            return ERROR;
        }
        else {
            cur_off += cb->desc[iloop].length;
            if (cur_off == cb->cur_len) {
                return OK;
            }
        }
    }
    return ERROR;
}

inline fp_frag_cb *fp_frag_table_match(void *table1, uint16_t id, uint32_t aux_info)
{
    fp_fast_bucket          *frag;
    uint8_t                 *point;
    fp_frag_cb              *cb;
    fp_fast_table           *table = (fp_fast_table *)table1;

    frag = &table->frag[id];

    LOG(FASTPASS, RUNNING, "search frag id 0x%04x, aux_info 0x%08x, tree %p, hight %d.",
        id, aux_info, frag->hash_tree,
        (frag->hash_tree)?frag->hash_tree->height:0);

    ros_rwlock_read_lock(&frag->rwlock);
    point = (uint8_t *)avluint_search(frag->hash_tree, aux_info);
    if (!point)
    {
        ros_rwlock_read_unlock(&frag->rwlock);
        LOG(FASTPASS, RUNNING, "no matched entry found.");
        return NULL;
    }
    ros_rwlock_read_unlock(&frag->rwlock);

    cb = (fp_frag_cb *)(point - OFFSET(fp_frag_cb, avlnode));

    return cb;
}

/* Add fast entry to hash tree */
fp_frag_cb *fp_frag_table_add(void *head1, uint32_t id, uint32_t aux_info)
{
    void                    *entry_tmp;
    fp_fast_bucket          *frag;
    fp_fast_table           *head = (fp_fast_table *)head1;
    fp_frag_cb              *frag_cb;

    LOG(FASTPASS, RUNNING,
        "add id %04x, aux value %08x to frag tree!", id, aux_info);

    frag = &(head->frag[id]);

    frag_cb = fp_frag_alloc_cb();
    if (!frag_cb) {
        return NULL;
    }

    ros_rwlock_write_lock(&frag->rwlock);

    /* Check if item exist in table */
    entry_tmp = (void *)avluint_search(frag->hash_tree, aux_info);
    if (entry_tmp) {

        ros_rwlock_write_unlock(&frag->rwlock);
        return NULL;
    }

    if (OK != avluint_insert(&frag->hash_tree, (AVLU_NODE *)&frag_cb->avlnode)){

        ros_rwlock_write_unlock(&frag->rwlock);
        return NULL;
    }

    ros_rwlock_write_unlock(&frag->rwlock);

    LOG(FASTPASS, RUNNING,
        "frag->hash_tree %p!", frag->hash_tree);

    return frag_cb;
}

/* Delete frag entry from hash tree */
int32_t fp_frag_table_del(void *head1, uint32_t id, uint32_t aux_info)
{
    fp_fast_bucket          *frag;
    AVLU_NODE               *node;
    fp_fast_table           *head = (fp_fast_table *)head1;

    LOG(FASTPASS, RUNNING,
        "del id %04x frag tree, aux value %08x!", id, aux_info);

    frag = &(head->frag[id]);

    ros_rwlock_write_lock(&frag->rwlock);
    node = (AVLU_NODE *)avluint_delete(&frag->hash_tree, aux_info);
    if (unlikely(!node))
    {
        ros_rwlock_write_unlock(&frag->rwlock);
        LOG(FASTPASS, ERR, "del frag from id tree failed.");
        return ERROR;
    }
    ros_rwlock_write_unlock(&frag->rwlock);

    return OK;
}

//计算头长，包括eth+ipL1+udp+gtp+ipL2
int ip_frag_calc_head_len(char *buf, int len, int *out_extlen)
{
    struct pro_gtp_hdr  *gtpu_hdr;
	union pro_gtp_flags *gtp_flags;
	struct pro_ipv4_hdr     *ipheader;
	struct pro_ipv4_hdr     *ip_l2;
	int            	extlen = 0;//gtp额外的头长
	int				header_len = 0;
	char 			*buf_in;

	if(buf == NULL)
	{
		LOG(FASTPASS, ERR, "buf(%p) is null",buf);
		return -1;
	}

	if((ipheader = pkt_get_l3_header(buf, len)) == NULL)
	{
		LOG(FASTPASS, ERR, "ip_frag_calc_head_len ipheader(%p) is null",ipheader);
		return -1;
	}

	//以太网头暂时不考虑vlan的情况
	gtpu_hdr = (struct pro_gtp_hdr *)(buf + sizeof(struct pro_eth_hdr)+
		ipheader->ihl*4+ sizeof(struct pro_udp_hdr));

	gtp_flags = &gtpu_hdr->flags;

	//计算gtp额外的头长
	if (gtp_flags->s.e || gtp_flags->s.s || gtp_flags->s.pn) {
        uint8_t  nextHdr;
        /* extension header length 定义为4字节，
           因为其长度实际是4字节为单位的，算偏移时要乘法，以防溢出 */
        uint32_t extHeaderLen;
        uint16_t extIdx = 0;

        /* sequence */
        if (gtp_flags->s.s) {
            /* do nothing now */
        }
        extlen += 2;

        /* N-PDU */
        if (gtp_flags->s.pn) {
            /* do nothing now */
        }
        extlen++;

		buf_in = (char *)((char *)gtpu_hdr + sizeof(struct pro_gtp_hdr));
        if (gtp_flags->s.e) {

            /* parse extension type */
            nextHdr = *(uint8_t *)(buf_in + extlen);
            extlen++;
            while (nextHdr) {
                extHeaderLen = *(uint8_t *)(buf_in + extlen);
                extlen++;

                /* do next header parse, then calcuate head offset */
                extlen += (extHeaderLen * 4 - 2);

                LOG(SERVER, RUNNING,
                    "extIdx:%d, type:0x%02x, length:%d.\n",
                    extIdx, nextHdr, extHeaderLen);
                extIdx++;
                nextHdr = *(uint8_t *)(buf_in + extlen);
                extlen++;
            }
        }
        else {
            extlen++;
        }
    }

	ip_l2 = (struct pro_ipv4_hdr *)((char *)gtpu_hdr+ sizeof(struct pro_gtp_hdr) + extlen);
	header_len = sizeof(struct pro_eth_hdr)+ ipheader->ihl*4 +
		sizeof(struct pro_udp_hdr) + (sizeof(struct pro_gtp_hdr) + extlen) + ip_l2->ihl*4;

	LOG(FASTPASS, RUNNING, "ip_frag_calc_head_len [%d %d %d %d]",header_len,extlen,ipheader->ihl*4,ip_l2->ihl*4);

	if(out_extlen)
		*out_extlen = extlen;
	return header_len;

}

void fp_printf_buf(char *buf_in, int len)
{
	char buf[1024]={0};
	int i,n=0;

	n+=sprintf(buf+n,"\r\n");
	for(i=0;i<len;i++)
	{
		n+=sprintf(buf+n,"%02x ",(buf_in[i]&0xff));
		if((i+1)%16 == 0)
			n+=sprintf(buf+n,"\r\n");
	}

	LOG(FASTPASS, RUNNING, "%s",buf);
	return;
}

char* fp_find_str(char* src,int len, char* sub)
{
	const char *bp;
	const char *sp;
	int	i;
	if(!src || !sub)
	{
		return src;
	}
	LOG(FASTPASS, RUNNING, "fp_find_str [%p %p] len:%d\r\n",src,sub,len);
	/* 遍历src字符串  */
	for(i=0;i<len;i++)
	{
		/* 用来遍历子串 */
		bp = &src[i];
		sp = sub;
		do
		{
			if(!*sp)  /*到了sub的结束位置，返回src位置   */
			{
				LOG(FASTPASS, RUNNING, "fp_find_str len:%d i:%d\r\n",len,i);
				return src;
			}
		}while(*bp++ == *sp ++);
	}
	return NULL;
}


int32_t fp_check_http_head_is_full(char *buf, int len)
{
	char *end_str = "\r\n\r\n";
	char *offset_buf = NULL;
	char *tcp_payload = NULL;
	char *http_head[FP_HTTP_HEAD_NUM]={"GET","HEA","POS","PUT","DEL","CON","OPT","TRA","PAT"};
	struct pro_tcp_hdr *tcp_hdr = NULL;
	int header_len = 0,tcp_payload_len = 0;
	uint8_t	tls_pro_type;
	uint32_t	handshake_type;
	int i=0;

	if (buf == NULL)
	{
        LOG(FASTPASS, ERR, "fp_check_http_head_is_full buf is null[%p] len[%d]",buf,len);
        return ERROR;
    }

	header_len = ip_frag_calc_head_len(buf,len,NULL);
	tcp_hdr = (struct pro_tcp_hdr *)(buf + header_len);
	tcp_payload = buf + header_len + tcp_hdr->doff*4;
	tcp_payload_len = len - header_len - tcp_hdr->doff*4;

	if((ntohs(tcp_hdr->dest) == 80) || (ntohs(tcp_hdr->dest) == 8080))
	{
		for(i=0;i<FP_HTTP_HEAD_NUM;i++)
		{
			if(strncmp(tcp_payload,http_head[i],3) == 0)
			{
				break;
			}
		}

		if(i == FP_HTTP_HEAD_NUM)
		{
	        LOG(FASTPASS, RUNNING, "fp_check_http_head_is_full can't find http head[%x %x %x]",
				tcp_payload[0],tcp_payload[1],tcp_payload[2]);
	        return ERROR;
	    }

		if((i== 0) && (len>20))
		{
			offset_buf = buf+(len-20);
			if(fp_find_str(offset_buf,20,end_str))
			{
		        LOG(FASTPASS, RUNNING, "fp_check_http_head_is_full find end str in last 20 bytes");
		        return OK;
		    }
		}

		if(fp_find_str(tcp_payload,tcp_payload_len,end_str))
		{
	        LOG(FASTPASS, RUNNING, "fp_check_http_head_is_full find end str");
	        return OK;
	    }

		LOG(FASTPASS, RUNNING, "fp_check_http_head_is_full buf [%p] len[%d], can't find end str",buf,len);
		return ERROR;
	}
	else if(ntohs(tcp_hdr->dest) == 443)
	{
		tls_pro_type = *tcp_payload;
		if(tls_pro_type == TLS_CONTENT_TYPE_HANDSHAKE)
		{
			handshake_type = ntohl(*((uint32_t *)(tcp_payload+5)));
			if(((handshake_type>>24)&0xff) == TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
			{
				if((tcp_payload_len-9) == (handshake_type&0xffffff))
				{
			        return OK;
			    }
			}
			else if(tls_pro_type == TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE)
			{
				return OK;
			}
		}
		else if(tls_pro_type == TLS_CONTENT_TYPE_APPLICATION)
		{
			return OK;
		}
	}
	else
	{
		LOG(FASTPASS, RUNNING, "fp_check_http_head_is_full other dest port[%d]",ntohs(tcp_hdr->dest));
		return OK;
	}
	return ERROR;
}

void fp_tcp_segment_free(void	 **tcp_seg_mgmt_head)
{
	fp_tcp_segment_desc *prev=NULL,*current=NULL;
	fp_tcp_segment_mgmt	*tcp_seg_mgmt = NULL;

	if(tcp_seg_mgmt_head == NULL)
	{
		LOG(FASTPASS, ERR, "fp_free_buf_queue tcp_seg_mgmt_head is null");
		return;
	}

	if((tcp_seg_mgmt = (fp_tcp_segment_mgmt *)(*tcp_seg_mgmt_head)) == NULL)
	{
		LOG(FASTPASS, ERR, "fp_free_buf_queue tcp_seg_mgmt is null");
		return;
	}

	if(tcp_seg_mgmt->list)
	{
		for(prev = tcp_seg_mgmt->list,current = tcp_seg_mgmt->list->next; current;
			prev = current, current = current->next)
		{
			ros_free(prev);
		}
		ros_free(prev);
	}

	if(tcp_seg_mgmt)
		ros_free(tcp_seg_mgmt);

	*tcp_seg_mgmt_head = NULL;
	return;
}

char *fp_tcp_segment_reasm(fp_tcp_segment_mgmt *tcp_seg_mgmt, int *buf_len)
{
	//struct ip_frag_value *current = NULL;
	fp_tcp_segment_desc  *current = NULL;
	struct pro_ipv4_hdr *ipL1_hdr,*ipL2_hdr;
    struct pro_udp_hdr  *udp_hdr;
    struct pro_gtp_hdr  *gtpu_hdr;
	struct pro_tcp_hdr *first_tcp_hdr = NULL;
	char *buf = NULL;
	int size = 0,head_size = 0,first_head_size = 0,total_len = 0;
	int	pos = 0;
	int content_len = 0;
	int extlen = 0;//gtp额外的头长

	if((tcp_seg_mgmt->list == NULL) || (tcp_seg_mgmt->seg_total_len == 0))
	{
		LOG(FASTPASS, ERR, "tcp_seg_mgmt_head(%p) is null or len(%d) is zero",tcp_seg_mgmt->list,
			tcp_seg_mgmt->seg_total_len);
		return NULL;
	}

	//新的报文长度为数据包总长加上各种头，并预留一段空间
	first_head_size = ip_frag_calc_head_len(tcp_seg_mgmt->list->buf,tcp_seg_mgmt->list->len,&extlen);
	first_tcp_hdr = (struct pro_tcp_hdr *)(tcp_seg_mgmt->list->buf + first_head_size);
	first_head_size += (first_tcp_hdr->doff*4);

	total_len = tcp_seg_mgmt->seg_total_len + first_head_size;
	size = total_len +100;

	LOG(FASTPASS, RUNNING, "tcp_segment_reasm total_len[%d] head_size[%d %d %d]",total_len,first_head_size,
		(first_tcp_hdr->doff*4),tcp_seg_mgmt->list->len);
	if((buf=ros_malloc(size)) == NULL)
	{
		LOG(FASTPASS, ERR, "ros_malloc new buf failed size %d",size);
		return NULL;
	}

	ros_memcpy(buf,tcp_seg_mgmt->list->buf,first_head_size);
	pos = first_head_size;
	for(current = tcp_seg_mgmt->list; current;current = current->next)
	{
		head_size= current->len - current->tcp_payload_len;
		ros_memcpy(buf+pos,(current->buf+head_size),current->tcp_payload_len);
		pos+=current->tcp_payload_len;
	}

	if(total_len != pos)
	{
		ros_free(buf);
		LOG(FASTPASS, ERR, "queue len[%d] != all segment len[%d], rebuild failed!",total_len,pos);
		return NULL;
	}

	//重新设置各种头的校验码和长度
	ipL1_hdr   = (struct pro_ipv4_hdr *)((char *)buf + sizeof(struct pro_eth_hdr));

	udp_hdr  = (struct pro_udp_hdr *)((char *)ipL1_hdr + ipL1_hdr->ihl*4);

	gtpu_hdr = (struct pro_gtp_hdr *)((char *)udp_hdr + sizeof(struct pro_udp_hdr));
    ip_frag_calc_head_len(tcp_seg_mgmt->list->buf,tcp_seg_mgmt->list->len,&extlen);

    ipL2_hdr   = (struct pro_ipv4_hdr *)((char *)gtpu_hdr + sizeof(struct pro_gtp_hdr) + extlen);

	/* set L2ip header */
    content_len      	+= (tcp_seg_mgmt->seg_total_len + ipL2_hdr->ihl*4 + first_tcp_hdr->doff*4);
    ipL2_hdr->tot_len   = htons(content_len);
	ipL2_hdr->frag_off	= htons(0x4000);
	ipL2_hdr->check     = 0;
    ipL2_hdr->check    	= calc_crc_ip(ipL2_hdr);

	/* set GTP header */
	//gtp头有点特殊，它只包含载荷和额外的头长，不包含自己的头长8字节
    content_len      	+= extlen;
    gtpu_hdr->length    = htons(content_len);

	/* set UDP header */
    content_len 		+= (sizeof(struct pro_udp_hdr) + sizeof(struct pro_gtp_hdr));
    udp_hdr->len        = htons(content_len);

	/* set L1ip header */
    content_len      	+= (ipL1_hdr->ihl*4);
    ipL1_hdr->tot_len   = htons(content_len);
	ipL1_hdr->check    = 0;
    ipL1_hdr->check    	= calc_crc_ip(ipL1_hdr);

	udp_hdr->check  = calc_crc_udp(udp_hdr,ipL1_hdr);

	LOG(FASTPASS, RUNNING, "ip_frag_reasm [%d %x] [%d] [%d %x] [%d %x]",ntohs(ipL2_hdr->tot_len),ntohs(ipL2_hdr->check),
		ntohs(gtpu_hdr->length),ntohs(udp_hdr->len),ntohs(udp_hdr->check),
		ntohs(ipL1_hdr->tot_len),ntohs(ipL1_hdr->check));
	*buf_len = pos;
	return buf;

}

int32_t fp_tcp_segment_process(void **entry, char *buf, void *arg, int len,
		struct pro_tcp_hdr *tcp_hdr)
{
	fp_tcp_segment_desc *tcp_seg = NULL;
	fp_tcp_segment_desc *old_tcp_seg = NULL;
	fp_tcp_segment_desc *current = NULL,*prev = NULL;
	fp_tcp_segment_mgmt	*seg_mgmt = NULL;
	unsigned int	new_seq;
	int header_len = 0;
	int tcp_payload_len = 0;

	if (entry == NULL)
	{
        LOG(FASTPASS, ERR, "fp_tcp_fegment_process para is null[%p]", entry);
        return ERROR;
    }

	seg_mgmt = (fp_tcp_segment_mgmt *)(*entry);
	if (seg_mgmt == NULL)
	{
		if ((seg_mgmt = ros_malloc(sizeof(fp_tcp_segment_mgmt))) == NULL)
		{
	        LOG(FASTPASS, ERR, "fp_tcp_fegment_process alloc segment_mgmt failed!");
	        return ERROR;
    	}
		else
		{
			memset(seg_mgmt,0,sizeof(fp_tcp_segment_mgmt));
		}
		*entry = seg_mgmt;
	}

	tcp_seg = ros_malloc(sizeof(fp_tcp_segment_desc));
	if(tcp_seg == NULL)
	{
        LOG(FASTPASS, ERR, "fp_tcp_fegment_process alloc segment_desc failed!");
        return ERROR;
    }
	else
	{
		header_len = ip_frag_calc_head_len(buf,len,NULL);
		tcp_payload_len = (len- header_len - tcp_hdr->doff*4);

		tcp_seg->arg = arg;
		tcp_seg->buf = buf;
		tcp_seg->len = len;
		tcp_seg->tcp_payload_len = tcp_payload_len;
		tcp_seg->sequence = ntohl(tcp_hdr->seq);
		tcp_seg->next = NULL;
		tcp_seg->prev = NULL;
	}

	LOG(FASTPASS, RUNNING, "fp_tcp_fegment_process arg[%p %p %d] pay_len[%d] seq[%x] doff[%d] list[%p]",tcp_seg->arg,tcp_seg->buf,tcp_seg->len,
		tcp_seg->tcp_payload_len,tcp_seg->sequence,tcp_hdr->doff*4,seg_mgmt->list);
	if(seg_mgmt->list == NULL)
	{
		seg_mgmt->list = tcp_seg;
		seg_mgmt->meat_total_len = tcp_payload_len;
		seg_mgmt->seg_total_len = tcp_payload_len;
	}
	else
	{
		new_seq = ntohl(tcp_hdr->seq);
		if(new_seq < seg_mgmt->list->sequence)
		{
			old_tcp_seg = seg_mgmt->list;
			tcp_seg->next = old_tcp_seg;
			tcp_seg->prev = NULL;
			old_tcp_seg->prev = tcp_seg;
			seg_mgmt->list=tcp_seg;
		}
		else if(new_seq > seg_mgmt->list->sequence)
		{
			//找到第一个大于新分段的sequence的分段，把新分段插入到它的前面
			for(prev = seg_mgmt->list,current = seg_mgmt->list->next; current;
				prev = current, current = current->next)
			{
				if(new_seq == current->sequence)
				{
					LOG(FASTPASS, ERR, "fp_tcp_fegment_process current->sequence:%d == new_seq:%d",current->sequence,new_seq);
					ros_free(tcp_seg);
					return ERROR;
				}
				else if(new_seq < current->sequence)
				{
					prev->next = tcp_seg;
					tcp_seg->prev = prev;
					tcp_seg->next = current;
					current->prev = tcp_seg;
					break;
				}
			}
			//遍历完了都没找到，把新分段放到末尾(prev)
			if(current == NULL && prev != NULL)
			{
				prev->next = tcp_seg;
				tcp_seg->prev = prev;
			}
		}
		else if(new_seq == seg_mgmt->list->sequence)
		{
			LOG(FASTPASS, DEBUG, "Duplicate fragment packet sequence:0x%x", new_seq);
			ros_free(tcp_seg);
			return ERROR;
		}

		//找到最后一个分段
		for(current = seg_mgmt->list; current->next!=NULL;current = current->next)
		{
			;
		}

		if(current->sequence <= seg_mgmt->list->sequence)
		{
			LOG(FASTPASS, ERR, "last segment sequence[%d] <= first segment sequence[%d], error!",
				current->sequence,seg_mgmt->list->sequence);
			return ERROR;
		}

		/*meat总长等于最后一个分段Sequence减第一个分段Sequence
		   加上自身tcp载荷长度*/
		seg_mgmt->meat_total_len = (current->sequence-seg_mgmt->list->sequence)+ current->tcp_payload_len;
		/*seg总长等于每个tcp载荷长度相加*/
		seg_mgmt->seg_total_len += tcp_payload_len;
	}
	seg_mgmt->num++;
	LOG(FASTPASS, RUNNING, "num[%d] total_len[%d %d]",seg_mgmt->num,seg_mgmt->meat_total_len,seg_mgmt->seg_total_len);

	return OK;
}


