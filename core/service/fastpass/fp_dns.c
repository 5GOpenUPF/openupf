/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "fp_msg.h"
#ifndef ENABLE_OCTEON_III
#include "fp_dpdk_adapter.h"
#endif
#include "fp_dns.h"
#include "fp_start.h"


CVMX_SHARED fp_dns_table *fp_dns_pool_head = NULL;
CVMX_SHARED fp_dns_credible_table *fp_dns_cdb_pool_head = NULL;

static int64_t fp_dns_cdb_init(uint32_t node_num);

static inline fp_dns_table *fp_dns_table_get()
{
    return fp_dns_pool_head;
}

fp_dns_table *fp_dns_table_get_public(void)
{
    return fp_dns_pool_head;
}

static inline fp_dns_bucket *fp_dns_bucket_get(uint16_t hashkey)
{
    if (likely(fp_dns_pool_head)) {
        return &fp_dns_pool_head->bucket[(hashkey & fp_dns_pool_head->bucket_mask)];
    } else {
        return NULL;
    }
}

static inline fp_dns_cache_node *fp_dns_node_get(uint32_t index)
{
    if (likely(fp_dns_pool_head && index < fp_dns_pool_head->entry_max)) {
        return &fp_dns_pool_head->entry[index];
    } else {
        return NULL;
    }
}

fp_dns_cache_node *fp_dns_node_get_public(uint32_t index)
{
    if (fp_dns_pool_head) {
        return &fp_dns_pool_head->entry[index];
    } else {
        return NULL;
    }
}

int64_t fp_dns_node_init(uint32_t node_num)
{
    int32_t             res_no = 0;
    uint8_t             *tmp = NULL;
    int64_t             total_mem = 0, size = 0;
    uint64_t            ret64;
    int32_t             loop;
    fp_dns_table        *head;

    /* create block pool */
    size = node_num * sizeof(fp_dns_cache_node) + sizeof(fp_dns_table) + FP_DNS_BUCKET_NUM * sizeof(fp_dns_bucket);
    total_mem += size;
    tmp = (uint8_t *)BUFFER_SHM_MALLOC(GLB_DNS_POOL_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        LOG(FASTPASS, RUNNING, ".");
        return ERROR;
    }

    head = (fp_dns_table *)tmp;
    head->entry = (fp_dns_cache_node *)((char *)tmp + sizeof(fp_dns_table));
    for (loop = 0; loop < node_num; loop++) {
        head->entry[loop].index = loop;
    }

    head->bucket = (fp_dns_bucket *)((char *)head->entry + node_num * sizeof(fp_dns_cache_node));
    for (loop = 0; loop < FP_DNS_BUCKET_NUM; loop++) {
        head->bucket[loop].dns_root = RB_ROOT_INIT_VALUE;
        ros_rwlock_init(&head->bucket[loop].rwlock);
    }

    res_no = Res_CreatePool();
    if (res_no < 0) {
        LOG(FASTPASS, ERR, "Create pool fail.");
        return ERROR;
    }

    ret64 = Res_AddSection(res_no, 0, 0, node_num);
    if (ret64 == G_FAILURE) {
        LOG(FASTPASS, ERR, "Add section fail.");
        return ERROR;
    }

    head->res_no      = res_no;
    head->entry_max   = node_num;
    head->bucket_mask = FP_DNS_BUCKET_NUM - 1;

    fp_dns_pool_head = head;

    size = fp_dns_cdb_init(node_num);
    if (size < 0) {
        LOG(FASTPASS, ERR, "DNS credible table init failed.");
        return ERROR;
    }

    return total_mem;
}

void fp_dns_deinit(void)
{
    if (fp_dns_pool_head) {
        Res_DestroyPool(fp_dns_pool_head->res_no);
        FP_SHM_FREE(GLB_MAC_TABLE_SYMBOL, fp_dns_pool_head);
        fp_dns_pool_head = NULL;
    }

    if (fp_dns_cdb_pool_head) {
        Res_DestroyPool(fp_dns_cdb_pool_head->pool_id);
        FP_SHM_FREE(GLB_MAC_TABLE_SYMBOL, fp_dns_cdb_pool_head);
        fp_dns_cdb_pool_head = NULL;
    }
}

static inline fp_dns_cache_node *fp_dns_buff_alloc()
{
    uint32_t key = 0, index;
    fp_dns_table *head = fp_dns_table_get();
    if (unlikely(NULL == head)) {
        return NULL;
    }
    if (G_FAILURE == Res_Alloc(head->res_no, &key, &index, EN_RES_ALLOC_MODE_OC)) {
        return NULL;
    }

    return fp_dns_node_get(index);
}

static inline void fp_dns_buff_free(fp_dns_cache_node *node)
{
    fp_dns_table        *head;

    if (!node) {
        return;
    }

    head = fp_dns_table_get();
    if (unlikely(NULL == head)) {
        return;
    }

    Res_Free(head->res_no, 0, node->index);

    return;
}

/*
 change name between ascii name and dns name,
 dir = 0 : ascii->dns, for example, "www.abc.com"  => "3www3abc3com"
 dir = 1 : dns->ascii, for example, "3www3abc3com" => "www.abc.com"
 */
static char *fp_dns_chngname(char *oldname, char *newname, uint32_t dir)
{
    uint32_t len;
    uint8_t i;
    char cc;
    char *ptr = oldname, *newptr = newname;
    char *locator;

    if ((oldname == NULL) || (newname == NULL) || (dir > 1)) {
        return NULL;
    }

    len = strlen(oldname);
    if (len == 0) {
        return NULL;
    }

    if (dir){
        if (len >= COMM_MSG_DNS_NAME_LENG){
            LOG(FASTPASS, RUNNING,
                "DNS response name %s overflows (%d>=%d)",
                oldname, len, COMM_MSG_DNS_NAME_LENG);
            return NULL;
        }

        (void)ros_memcpy(newptr, ptr + 1, len);
        *(newptr + len) = 0;

        locator = newptr;
        while ((cc = *ptr) != 0) {
            if (cc > 63){  /*dns defines*/
                *locator = 0; /*we don't support compressive mode in uncompressive string*/
                break;
            }

            ptr += cc+1;
            if (*ptr) /*if not reach the end of string, replace number with .*/
                *(locator + cc) = '.';
            locator += cc+1;
        }
    }
    else {
        if (len >= COMM_MSG_DNS_NAME_LENG){
            LOG(FASTPASS, RUNNING,
                "DNS request name %s overflows (%d>=%d)",
                oldname, len, COMM_MSG_DNS_NAME_LENG);
            return NULL;
        }
        (void)ros_memcpy(newptr + 1, ptr, len);
        *(newptr+1+len) = 0;

        locator = newptr;
        while (*ptr){
            for (i=0; *ptr && *ptr != '.'; i++, ptr++)
                ;
            *locator = (char)i;
            if (*ptr == 0)
                break;
            locator += i+1; /*move to next location for '.'*/
            ptr += 1; /*skip '.'*/
        }
    }

    return newptr;
}

/*get hash key value by domain name*/
static int32_t fp_dns_hashkey (char *name, uint16_t *hash_key, uint16_t *aux_info)
{
    uint32_t namelen, wordlen;
    uint8_t  key, aux;
    uint32_t i;
    uint16_t tmp;

    /* check if it is null */
    if (name == NULL) {
        *hash_key = 0;
        *aux_info = 0;
        return ERROR;
    }

    /* get length */
    namelen = strlen (name);
    if (namelen == 0) {
        *hash_key = 0;
        *aux_info = 0;
        return ERROR;
    }
    wordlen = (namelen & 0xFFFE);

    /* get hash key */
    key = 0;
    aux = 0;
    for (i = 0; i < wordlen; i += sizeof(uint16_t)) {

        tmp = *(uint16_t *)&name[i];

        aux ^= tmp;
        key ^= hash16_by_short(0, tmp);
    }

    /* if has odd byte */
    if (wordlen != namelen) {
        tmp = name[namelen - 1];

        aux ^= tmp;
        key ^= hash16_by_short(0, tmp);
    }

    *hash_key = key;
    *aux_info = aux;

    return OK;
}

static int fp_dns_key_compare(struct rb_node *node, void *key)
{
    fp_dns_cache_node *entry = (fp_dns_cache_node *)node;
    uint16_t aux_info = *(uint16_t *)key;

    if (entry->aux_info < aux_info) {
        return 1;
    } else if (entry->aux_info > aux_info) {
        return -1;
    } else {
        return 0;
    }
}

static fp_dns_cache_node *fp_dns_table_match(uint16_t hash_key, uint16_t aux_info)
{
    fp_dns_bucket           *bucket;
    fp_dns_cache_node       *node;

    bucket = fp_dns_bucket_get(hash_key);
    if (unlikely(NULL == bucket)) {
        LOG(FASTPASS, ERR, "dns bucket invalid.");
        return NULL;
    }

    LOG(FASTPASS, RUNNING, "search hash value 0x%04x, bucket %p, aux_info %04x.",
        hash_key, bucket, aux_info);

    ros_rwlock_read_lock(&bucket->rwlock);
    node = (fp_dns_cache_node *)rbtree_search(&bucket->dns_root, &aux_info, fp_dns_key_compare);
    ros_rwlock_read_unlock(&bucket->rwlock);
    if (NULL == node) {
        LOG(FASTPASS, RUNNING, "no matched entry found.");
        return NULL;
    }

    return node;
}

static fp_dns_cache_node *fp_dns_table_insert(fp_dns_cache_node *entry,
    uint16_t hash_key, uint16_t aux_info)
{
    fp_dns_table        *table = fp_dns_table_get();
    fp_dns_cache_node   *entry_tmp;
    fp_dns_bucket       *bucket;

    LOG(FASTPASS, RUNNING,
        "add dns node %d to hash %04x tree!", entry->index, hash_key);
    if (unlikely(NULL == table)) {
        return NULL;
    }

    bucket = fp_dns_bucket_get(hash_key);
    if (unlikely(NULL == bucket)) {
        LOG(FASTPASS, ERR, "dns bucket invalid.");
        return NULL;
    }

    LOG(FASTPASS, RUNNING, "add hash value %04x, bucket %p, aux_info %04x.",
        (hash_key & table->bucket_mask), bucket, aux_info);

    ros_rwlock_write_lock(&bucket->rwlock); /* lock */

    /* Check if item exist in table */
    entry_tmp = (fp_dns_cache_node *)rbtree_search(&bucket->dns_root, &aux_info, fp_dns_key_compare);
    if (entry_tmp) {
        ros_rwlock_write_unlock(&bucket->rwlock); /* unlock */
        return NULL;
    }
    entry->aux_info = aux_info;

    if (0 > rbtree_insert(&bucket->dns_root, &entry->dns_node, &aux_info, fp_dns_key_compare)){
        LOG(FASTPASS, ERR, "Insert dns cache fail.");
        ros_rwlock_write_unlock(&bucket->rwlock); /* unlock */
        return NULL;
    }
    ros_rwlock_write_unlock(&bucket->rwlock); /* unlock */

    return entry;
}

uint32_t fp_dns_table_del(uint32_t index)
{
    fp_dns_table            *table = fp_dns_table_get();
    fp_dns_cache_node       *entry;
    fp_dns_bucket           *bucket;
    uint16_t                auxinfo, hashkey;

    LOG(FASTPASS, RUNNING, "index %d!", index);
    if (unlikely(NULL == table)) {
        return ERROR;
    }

    entry = fp_dns_node_get(index);

    /* calculate hash key according name */
    fp_dns_hashkey(entry->dns_cfg.name, &hashkey, &auxinfo);

    bucket = fp_dns_bucket_get(hashkey);
    if (unlikely(NULL == bucket)) {
        LOG(FASTPASS, ERR, "dns bucket invalid.");
        return ERROR;
    }

    LOG(FASTPASS, RUNNING, "tree %p, bucket %p, aux_info %04x.",
        bucket->dns_root.rb_node, bucket, auxinfo);

    ros_rwlock_write_lock(&bucket->rwlock);
    rbtree_erase(&entry->dns_node, &bucket->dns_root);
    ros_rwlock_write_unlock(&bucket->rwlock);

    Res_Free(table->res_no, 0, index);

    return OK;
}

int32_t fp_dns_handle_query(uint8_t *dns_pl, uint32_t dns_len)
{
    fp_dns_header           *dns_h = (fp_dns_header *)dns_pl;
    fp_dns_cache_node       *cache;
    uint32_t                namelen, leftlen = dns_len;
    uint16_t                offset = 0;
    char                    *pdata, *dnsname, newname[COMM_MSG_DNS_NAME_LENG];
    uint16_t                hashkey, auxinfo;
    fp_dns_rr               *rr;
    uint16_t                q_type, q_class, cnt;
    fp_dns_rr_name_point    *rr_np;
    fp_dns_flags            dns_flg = {.d.ra = 1, .d.qr = 1};
    //uint32_t                cur_time = ros_getime();

    LOG(FASTPASS, RUNNING, "receive dns query, payload length: %u", dns_len);

    /* check length */
    if (dns_len <= sizeof(fp_dns_header)) {
        LOG(FASTPASS, ERR, "error: DNS header length.");
        return ERROR;
    }

    /* offset 12 */
    leftlen -= sizeof(fp_dns_header);

    /* get domain name first */
    dnsname = (char*)(dns_pl + sizeof(fp_dns_header));
    namelen = strlen (dnsname);
    if (namelen + 4 >= leftlen) {
        LOG(FASTPASS, ERR, "error: DNS name length.");
        return ERROR;
    }

    q_type = ntohs(*(uint16_t *)(dnsname + namelen + 1));
    q_class = ntohs(*(uint16_t *)(dnsname + namelen + 3));
    if (q_class != FP_DNS_CLASS_IN) {
        LOG(FASTPASS, ERR, "error: DNS class: %d.", q_class);
        return ERROR;
    }

    /* replace length by '.' */
    if (NULL == fp_dns_chngname(dnsname, newname, 1)) {
        LOG(FASTPASS, ERR, "DNS change name failed.");
        return ERROR;
    }

    /* calculate hash key according name */
    fp_dns_hashkey(newname, &hashkey, &auxinfo);

    /* get dns cache by name */
    cache = fp_dns_table_match(hashkey, auxinfo);
    if (cache == NULL) {
        LOG(FASTPASS, DEBUG, "DNS match %s failed.", newname);
        return ERROR;
    }
    pdata  = (char *)dns_pl;

    /* found */
    dns_h->flags.value |= htons(dns_flg.value);

    offset = dns_len;

    switch (q_type) {
        case FP_DNS_TYPE_A:
            {
                dns_h->answ = 0;
                for (cnt = 0; cnt < cache->dns_cfg.ipaddr_num; ++cnt) {
                    /* set rr */
                    if (cache->dns_cfg.ipaddr[cnt].ip_ver == EN_DNS_IPV4) {
                        rr_np = (fp_dns_rr_name_point *)(pdata + offset);
                        rr = (fp_dns_rr *)(rr_np + 1);
                        rr_np->value    = htons(0xc00c);
                        rr->dnstype     = htons(FP_DNS_TYPE_A);
                        rr->dnsclass    = htons(FP_DNS_CLASS_IN);
                        rr->ttl         = htonl(FP_DNS_ANS_TTL);
                        //rr->ttl         = htonl(cache->dns_cfg.expire > cur_time ? cache->dns_cfg.expire - cur_time : 0);
                        rr->length      = htons(4);
                        *(uint32_t *)rr->rrdata = htonl(cache->dns_cfg.ipaddr[cnt].ip.ipv4);

                        offset += sizeof(fp_dns_rr_name_point) + sizeof(fp_dns_rr) + 4;
                        ++dns_h->answ;
                    }
                }
                dns_h->answ  = htons(dns_h->answ);
            }
            break;

        case FP_DNS_TYPE_AAAA:
            {
                dns_h->answ = 0;
                for (cnt = 0; cnt < cache->dns_cfg.ipaddr_num; ++cnt) {
                    /* set rr */
                    if (cache->dns_cfg.ipaddr[cnt].ip_ver == EN_DNS_IPV6) {
                        rr_np = (fp_dns_rr_name_point *)(pdata + offset);
                        rr = (fp_dns_rr *)(rr_np + 1);
                        rr_np->value    = htons(0xc00c);
                        rr->dnstype     = htons(FP_DNS_TYPE_AAAA);
                        rr->dnsclass    = htons(FP_DNS_CLASS_IN);
                        rr->ttl         = htonl(FP_DNS_ANS_TTL);
                        //rr->ttl         = htonl(cache->dns_cfg.expire > cur_time ? cache->dns_cfg.expire - cur_time : 0);
                        rr->length      = htons(IPV6_ALEN);
                        ros_memcpy(rr->rrdata, cache->dns_cfg.ipaddr[cnt].ip.ipv6, IPV6_ALEN);

                        offset += sizeof(fp_dns_rr_name_point) + sizeof(fp_dns_rr) + IPV6_ALEN;
                        ++dns_h->answ;
                    }
                }
                dns_h->answ  = htons(dns_h->answ);
            }
            break;

        default:
            LOG(FASTPASS, ERR, "Unsupport DNS queries type: %d.", q_type);
            return ERROR;
    }

    LOG(FASTPASS, RUNNING, "done, new len %u", offset);

    return offset;
}

int32_t fp_dns_handle_response(uint8_t *dns_pl, uint32_t dns_len)
{
    fp_dns_header           *dns_h = (fp_dns_header *)dns_pl;
    fp_dns_cache_node       *cache;
    uint32_t                namelen, qstnlen, rrlen, leftlen = dns_len;
    uint16_t                ancount = 0;
    char                    *pdata, *dnsname, newname[COMM_MSG_DNS_NAME_LENG];
    uint16_t                hashkey, auxinfo;
    uint32_t                newflag = 0;
    uint16_t                q_type, q_class, offset;
    fp_dns_rr_name_point    ans_p;
    comm_msg_dns_ip         *dns_ip;

    LOG(FASTPASS, RUNNING, "receive dns response, payload length: %u", dns_len);
    /* check length */
    if (dns_len <= sizeof(fp_dns_header)) {
        LOG(FASTPASS, ERR, "DNS header length error.");
        return ERROR;
    }

    /* offset 12 */
    leftlen -= sizeof(fp_dns_header);

    /* get domain name first */
    dnsname = (char*)(dns_pl + sizeof(fp_dns_header));
    namelen = strlen (dnsname);
    if (namelen + 4 >= leftlen) {
        LOG(FASTPASS, RUNNING, "DNS name length error.");
        return ERROR;
    }

    /* replace length by '.' */
    if (NULL == fp_dns_chngname (dnsname, newname, 1)) {
        LOG(FASTPASS, ERR, "DNS change name failed.");
        return ERROR;
    }

    /* calculate hash key according name */
    fp_dns_hashkey(newname, &hashkey, &auxinfo);

    /* get dns cache by name */
    cache = fp_dns_table_match(hashkey, auxinfo);
    if (cache == NULL) {
        cache = fp_dns_buff_alloc();
        if (cache == NULL) {
            LOG(FASTPASS, ERR, "Alloc dns buff failed.");
            return ERROR;
        }
        newflag = 1;
    }
    cache->dns_cfg.ipaddr_num = 0;
    strncpy(cache->dns_cfg.name, newname, namelen);
    cache->dns_cfg.name[namelen] = '\0';

    /*
    |----------------------------------------|
    |QR1|opcode4|AA1|TC1|RD1|RA1|zero3|rcode4|
    |----------------------------------------|
    */
    if (dns_h->flags.d.ra == 0) {
        LOG(FASTPASS, DEBUG, "error: dns.ra: 0.");
        goto err_para;
    }

    /* has error */
    if ((dns_h->flags.value & 0xf00) != 0){
        LOG(FASTPASS, DEBUG, "error: dns_h->flags:%d.", dns_h->flags.value);
        goto err_para;
    }

    /* analyze the response, we just support 1 */
    if (ntohs(dns_h->ques) != 1) {
        LOG(FASTPASS, DEBUG, "error: dns_h->ques: %d.", ntohs(dns_h->ques));
        goto err_para;
    }

    /* since rcode=0, then must have an answer */
    if (dns_h->answ == 0) {
        LOG(FASTPASS, DEBUG, "error: dns_h->answ: %d.", dns_h->answ);
        goto err_para;
    }

    /* header + name + type(2) + class(2) + RR(>12) */
    q_type = ntohs(*(uint16_t *)(dnsname + namelen + 1));
    q_class = ntohs(*(uint16_t *)(dnsname + namelen + 3));
    if (q_class != FP_DNS_CLASS_IN) {
        LOG(FASTPASS, DEBUG, "error: q_class: %d.", q_class);
        goto err_para;
    }

    qstnlen = namelen + 1 + 4;
    if (qstnlen + 12 > leftlen) {
        LOG(FASTPASS, DEBUG, "error: The length is not enough.");
        goto err_para;
    }

    leftlen -= qstnlen;
    pdata = (char *)(dns_pl + sizeof(fp_dns_header) + qstnlen);
    offset = 0;

    /* pointer to RR */
    /* check other field of question part, loosely or strictly */
    while (leftlen){
        fp_dns_rr *dnsrrp, stRR;

        /*maybe additional records have ipaddr, we just honor answer part*/
        if (++ancount > ntohs(dns_h->answ))
            break;

        /* compressive name + rr_data_offsize */
        if (leftlen < 12) {
            LOG(FASTPASS, DEBUG, "error: The length is not enough.");
            goto err_para;
        }

        ans_p.value = ntohs(*(uint16_t *)pdata);
        dnsname = (char *)pdata;
        if (ans_p.d.h == 0x3){ /*compressive mode*/
            dnsrrp = (fp_dns_rr *)(dnsname + sizeof(ans_p));
            leftlen -= sizeof(ans_p) + FP_DNS_RR_DATA_OFFSIZE;
            offset += sizeof(ans_p) + FP_DNS_RR_DATA_OFFSIZE;
        }
        else {
            rrlen = strlen(dnsname) + 1 + FP_DNS_RR_DATA_OFFSIZE;
            if (rrlen > leftlen) {
                LOG(FASTPASS, DEBUG, "error: The length is not enough.");
                goto err_para;
            }

            dnsrrp = (fp_dns_rr *)(dnsname + strlen(dnsname) + 1);
            leftlen -= rrlen;
            offset += rrlen;
        }

        /*!!!to avoid byte alignment problem!!!*/
        ros_memcpy(&stRR, dnsrrp, FP_DNS_RR_DATA_OFFSIZE);

        /* get length */
        stRR.length = ntohs(stRR.length);
        stRR.dnstype = ntohs(stRR.dnstype);
        if (0 == stRR.length) {
            LOG(FASTPASS, DEBUG, "error: DNS RR length abnormal: %d.", stRR.length);
            goto err_para;
        }

        if (leftlen < stRR.length) {
            LOG(FASTPASS, DEBUG, "error: DNS RR length abnormal: %d.", stRR.length);
            goto err_para;
        }

        /* for next RR */
        leftlen -= stRR.length;
        pdata = (char *)dnsrrp + FP_DNS_RR_DATA_OFFSIZE + stRR.length;

        if (stRR.dnstype != q_type) {
            /* Skip unnecessary values */
            continue;
        }

        switch (stRR.dnstype) {
            case FP_DNS_TYPE_A:
                /* ip address: 4, 8... */
                if (stRR.length & 3) {
                    LOG(FASTPASS, ERR, "error: DNS RR length abnormal: %d.", stRR.length);
                    goto err_para;
                }

                /* we can only keep more ip address */
                if (cache->dns_cfg.ipaddr_num >= COMM_MSG_DNS_IP_NUM)
                    break;

                dns_ip = &cache->dns_cfg.ipaddr[cache->dns_cfg.ipaddr_num];
                /*get ip address*/
                dns_ip->ip_ver = EN_DNS_IPV4;
                dns_ip->ip.ipv4 = ntohl(*(uint32_t *)dnsrrp->rrdata);
                LOG(FASTPASS, RUNNING, "get IP[%d]: 0x%08x", cache->dns_cfg.ipaddr_num,
                    dns_ip->ip.ipv4);
                ++cache->dns_cfg.ipaddr_num;

                cache->dns_cfg.expire = ros_getime() + ntohl(stRR.ttl);
                break;

            case FP_DNS_TYPE_CNAME:
                break;

            case FP_DNS_TYPE_AAAA:
                /* ipv6 address: 16, 32... */
                if (stRR.length & 0xf) {
                    LOG(FASTPASS, ERR, "error: DNS RR length abnormal: %d.", stRR.length);
                    goto err_para;
                }

                /* we can only keep more ip address */
                if (cache->dns_cfg.ipaddr_num >= COMM_MSG_DNS_IP_NUM)
                    break;

                dns_ip = &cache->dns_cfg.ipaddr[cache->dns_cfg.ipaddr_num];
                /*get ip address*/
                dns_ip->ip_ver = EN_DNS_IPV6;
                ros_memcpy(dns_ip->ip.ipv6, dnsrrp->rrdata, IPV6_ALEN);
                LOG(FASTPASS, RUNNING, "get IP[%d]: 0x%08x %08x %08x %08x", cache->dns_cfg.ipaddr_num,
                    *(uint32_t *)&dns_ip->ip.ipv6[0], *(uint32_t *)&dns_ip->ip.ipv6[4],
                    *(uint32_t *)&dns_ip->ip.ipv6[8], *(uint32_t *)&dns_ip->ip.ipv6[12]);
                ++cache->dns_cfg.ipaddr_num;

                cache->dns_cfg.expire = ros_getime() + ntohl(stRR.ttl);
                break;

            default:
                LOG(FASTPASS, RUNNING, "Unsupport dns answers type: %d.", stRR.dnstype);
                break;
        }
    }

    if (cache->dns_cfg.ipaddr_num == 0){ /*No ip address information*/
        LOG(FASTPASS, RUNNING, "error: Get DNS answer ip address: %d.", cache->dns_cfg.ipaddr_num);
        goto err_para;
    }

    if (newflag) {
        if (NULL == fp_dns_table_insert(cache, hashkey, auxinfo)) {
            LOG(FASTPASS, ERR, "Insert dns cache node failed.");
            goto err_para;
        }
    }

    if (EN_COMM_ERRNO_OK != fp_dns_update2sp(&cache->index, 1)) {
        LOG(FASTPASS, ERR, "Update dns cache to spu failed.");
    }

    return OK;

err_para:

    LOG(FASTPASS, DEBUG, "Handle dns response fail.");
    if (newflag) {
        fp_dns_buff_free(cache);
    }

    return ERROR;
}

void fp_dns_config_hton(comm_msg_dns_config *cfg)
{
    uint16_t cnt;

    if (cfg->ipaddr_num > COMM_MSG_DNS_IP_NUM) {
        /* 防止非法调用引起内存越界 */
        LOG(FASTPASS, ERR, "ERROR: Illegal function call.");
        return;
    }
    for (cnt = 0; cnt < cfg->ipaddr_num; ++cnt) {
        if (EN_DNS_IPV4 == cfg->ipaddr[cnt].ip_ver) {
            cfg->ipaddr[cnt].ip.ipv4 = htonl(cfg->ipaddr[cnt].ip.ipv4);
        }
    }
    cfg->expire     = htonl(cfg->expire);
    cfg->ipaddr_num = htons(cfg->ipaddr_num);
}

/* 只能网络序转主机序才能调用，否则会引起不必要的循环异常 */
static inline void fp_dns_config_ntoh(comm_msg_dns_config *cfg)
{
    uint16_t cnt;

    cfg->expire     = ntohl(cfg->expire);
    cfg->ipaddr_num = ntohs(cfg->ipaddr_num);
    if (cfg->ipaddr_num > COMM_MSG_DNS_IP_NUM) {
        /* 防止非法调用引起内存越界 */
        LOG(FASTPASS, ERR, "ERROR: Illegal function call.");
        return;
    }
    for (cnt = 0; cnt < cfg->ipaddr_num; ++cnt) {
        if (EN_DNS_IPV4 == cfg->ipaddr[cnt].ip_ver) {
            cfg->ipaddr[cnt].ip.ipv4 = ntohl(cfg->ipaddr[cnt].ip.ipv4);
        }
    }
}

uint32_t fp_dns_update2sp(uint32_t *index_arr, uint32_t index_num)
{
    uint8_t                     buf[SERVICE_BUF_TOTAL_LEN];
    uint32_t                    buf_len = 0;
    comm_msg_header_t           *msg;
    comm_msg_rules_ie_t         *ie = NULL;
    fp_dns_cache_node           *entry = NULL;
    uint32_t                    cnt = 0, data_cnt = 0;
    comm_msg_dns_ie_data        *ie_data = NULL;
    uint32_t max_rules = (SERVICE_BUF_TOTAL_LEN - COMM_MSG_HEADER_LEN - COMM_MSG_IE_LEN_COMMON) / sizeof(comm_msg_dns_ie_data);

    if (NULL == index_arr || 0 == index_num) {
        LOG(FASTPASS, ERR, "parameter abnormal, index_arr(%p), index number: %u.", index_arr, index_num);
        return EN_COMM_ERRNO_PARAM_INVALID;
    }

    msg = fp_fill_msg_header(buf);
    ie = COMM_MSG_GET_RULES_IE(msg);
    ie->cmd = htons(EN_COMM_MSG_UPU_DNS_ADD);
    ie_data = (comm_msg_dns_ie_data *)ie->data;

    for (cnt = 0; cnt < index_num; ++cnt) {
        entry = fp_dns_node_get(index_arr[cnt]);
        if (NULL == entry) {
            LOG(FASTPASS, ERR, "Entry index error, index: %u.", index_arr[cnt]);
            continue;
        }

        ie_data[data_cnt].index = htonl(entry->index);
        ros_memcpy(&ie_data[data_cnt].cfg, &entry->dns_cfg, sizeof(comm_msg_dns_config));
        fp_dns_config_hton(&ie_data[data_cnt].cfg);
        ++data_cnt;

        if (data_cnt >= max_rules) {
            buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_dns_ie_data) * data_cnt;
            ie->rules_num = htonl(data_cnt);
            ie->len = htons(buf_len);
            buf_len += COMM_MSG_HEADER_LEN;
            msg->total_len = htonl(buf_len);
            if (0 > fp_msg_send((char *)buf, buf_len)) {
                LOG(FASTPASS, ERR, "Send msg to MB failed.");
                return EN_COMM_ERRNO_SEND_MSG_ERROR;
            }
            data_cnt = 0;
        }
    }

    if (data_cnt > 0) {
        buf_len = COMM_MSG_IE_LEN_COMMON + sizeof(comm_msg_dns_ie_data) * data_cnt;
        ie->rules_num = htonl(data_cnt);
        ie->len = htons(buf_len);
        buf_len += COMM_MSG_HEADER_LEN;
        msg->total_len = htonl(buf_len);
        if (0 > fp_msg_send((char *)buf, buf_len)) {
            LOG(FASTPASS, ERR, "Send msg to MB failed.");
            return EN_COMM_ERRNO_SEND_MSG_ERROR;
        }
        data_cnt = 0;
    }

    return EN_COMM_ERRNO_OK;
}

/***********************DNS credible list***********************/

static inline fp_dns_credible_table *fp_dns_cdb_table_get()
{
    return fp_dns_cdb_pool_head;
}

static inline fp_dns_credible_entry *fp_dns_cdb_entry_get(uint32_t index)
{
    if (likely(fp_dns_cdb_pool_head)) {
        return &fp_dns_cdb_pool_head->entry[index];
    } else {
        return NULL;
    }
}

static int64_t fp_dns_cdb_init(uint32_t node_num)
{
    int32_t             res_no = 0;
    uint8_t             *tmp = NULL;
    int64_t             total_mem = 0, size = 0;
    uint64_t            ret64;
    int32_t             loop;

    size = node_num * sizeof(fp_dns_credible_entry) + sizeof(fp_dns_credible_table);
    total_mem += size;
    tmp = (uint8_t *)BUFFER_SHM_MALLOC(GLB_DNS_POOL_SYMBOL, size, CACHE_LINE_SIZE);
    if (!tmp) {
        LOG(FASTPASS, ERR, "Malloc fail.");
        return ERROR;
    }

    fp_dns_cdb_pool_head = (fp_dns_credible_table *)tmp;
    fp_dns_cdb_pool_head->entry = (fp_dns_credible_entry *)((char *)tmp + sizeof(fp_dns_credible_table));
    for (loop = 0; loop < node_num; loop++) {
        fp_dns_cdb_pool_head->entry[loop].index = loop;
    }

    res_no = Res_CreatePool();
    if (res_no < 0) {
        LOG(FASTPASS, ERR, "Create pool fail.");
        return ERROR;
    }

    ret64 = Res_AddSection(res_no, 0, 0, node_num);
    if (ret64 == G_FAILURE) {
        LOG(FASTPASS, ERR, "Add section fail.");
        return ERROR;
    }

    fp_dns_cdb_pool_head->pool_id   = (uint16_t)res_no;
    fp_dns_cdb_pool_head->max_num   = node_num;
    fp_dns_cdb_pool_head->cdb_root  = RB_ROOT_INIT_VALUE;
    ros_rwlock_init(&fp_dns_cdb_pool_head->lock);
    fp_dns_cdb_pool_head->master_switch = 0; /* All are not trusted by default */

    return total_mem;
}

static int fp_dns_credible_key_compare(struct rb_node *node, void *key)
{
    fp_dns_credible_entry *entry = (fp_dns_credible_entry *)node;

    return ros_memcmp(&entry->ipaddr, key, sizeof(comm_msg_dns_ip));
}

int fp_dns_credible_master_switch(void)
{
    fp_dns_credible_table *table = fp_dns_cdb_table_get();

    if (0 == fp_start_is_run() || NULL == table) {
        return 0;
    }

    return table->master_switch;
}

int fp_dns_credible_match(comm_msg_dns_ip *ipaddr)
{
    fp_dns_credible_entry  *entry = NULL;
    fp_dns_credible_table  *table = fp_dns_cdb_table_get();

    if (0 == fp_start_is_run() || NULL == table) {
        return -1;
    }
    if (NULL == ipaddr) {
        LOG(SESSION, ERR, "Abnormal parameter, ipaddr(%p).", ipaddr);
        return -1;
    }

    LOG(SESSION, RUNNING, "Search DNS credible.");
    ros_rwlock_write_lock(&table->lock); /* lock */
    entry = (fp_dns_credible_entry *)rbtree_search(&table->cdb_root,
        ipaddr, fp_dns_credible_key_compare);
    ros_rwlock_write_unlock(&table->lock); /* unlock */

    return entry == NULL ? -1 : 0;
}

int fp_dns_credible_cmd(struct cli_def *cli, int argc, char **argv)
{
    fp_dns_credible_table *table = fp_dns_cdb_table_get();
    char ip_str[512];

    if (argc < 1 || 0 == strncmp(argv[0], "help", 4) || 0 == strncmp(argv[0], "hlep", 4)) {
        goto hlep;
    }

    if (!fp_start_is_run()) {
        cli_print(cli, "FPU not working.\r\n");
        return 0;
    }
    if (NULL == table) {
        cli_print(cli, "FPU buys, try again.\r\n");
        return 0;
    }

    if (argc > 0 && 0 == strncmp(argv[0], "show", 4)) {
        fp_dns_credible_entry *entry = NULL;
        uint32_t cnt = 0, tmp_addr;

        cli_print(cli, "DNS credible master switch: %s",
            table->master_switch ? "enabled" : "disabled");
        cli_print(cli, "--------------DNS sniffer enabled list--------------");
        entry = (fp_dns_credible_entry *)rbtree_first(&table->cdb_root);
        while (entry) {
            if (entry->ipaddr.ip_ver == EN_DNS_IPV4) {
                tmp_addr = entry->ipaddr.ip.ipv4;
                if (NULL == inet_ntop(AF_INET, &tmp_addr, ip_str, sizeof(ip_str))) {
                    LOG(STUB, ERR, "inet_ntop failed, error: %s.", strerror(errno));
                    continue;
                }
                cli_print(cli, "IP[%u]: %s", ++cnt, ip_str);
            } else {
                if (NULL == inet_ntop(AF_INET6, entry->ipaddr.ip.ipv6, ip_str, sizeof(ip_str))) {
                    LOG(STUB, ERR, "inet_ntop failed, error: %s.", strerror(errno));
                    continue;
                }
                cli_print(cli, "IP[%u]: %s", ++cnt, ip_str);
            }

            entry = (fp_dns_credible_entry *)rbtree_next(&entry->cdb_node);
        }
    } else if (argc > 1 && 0 == strncmp(argv[0], "add", 3)) {
        comm_msg_dns_ip ipaddr = {0};
        uint32_t key, index;
        fp_dns_credible_entry *entry;

        if (strchr(argv[1], ':')) {
            if (1 != inet_pton(AF_INET6, argv[1], ipaddr.ip.ipv6)) {
                LOG(COMM, ERR, "inet_ntop failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            ipaddr.ip_ver = EN_DNS_IPV6;
        } else {
            if (1 != inet_pton(AF_INET, argv[1], &ipaddr.ip.ipv4)) {
                LOG(COMM, ERR, "inet_ntop failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            ipaddr.ip_ver = EN_DNS_IPV4;
        }

        /* Check repeat */
        ros_rwlock_write_lock(&table->lock); /* lock */
        if (NULL != rbtree_search(&table->cdb_root,
            &ipaddr, fp_dns_credible_key_compare)) {
            ros_rwlock_write_unlock(&table->lock); /* unlock */
            cli_print(cli, "Add dns credible entry failed, The IP already exists.");
            return -1;
        }
        ros_rwlock_write_unlock(&table->lock); /* unlock */

        /* Alloc resource */
        if (G_FAILURE == Res_Alloc(table->pool_id, &key, &index, EN_RES_ALLOC_MODE_OC)) {
            cli_print(cli, "Add dns credible entry failed, Insufficient resources.");
            return -1;
        }
        entry = fp_dns_cdb_entry_get(index);
        if (NULL == entry) {
            Res_Free(table->pool_id, key, index);
            cli_print(cli, "Add dns credible entry failed, system abnormal");
            return -1;
        }

        /* copy info */
        ros_memcpy(&entry->ipaddr, &ipaddr, sizeof(ipaddr));

        ros_rwlock_write_lock(&table->lock);/* lock */
        if (0 > rbtree_insert(&table->cdb_root, &entry->cdb_node,
            &entry->ipaddr, fp_dns_credible_key_compare)) {
            ros_rwlock_write_unlock(&table->lock);/* unlock */
            Res_Free(table->pool_id, key, index);
            cli_print(cli, "Add dns credible entry failed, insert dns credible to root failed.");
            return -1;
        }
        ros_rwlock_write_unlock(&table->lock);/* unlock */

        cli_print(cli, "Add dns credible entry success.");
    } else if (argc > 1 && 0 == strncmp(argv[0], "del", 3)) {

        comm_msg_dns_ip ipaddr = {0};
        fp_dns_credible_entry *entry;

        if (strchr(argv[1], ':')) {
            if (1 != inet_pton(AF_INET6, argv[1], ipaddr.ip.ipv6)) {
                LOG(COMM, ERR, "inet_ntop failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            ipaddr.ip_ver = EN_DNS_IPV6;
        } else {
            if (1 != inet_pton(AF_INET, argv[1], &ipaddr.ip.ipv4)) {
                LOG(COMM, ERR, "inet_ntop failed, error: %s.",
                    strerror(errno));
                return -1;
            }
            ipaddr.ip_ver = EN_DNS_IPV4;
        }

        /* Check repeat */
        ros_rwlock_write_lock(&table->lock); /* lock */
        entry = (fp_dns_credible_entry *)rbtree_delete(&table->cdb_root,
            &ipaddr, fp_dns_credible_key_compare);
        ros_rwlock_write_unlock(&table->lock); /* unlock */
        if (NULL == entry) {
            cli_print(cli, "Delete dns credible entry failed, no such entry.");
            return -1;
        }
        Res_Free(table->pool_id, 0, entry->index);

        cli_print(cli, "Del dns credible entry success.");
    } else if (argc > 0 && 0 == strncmp(argv[0], "enable", 6)) {
        table->master_switch = 1;
    } else if (argc > 0 && 0 == strncmp(argv[0], "disable", 7)) {
        table->master_switch = 0;
    } else {
        goto hlep;
    }

    return 0;

hlep:

    cli_print(cli, "usage: dns_cdb <add|del|show|enable|disable> [IPv4|IPv6]");
    cli_print(cli, "  e.g. dns_cdb add 10.8.14.10");
    cli_print(cli, "  e.g. dns_cdb add 2002::1234:5678");
    cli_print(cli, "  e.g. dns_cdb show");
    cli_print(cli, "  e.g. dns_cdb enable");
    cli_print(cli, "  e.g. dns_cdb disable");
    cli_print(cli, "  \"enable\" Global enabled, all rules will enable DNS credible.");

    return -1;
}
/***********************DNS credible list end***********************/

int fp_dns_test(struct cli_def *cli, int argc, char **argv)
{
    if (argc < 1) {
        cli_print(cli, "dns_test <alloc> [number]");
        return -1;
    }

    if (!fp_start_is_run()) {
        cli_print(cli,"fpu not running.\r\n");
        return 0;
    }

    if (0 == strncmp(argv[0], "alloc", 5)) {
        uint32_t num = 100, cnt;
        fp_dns_cache_node *cache;

        if (argc >= 2) {
            num = atoi(argv[1]);
        }

        for (cnt = 0; cnt < num; ++cnt) {
            cache = fp_dns_buff_alloc();
            if (cache == NULL) {
                cli_print(cli, "Alloc dns buff failed, cur: %u.", cnt);
                return -1;
            }

            if (EN_COMM_ERRNO_OK != fp_dns_update2sp(&cache->index, 1)) {
                cli_print(cli, "Update dns cache to spu failed.");
            }
        }
    }

    return 0;
}

