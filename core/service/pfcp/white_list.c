/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "white_list.h"

struct white_list_table_head wl_head;

static struct white_list_table_head *white_list_header(void)
{
    return &wl_head;
}

static struct white_list_table *white_list_get_entry(uint32_t index)
{
    return &wl_head.wl_table[index];
}

int64_t white_list_table_init(uint32_t wl_num)
{
	uint32_t index = 0;
	int pool_id = -1;
	struct white_list_table *wl_tbl = NULL;
	uint32_t max_num = 0;
	int64_t size = 0;

	if (0 == wl_num) {
		LOG(SESSION, ERR,
			"Abnormal parameter, wl_num: %u.", wl_num);
		return -1;
	}

	max_num = wl_num;
	LOG(SESSION, RUNNING,
			"init wl_rule, sizeof(wl_rule): %lu  max_num: %u.",
			sizeof(struct white_list_table), max_num);
	size = sizeof(struct white_list_table) * max_num;
	wl_tbl = ros_malloc(size);
	if (NULL == wl_tbl) {
		LOG(SESSION, ERR,
			"init pf_rule failed, no enough memory, max number: %u =",max_num);
		return -1;
	}
	ros_memset(wl_tbl, 0, sizeof(struct white_list_table) * max_num);

	for (index = 0; index < max_num; ++index) {
		wl_tbl[index].index = index;
		wl_tbl[index].head_enrich_flag = 0xffffffff;
		ros_rwlock_init(&wl_tbl[index].lock);
	}

	pool_id = Res_CreatePool();
	if (pool_id < 0) {
        LOG(SESSION, ERR, "Create resource pool failed.");
		return -1;
	}
	if (G_FAILURE == Res_AddSection(pool_id, 0, 0, max_num)) {
        LOG(SESSION, ERR, "Create resource section failed.");
		return -1;
	}

	wl_head.pool_id = pool_id;
	wl_head.wl_table = wl_tbl;
	wl_head.max_num = max_num;
	ros_rwlock_init(&wl_head.lock);
	ros_atomic32_set(&wl_head.use_num, 0);


	LOG(SESSION, MUST, "white_list init success. max_num:%d",max_num);
	return size;
}

static int white_list_entry_compare_host(struct rb_node *node, void *key)
{
    struct white_list_table *entry = (struct white_list_table *)node;

    return strcmp(entry->host, (char *)key);
}

static int white_list_entry_compare_ip(struct rb_node *node, void *key)
{
    struct white_list_table *entry = (struct white_list_table *)node;
	uint32_t ip_addr = *(uint32_t *)key;

    if (ip_addr < entry->ip) {
        return -1;
    }
    else if (ip_addr > entry->ip) {
        return 1;
    }

    return 0;
}

int white_list_entry_insert(char *host,uint32_t ipaddr,uint8_t flag)
{
    uint32_t index = 0, res_key = 0;
    struct white_list_table *entry = NULL;
    struct white_list_table_head *wl_head = white_list_header();

    if (flag && NULL == host) {
        LOG(SESSION, ERR,"white_list_entry_insert failed, flag:%d host:%p,ipaddr:%x\r\n", flag,host,ipaddr);
        return -1;
    }
	else if(!flag && 0xffffffff == ipaddr) {
        LOG(SESSION, ERR,"white_list_entry_insert failed, flag:%d host:%p,ipaddr:%x\r\n", flag,host,ipaddr);
        return -1;
    }

	if(host)
		LOG(SESSION, RUNNING,"white_list_entry_insert,flag:%d host:%s,ipaddr:%x\r\n", flag,host,ipaddr);
	else
		LOG(SESSION, RUNNING,"white_list_entry_insert,flag:%d host:%p,ipaddr:%x\r\n", flag,host,ipaddr);


    if(flag)
	{
		ros_rwlock_write_lock(&wl_head->lock); /* lock */
		entry = (struct white_list_table *)rbtree_search(&wl_head->host_root,host,
			white_list_entry_compare_host);
		ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
    	if(entry != NULL)
		{
	        LOG(SESSION, ERR,"white_list_entry_insert, host(%s) already exists\r\n",host);
	        return 1;
	    }
		else
		{
	        if (G_FAILURE == Res_Alloc(wl_head->pool_id, &res_key, &index,
	            EN_RES_ALLOC_MODE_OC)) {
	            LOG(SESSION, ERR,"insert seid entry failed, Resource exhaustion, pool id: %d.\r\n",
	                wl_head->pool_id);
	            return -1;
	        }

	        entry = white_list_get_entry(index);
	        strcpy(entry->host, host);
			entry->flag = 1;
			entry->head_enrich_flag=0xffffffff;

	        ros_rwlock_write_lock(&wl_head->lock); /* lock */
	        /* insert seid tree */
	        if (0 > rbtree_insert(&wl_head->host_root, &entry->node, host,
	            white_list_entry_compare_host)) {
	            ros_rwlock_write_unlock(&wl_head->lock); /* unlock */

	            Res_Free(wl_head->pool_id, 0, entry->index);
	            LOG(SESSION, ERR,"white list entry insert failed, key: %s.\r\n",host);
	            return -1;
	        }
	        ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
	    }
	}
	else
	{
		ros_rwlock_write_lock(&wl_head->lock); /* lock */
		entry = (struct white_list_table *)rbtree_search(&wl_head->ip_root,&ipaddr,
			white_list_entry_compare_ip);
		ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
		if(entry != NULL)
		{
	        LOG(SESSION, ERR,"white_list_entry_insert, ipaddr(%x) already exists\r\n",ipaddr);
	        return 1;
	    }
		else
		{
	        if (G_FAILURE == Res_Alloc(wl_head->pool_id, &res_key, &index,
	            EN_RES_ALLOC_MODE_OC)) {
	            LOG(SESSION, ERR,"insert seid entry failed, Resource exhaustion, pool id: %d.\r\n",
	                wl_head->pool_id);
	            return -1;
	        }

	        entry = white_list_get_entry(index);
	        entry->ip=ipaddr;
			entry->head_enrich_flag=0xffffffff;

	        ros_rwlock_write_lock(&wl_head->lock); /* lock */
	        /* insert seid tree */
	        if (0 > rbtree_insert(&wl_head->ip_root, &entry->node, &ipaddr,
	            white_list_entry_compare_ip)) {
	            ros_rwlock_write_unlock(&wl_head->lock); /* unlock */

	            Res_Free(wl_head->pool_id, 0, entry->index);
	            LOG(SESSION, ERR,"white list entry insert failed, ipaddr: %x.\r\n",ipaddr);
	            return -1;
	        }
	        ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
	    }
	}

	if(host)
		LOG(SESSION, RUNNING,"insert success, host:%s\r\n",host);
	else
		LOG(SESSION, RUNNING,"insert success, ipaddr:%x\r\n",ipaddr);
    return 0;
}

int white_list_entry_remove(char *host,uint32_t ipaddr,uint8_t flag)
{
    struct white_list_table *entry = NULL;
    struct white_list_table_head *wl_head = white_list_header();

    ros_rwlock_write_lock(&wl_head->lock); /* lock */
	if(flag)
	{
		if(NULL == host)
		{
	        ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
	        LOG(SESSION, ERR,"wl entry remove failed, host(%p) is NULL\r\n",host);
	        return -1;
	    }
    	if(NULL == (entry = (struct white_list_table *)rbtree_delete(&wl_head->host_root,host,
			white_list_entry_compare_host)))
		{
	        ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
	        LOG(SESSION, ERR,"wl entry remove failed, host id: %s.\r\n",host);
	        return -1;
	    }
	}
	else
	{
		if(NULL == (entry = (struct white_list_table *)rbtree_delete(&wl_head->ip_root,&ipaddr,
			white_list_entry_compare_ip)))
		{
	        ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
	        LOG(SESSION, ERR,"wl entry remove failed, ipaddr: %x.\r\n",ipaddr);
	        return -1;
	    }
	}

    Res_Free(wl_head->pool_id, 0, entry->index);
    ros_rwlock_write_unlock(&wl_head->lock); /* unlock */

	LOG(SESSION, RUNNING,"remove success\r\n");
    return 0;
}

void white_list_entry_clean_all(void)
{
	struct white_list_table *entry = NULL;
    struct white_list_table_head *wl_head = white_list_header();
    int32_t cur_index = -1;

    cur_index = Res_GetAvailableInBand(wl_head->pool_id, cur_index + 1, wl_head->max_num);
    for (; -1 != cur_index;) {
        entry = white_list_get_entry(cur_index);

        white_list_entry_remove(entry->host,entry->ip,entry->flag);

        cur_index = Res_GetAvailableInBand(wl_head->pool_id, cur_index + 1, wl_head->max_num);
    }

    LOG(SESSION, RUNNING, "white_list clean success.");
}

struct white_list_table *white_list_entry_search(char *host, uint32_t ipaddr, uint8_t flag)
{
    struct white_list_table *entry = NULL;
    struct white_list_table_head *wl_head = white_list_header();

	if (flag) {
		if (NULL == host) {
	        LOG(SESSION, ERR, "Parameters error, host(%p)",host);
	        return NULL;
	    }
        LOG(SESSION, RUNNING, "White-list search host: %s", host);

        ros_rwlock_write_lock(&wl_head->lock); /* lock */
        entry = (struct white_list_table *)rbtree_search(&wl_head->host_root, host,
			white_list_entry_compare_host);
        ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
    	if (NULL == entry) {
	        LOG(SESSION, RUNNING, "White-list no such host: %s.", host);
	        return NULL;
	    }
	} else {
	    LOG(SESSION, RUNNING, "White-list search IP address: 0x%x", ipaddr);

	    ros_rwlock_write_lock(&wl_head->lock); /* lock */
        entry = (struct white_list_table *)rbtree_search(&wl_head->ip_root, &ipaddr,
			white_list_entry_compare_ip);
        ros_rwlock_write_unlock(&wl_head->lock); /* unlock */
		if (NULL == entry) {
	        LOG(SESSION, RUNNING, "White-list no such IP address: 0x%x", ipaddr);
	        return NULL;
	    }
	}
	LOG(SESSION, RUNNING, "White-list search success index: %u", entry->index);

    return entry;
}

int white_list_entry_modify(char *host,uint32_t ipaddr,uint8_t flag,uint32_t head_enrich_flag)
{
    struct white_list_table *entry = NULL;

    if((entry=white_list_entry_search(host,ipaddr,flag))==NULL)
	{
        LOG(SESSION, ERR, "wl entry modify failed, can't find host[%s] ipaddr[%x] flag[%d]",host,ipaddr,flag);
		return -1;
    }

	entry->head_enrich_flag = head_enrich_flag;

	if(entry->flag)
		LOG(SESSION, RUNNING, "white_list_entry_modify success index:%d, host:[%s] head_enrich_flag[%x]",
			entry->index,entry->host,entry->head_enrich_flag);
	else
		LOG(SESSION, RUNNING, "white_list_entry_modify success index:%d, ip:[%x] head_enrich_flag[%x]",
			entry->index,entry->ip,entry->head_enrich_flag);

    return 0;
}

void white_list_entry_show(struct cli_def *cli)
{
	struct white_list_table *entry = NULL;
    struct white_list_table_head *wl_head = white_list_header();

	ros_rwlock_write_lock(&wl_head->lock);/* lock */

	cli_print(cli, "host white list:\r\n");
	entry = (struct white_list_table *)rbtree_first(&wl_head->host_root);
	while (NULL != entry) {
		cli_print(cli, "index:%d, host:[%s] head_enrich_flag[%x]\r\n",entry->index,entry->host,entry->head_enrich_flag);

		entry = (struct white_list_table *)rbtree_next(&entry->node);
	}

	cli_print(cli, "\r\nip white list:\r\n");
	entry = (struct white_list_table *)rbtree_first(&wl_head->ip_root);
	while (NULL != entry) {
		cli_print(cli, "index:%d, ip:[%d.%d.%d.%d] head_enrich_flag[%x]\r\n",entry->index,((entry->ip)>>24)&0xff,
					((entry->ip)>>16)&0xff,((entry->ip)>>8)&0xff,(entry->ip)&0xff,entry->head_enrich_flag);

		entry = (struct white_list_table *)rbtree_next(&entry->node);
	}
	ros_rwlock_write_unlock(&wl_head->lock);// unlock

}


int cli_white_list(struct cli_def *cli, int argc, char **argv)
{
	uint32_t ipaddr,head_enrich_flag;
	int	  result;

	if(argc < 1)
	{
        cli_print(cli, "%d:Please input add/del/mod/search/show ip/host value.\r\n",__LINE__);
        return 0;
    }

	if(strcmp(argv[0],"add") && strcmp(argv[0],"del") && strcmp(argv[0],"mod") &&
	    strcmp(argv[0],"search") && strcmp(argv[0],"show"))
	{
        cli_print(cli, "%d:Please input add/del/mod/search/show ip/host value.\r\n",__LINE__);
        return 0;
    }

	if(!strcmp(argv[0],"show") && argc < 1)
	{
        cli_print(cli, "%d:Please input white_list show\r\n",__LINE__);
        return 0;
    }
	else if((!strcmp(argv[0],"add") || !strcmp(argv[0],"del") || !strcmp(argv[0],"search")) && argc < 3){
        cli_print(cli, "%d:Please input add/del/search ip/host value.\r\n",__LINE__);
        return 0;
    }
	else if(!strcmp(argv[0],"mod") && argc < 4)
	{
        cli_print(cli, "%d:Please input mod ip/host value head_enrich_flag(0xff)\r\n",__LINE__);
        return 0;
    }

	if((!strcmp(argv[0],"add") || !strcmp(argv[0],"del") || !strcmp(argv[0],"mod") || !strcmp(argv[0],"search"))&&
		(strcmp(argv[1],"ip") && strcmp(argv[1],"host")))
	{
        cli_print(cli, "%d:Please input add/del/mod/search ip/host value.\r\n",__LINE__);
        return 0;
    }

	if(!strcmp(argv[0],"add"))
	{
		if(!strcmp(argv[1],"ip"))
		{
			ipaddr = htonl(inet_addr(argv[2]));
			cli_print(cli, "white ip[%x][%x]\r\n",ipaddr,inet_addr(argv[2]));

			result = white_list_entry_insert(NULL,ipaddr,0);
			if(result == 0)
				cli_print(cli, "white list[%d.%d.%d.%d] insert success\r\n",(ipaddr>>24)&0xff,
					(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff);
			else if(result == 1)
				cli_print(cli, "white list[%d.%d.%d.%d] already exist\r\n",(ipaddr>>24)&0xff,
					(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff);
			else
				cli_print(cli, "white list[%x] insert failed\r\n",ipaddr);
		}
		else
		{
			result = white_list_entry_insert(argv[2],0,1);
			if(result == 0)
				cli_print(cli, "white list[%s] insert success\r\n",argv[2]);
			else if(result == 1)
				cli_print(cli, "white list[%s] already exist\r\n",argv[2]);
			else
				cli_print(cli, "white list[%s] insert failed\r\n",argv[2]);
		}
	}
	else if(!strcmp(argv[0],"del"))
	{
		if(!strcmp(argv[1],"ip"))
		{
			ipaddr = htonl(inet_addr(argv[2]));
			if(!white_list_entry_remove(NULL,ipaddr,0))
				cli_print(cli, "white list[%d.%d.%d.%d] remove success\r\n",(ipaddr>>24)&0xff,
					(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff);
			else
				cli_print(cli, "white list[%d.%d.%d.%d] remove failed\r\n",(ipaddr>>24)&0xff,
					(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff);
		}
		else
		{
			if(!white_list_entry_remove(argv[2],0,1))
				cli_print(cli, "white list[%s] remove success\r\n",argv[2]);
			else
				cli_print(cli, "white list[%s] remove failed\r\n",argv[2]);
		}
	}
	else if(!strcmp(argv[0],"mod"))
	{
		if (('0' == argv[3][0]) && (('x' == argv[3][1]) || ('X' == argv[3][1]))) {
    		head_enrich_flag = strtoll(argv[3], NULL, 16);
		}
		else
		{
	        cli_print(cli, "%d: Please input 0xff of head_enrich_flag\r\n",__LINE__);
	        return 0;
	    }

		if(!strcmp(argv[1],"ip"))
		{
			ipaddr = htonl(inet_addr(argv[2]));

			if(white_list_entry_modify(NULL,ipaddr,0,head_enrich_flag) == 0)
				cli_print(cli, "white list[%d.%d.%d.%d] head_enrich_flag[%x] modify success\r\n",(ipaddr>>24)&0xff,
					(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff,head_enrich_flag);
			else
				cli_print(cli, "white list[%d.%d.%d.%d] head_enrich_flag[%x] modify failed\r\n",(ipaddr>>24)&0xff,
					(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff,head_enrich_flag);
		}
		else
		{
			if(white_list_entry_modify(argv[2],0,1,head_enrich_flag) == 0)
				cli_print(cli, "white list[%s] head_enrich_flag[%x] modify success\r\n",argv[2],head_enrich_flag);
			else
				cli_print(cli, "white list[%s] head_enrich_flag[%x] modify failed\r\n",argv[2],head_enrich_flag);
		}
	}
	else if(!strcmp(argv[0],"search"))
	{
		if(!strcmp(argv[1],"ip"))
		{
			ipaddr = htonl(inet_addr(argv[2]));
			if(white_list_entry_search(NULL,ipaddr,0))
				cli_print(cli, "white list search success ipaddr[%x]\r\n",ipaddr);
			else
				cli_print(cli, "white list search failed ipaddr[%x]\r\n",ipaddr);
		}
		else
		{
			if(white_list_entry_search(argv[2],0,1))
				cli_print(cli, "white list search success host[%s]\r\n",argv[2]);
			else
				cli_print(cli, "white list search failed host[%s]\r\n",argv[2]);
		}
	}
	else
	{
		white_list_entry_show(cli);
	}

	if(!strcmp(argv[0],"show"))
		cli_print(cli, "cli_white_list %s\r\n",argv[0]);
	else
		cli_print(cli, "cli_white_list %s %s %s \r\n",argv[0],argv[1],argv[2]);

	return 0;
}

