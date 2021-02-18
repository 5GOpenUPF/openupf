/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef __FP_FRAG_H__
#define __FP_FRAG_H__

#define FP_FRAG_MAX             32
#define FP_FRAG_SPARE           128         /* reserve for furture, used for add more header */
#define FP_HTTP_HEAD_NUM        9 

typedef struct tag_fp_frag_desc {
    uint16_t            valid :1;           /* valid bit */
    uint16_t            offset:15;          /* resv */
    uint16_t            length;
}fp_frag_desc;

typedef struct tag_fp_frag_cb {
    AVLU_NODE           avlnode;
    fp_frag_desc        desc[FP_FRAG_MAX];
    uint16_t            cur_len;
    uint8_t             last_flag;
    uint8_t             buff[1];
}fp_frag_cb;

/*用于tcp分段*/
typedef struct tag_fp_tcp_segment_desc {
	struct tag_fp_tcp_segment_desc *next, *prev;
	char 			*buf;
	void    		*arg;
	unsigned int	len;//报文总长
	unsigned int	tcp_payload_len;//tcp载荷长度
	unsigned int 	sequence;
}fp_tcp_segment_desc;

typedef struct tag_fp_tcp_segment_mgmt {
	fp_tcp_segment_desc *list;
	uint32_t			num;
	unsigned int 		seg_total_len;//用每个分段包长度累加得到的总长度(tcp载荷)
	unsigned int 		meat_total_len;//用Sequence计算得出的总长度(tcp载荷)
}fp_tcp_segment_mgmt;

fp_frag_cb *fp_frag_alloc_cb(void);
int32_t fp_frag_check_full(fp_frag_cb *cb);
fp_frag_cb *fp_frag_entry(void *head, struct pro_ipv4_hdr *ipheader);
inline fp_frag_cb *fp_frag_table_match(void *table, uint16_t id, uint32_t aux_info);
fp_frag_cb *fp_frag_table_add(void *head, uint32_t id, uint32_t aux_info);
int32_t fp_frag_table_del(void *head, uint32_t id, uint32_t aux_info);
int32_t fp_frag_defrag(fp_frag_cb *cb, struct pro_ipv4_hdr *ipheader);
int32_t fp_check_http_head_is_full(char *buf, int len);
void fp_tcp_segment_free(void	 **tcp_seg_mgmt_head);
char *fp_tcp_segment_reasm(fp_tcp_segment_mgmt *tcp_seg_mgmt, int *buf_len);
int32_t fp_tcp_segment_process(void **entry, char *buf, void *arg, int len, 
		struct pro_tcp_hdr *tcp_hdr);

#endif

