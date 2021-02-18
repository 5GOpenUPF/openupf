/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _UPC_TEID_H__
#define _UPC_TEID_H__

#ifdef __cplusplus
extern "C" {
#endif


#define UPC_TEID_GET_NODE_INDEX(teid, node_bit_num)  \
    (uint32_t)((uint64_t)teid >> (32 - node_bit_num))

#define UPC_TEID_GET_TEID_INDEX(teid, node_teid_mask)  \
    ((uint32_t)teid & (uint32_t)node_teid_mask)

#define UPC_TEID_GET_TEID(node_index, node_teid_max, teid_index)  \
    ((uint32_t)node_index * (uint32_t)node_teid_max + (uint32_t)teid_index)

/* TEID table */
struct upc_teid_entry {
    uint32_t                    index;
    uint32_t                    teid;
    uint8_t                     valid;
    uint8_t                     spare_u8;
    ros_atomic16_t              cur_use;/* How many entry are currently using */
};

struct upc_teid_table {
    struct upc_teid_entry	    *teid_entry;
    ros_rwlock_t        	    lock;
    uint32_t                    index;
    uint32_t            	    max_num;
    ros_atomic32_t      	    use_num;
    uint16_t            	    pool_id;
};

struct upc_teid_mgmt {
    struct upc_teid_table       *teid_table;     /* all teid table */
    ros_rwlock_t        	    lock;
    uint32_t            	    node_max_num;   /* max node number */
    uint32_t                    node_bit_num;   /* node Bit number */
    uint32_t                    node_teid_max;  /* Maximum TEID per node */
    uint32_t                    node_teid_mask; /* TEID mask of node max */
    ros_atomic32_t      	    teid_use_num;   /* all node used teid number */
};

struct upc_choose_id_mgmt {
    uint8_t         choose_id[256];
    uint32_t        teid[256];
};

struct upc_teid_mgmt *upc_teid_mgmt_get(void);

struct upc_choose_id_mgmt *upc_teid_choose_mgmt_get(uint32_t index);
void upc_teid_choose_mgmt_init(uint32_t index);
int64_t upc_teid_init(uint32_t node_num, uint32_t teid_num);
uint32_t upc_teid_alloc(uint32_t node_index);
int upc_teid_add_target(uint32_t teid);
int upc_teid_free(uint32_t teid);
int upc_teid_is_alloced(uint32_t teid);
int upc_teid_sum(uint32_t teid);
int upc_teid_used_sub(uint32_t teid);
int upc_teid_used_add(uint32_t teid);
int upc_teid_used_get(uint32_t teid);

int upc_teid_alloc_target(uint32_t teid);
int upc_teid_used_set(uint32_t teid, int16_t use_num);




#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _UPC_TEID_H__ */


