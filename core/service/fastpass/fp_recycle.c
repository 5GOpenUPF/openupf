/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "service.h"
#include "fp_msg.h"
#include "fp_recycle.h"

CVMX_SHARED uint32_t fp_recycle_count;
CVMX_SHARED uint32_t fp_recycle_num;
CVMX_SHARED uint32_t fp_recycle_level;

void fp_recycle_init(uint32_t fast_num)
{
    /* count from 0 */
    fp_recycle_count = 0;

    /* set default recycle level */
    fp_recycle_level = FP_RECYCLE_LEVEL_1;

    LOG(FASTPASS, RUNNING, "set recycle policy to level 1!");

    /* calculate recycle num each time */
    fp_recycle_num = fast_num/FP_RECYCLE_PERIOD;

    LOG(FASTPASS, RUNNING, "check %d fast entrires' recycle status every second!", fp_recycle_num);

    return;
}

/* check 1000 entries cost 10ms */
void fp_recycle_entry()
{
    fp_fast_table *fast_head = (fp_fast_table *)fp_fast_table_get(COMM_MSG_FAST_IPV4);
    fp_fast_entry *fast_entry;
    uint32_t recycle_start, recycle_end;
    int32_t  recycl_cur;
    uint32_t sum_num;
    uint32_t recycle_cnt = 0;
    uint32_t valid_cnt = 0;

    /* calculate start and end point */
    recycle_start = fp_recycle_count*fp_recycle_num;
    if (fp_recycle_count == FP_RECYCLE_PERIOD - 1) {
        /* last second, handle all remainder entries */
        recycle_end = fast_head->entry_max;
    }
    else {
        recycle_end = recycle_start + fp_recycle_num;
    }

    /* recycle entries one by one */
    /* there have 3 types fast table, share same resource pool */
    /* so we choose anyone to recycle, it will cover all pool */
    recycl_cur = Res_GetAvailableInBand(fast_head->res_no, recycle_start,  recycle_end);
    while (recycl_cur != ERROR) {

        valid_cnt++;

        /* increase count */
        fast_entry = fp_fast_entry_get(fast_head, recycl_cur);
        fast_entry->count++;

        /* increased, so use ">" here, not ">=" */
        if (fast_entry->count > fp_recycle_level) {

            /* free entry */
            fp_fast_free(fast_head, fast_entry->index);

            recycle_cnt++;
        }

        /* get next */
        recycl_cur = Res_GetAvailableInBand(fast_head->res_no, recycl_cur + 1,  recycle_end);
    }

    /* increase this counter after recycle */
    fp_recycle_count++;
    if (fp_recycle_count >= FP_RECYCLE_PERIOD) {
        fp_recycle_count = 0;
    }

    LOG(FASTPASS, PERIOD,
        "check entry %d to %d, valid entry %d, recycle %d, current policy level %d!",
        recycle_start, recycle_end, valid_cnt, recycle_cnt,
        ((fp_recycle_level == FP_RECYCLE_LEVEL_3) ? 3 : ((fp_recycle_level == FP_RECYCLE_LEVEL_2) ? 2 : 1)));

    /* evaluate recycle policy */
    sum_num = Res_GetAlloced(fast_head->res_no);
    if (sum_num * 100 > fast_head->entry_max * FP_RECYCLE_THRESHOLD_3) {

        if (fp_recycle_level != FP_RECYCLE_LEVEL_3) {
            fp_recycle_level = FP_RECYCLE_LEVEL_3;
            LOG(FASTPASS, RUNNING, "alloced fast entries(%d) over 90%%(%d), set recycle policy to level 3!",
                sum_num, fast_head->entry_max * FP_RECYCLE_THRESHOLD_3);
        }
    }
    else if (sum_num * 100 > fast_head->entry_max * FP_RECYCLE_THRESHOLD_2) {

        if (fp_recycle_level != FP_RECYCLE_LEVEL_2) {
            fp_recycle_level = FP_RECYCLE_LEVEL_2;
            LOG(FASTPASS, RUNNING, "alloced fast entries(%d) over 70%%(%d), set recycle policy to level 2!",
                sum_num, fast_head->entry_max * FP_RECYCLE_THRESHOLD_2);
        }
    }
    else if (fp_recycle_level != FP_RECYCLE_LEVEL_1) {

        fp_recycle_level = FP_RECYCLE_LEVEL_1;
        LOG(FASTPASS, RUNNING, "alloced fast entries(%d) lower than 70%%(%d), set recycle policy to level 1!",
            sum_num, fast_head->entry_max * FP_RECYCLE_THRESHOLD_2);
    }

    return;
}


