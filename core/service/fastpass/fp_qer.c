/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/
#include "service.h"
#include "fp_msg.h"
#include "fp_start.h"
#include "fp_qer.h"

enum policer_action fp_policer_table[FP_DROP][FP_DROP] =
{
	{ FP_GREEN, FP_GREEN,    FP_GREEN},
	{ FP_GREEN, FP_YELLOW,   FP_RED},
	{ FP_GREEN, FP_RED,      FP_RED}
};

/* config local var by configuration */
void fp_qer_launch(fp_qer_entry *qer_entry)
{
    /* set up_link data */
    if (qer_entry->qer_cfg.flag.s.f_um) {
        ros_atomic64_set(&qer_entry->ul_meter.tokenp_num, 0);
        qer_entry->ul_meter.tokenp_grow  = qer_entry->qer_cfg.ul_mbr * FP_QER_KBR_TO_BYTE;
        ros_atomic64_set(&qer_entry->ul_meter.last_cycles, 0);
    }
	if (qer_entry->qer_cfg.flag.s.f_ug) {
        ros_atomic64_set(&qer_entry->ul_meter.tokenc_num, 0);
        qer_entry->ul_meter.tokenc_grow  = qer_entry->qer_cfg.ul_gbr * FP_QER_KBR_TO_BYTE;
        ros_atomic64_set(&qer_entry->ul_meter.last_cycles, 0);
    }
    if (qer_entry->qer_cfg.flag.s.f_up) {
        ros_atomic32_set(&qer_entry->ul_meter.pkt_num, qer_entry->qer_cfg.ul_pkt_max);
        qer_entry->ul_meter.valid_cycle = qer_entry->qer_cfg.valid_time;
    }

    /* set down_link data */
    if (qer_entry->qer_cfg.flag.s.f_dm) {
        ros_atomic64_set(&qer_entry->dl_meter.tokenp_num, 0);
        qer_entry->dl_meter.tokenp_grow  = qer_entry->qer_cfg.dl_mbr * FP_QER_KBR_TO_BYTE;
        ros_atomic64_set(&qer_entry->dl_meter.last_cycles, 0);
    }
	if (qer_entry->qer_cfg.flag.s.f_dg) {
        ros_atomic64_set(&qer_entry->dl_meter.tokenc_num, 0);
        qer_entry->dl_meter.tokenc_grow  = qer_entry->qer_cfg.dl_gbr * FP_QER_KBR_TO_BYTE;
        ros_atomic64_set(&qer_entry->dl_meter.last_cycles, 0);
    }
    if (qer_entry->qer_cfg.flag.s.f_dp) {
        ros_atomic32_set(&qer_entry->dl_meter.pkt_num, qer_entry->qer_cfg.dl_pkt_max);
        qer_entry->dl_meter.valid_cycle = qer_entry->qer_cfg.valid_time;
    }

}

void fp_qer_update_token(ros_atomic64_t *last_cycle, ros_atomic64_t *token_num, uint64_t token_grow, ros_atomic64_t *debt)
{
    uint64_t cur_cycle;

    /* get new cycle */
    cur_cycle = fp_get_cycle();

    /* like this branch when mass packets */
    if (likely(cur_cycle < (uint64_t)ros_atomic64_read(last_cycle))) {
        /* do nothing */
        return;
    }
    else {

        /* over burst time */
        if (cur_cycle > (uint64_t)ros_atomic64_read(last_cycle) + FP_QER_BURST_TIME_LEN) {

            LOG(FASTPASS, RUNNING,
                "current cycle(%lu) minus last cycle(%lu) over than burst time length(%lu), update to burst bucket.",
                cur_cycle, ros_atomic64_read(last_cycle), FP_QER_BURST_TIME_LEN);

            /* set new cycles */
            ros_atomic64_set(last_cycle, cur_cycle);

            /* set to double mbr bytes */
            ros_atomic64_set(token_num, token_grow * FP_QER_BURST_TIMES);
			ros_atomic64_set(debt, 0);
        }
        /* over time, but less than burst time, add 1 second's token to bucket */
        else {

            /* update cycles */
            ros_atomic64_add(last_cycle, fp_get_freq());

            /* if over than burst size, set to burst size */
            if (ros_atomic64_read(token_num) > (int32_t)token_grow) {

                /* set to burst size */
                ros_atomic64_set(token_num, token_grow * FP_QER_BURST_TIMES);
            }
            else {

                /* add on second's token */
                /* mbr or gbr is kbps, translate to bytes */
                ros_atomic64_add(token_num, token_grow);
				ros_atomic64_sub(token_num, ros_atomic64_read(debt));
            }

			ros_atomic64_set(debt, 0);

            LOG(FASTPASS, RUNNING,
                "cross second boundary, grow bucket to %ld, token_grow %ld.",
                ros_atomic64_read(token_num), token_grow);
        }
    }
}


void fp_qer_update_cp_token(ros_atomic64_t *last_cycle, ros_atomic64_t *tokenc_num, uint64_t tokenc_grow,
	ros_atomic64_t *tokenp_num, uint64_t tokenp_grow, ros_atomic64_t *debt)
{
    uint64_t cur_cycle;

    /* get new cycle */
    cur_cycle = fp_get_cycle();

    /* like this branch when mass packets */
    if (likely(cur_cycle < (uint64_t)ros_atomic64_read(last_cycle))) {
        /* do nothing */
        return;
    }
    else {

        /* over burst time */
        if (cur_cycle > (uint64_t)ros_atomic64_read(last_cycle) + FP_QER_BURST_TIME_LEN) {

            LOG(FASTPASS, RUNNING,
                "current cycle(%lu) minus last cycle(%lu) over than burst time length(%lu), update to burst bucket.",
                cur_cycle, ros_atomic64_read(last_cycle), FP_QER_BURST_TIME_LEN);

            /* set new cycles */
            ros_atomic64_set(last_cycle, cur_cycle);

            /* set to double mbr bytes */
            ros_atomic64_set(tokenc_num, tokenc_grow * FP_QER_BURST_TIMES);
			ros_atomic64_set(tokenp_num, tokenp_grow * FP_QER_BURST_TIMES);
			ros_atomic64_set(debt, 0);
        }
        /* over time, but less than burst time, add 1 second's token to bucket */
        else {

            /* update cycles */
            ros_atomic64_add(last_cycle, fp_get_freq());

            /* if over than burst size, set to burst size */
            if (ros_atomic64_read(tokenc_num) > (int64_t)tokenc_grow) {

                /* set to burst size */
                ros_atomic64_set(tokenc_num, tokenc_grow * FP_QER_BURST_TIMES);
            }
            else {

                /* add on second's token */
                /* gbr is kbps, translate to bytes */
                ros_atomic64_add(tokenc_num, tokenc_grow);
            }

			/* if over than burst size, set to burst size */
            if (ros_atomic64_read(tokenp_num) > (int32_t)tokenp_grow) {

                /* set to burst size */
                ros_atomic64_set(tokenp_num, tokenp_grow * FP_QER_BURST_TIMES);
            }
            else {

                /* add on second's token */
                /* mbr is kbps, translate to bytes */
                ros_atomic64_add(tokenp_num, tokenp_grow);
				ros_atomic64_sub(tokenp_num, ros_atomic64_read(debt));
            }

			ros_atomic64_set(debt, 0);

            LOG(FASTPASS, RUNNING,
                "cross second boundary, grow c bucket to %ld, tokenc_grow %ld, grow p bucket to %ld, tokenp_grow %ld.",
                ros_atomic64_read(tokenc_num), tokenc_grow, ros_atomic64_read(tokenp_num), tokenp_grow);
        }
    }
}

int fp_qer_handle_ul(int pkt_len, int pkt_num, fp_qer_entry *qer_entry, uint32_t input_color)
{
	uint32_t output_color = COMM_MSG_LIGHT_YELLOW;
	/* 1. check gate status, 0:open, 1:close */
	if (qer_entry->qer_cfg.ul_gate) {
		LOG(FASTPASS, RUNNING, "qer gate close(%d).", qer_entry->qer_cfg.ul_gate);
		return COMM_MSG_LIGHT_RED;
	}

	/* 2. check packet status */
	if (qer_entry->qer_cfg.flag.s.f_up) {

		/* check valid time */
		if (ros_getime() > qer_entry->ul_meter.valid_cycle) {
			LOG(FASTPASS, RUNNING, "qer packet status time over(%u > %u).",
				ros_getime(), qer_entry->dl_meter.valid_cycle);
			return COMM_MSG_LIGHT_RED;
		}

		/* check pkt number */
		if (ros_atomic32_read(&qer_entry->ul_meter.pkt_num) <= 0) {
			LOG(FASTPASS, RUNNING, "qer packet status count exhausted.");
			return COMM_MSG_LIGHT_RED;
		}
		ros_atomic32_sub(&qer_entry->ul_meter.pkt_num, pkt_num);
	}

	/* 3. check bit rate */
	if (qer_entry->qer_cfg.flag.s.f_um &&
		qer_entry->qer_cfg.flag.s.f_ug) {

		/* update token bucket */
		fp_qer_update_cp_token(&qer_entry->ul_meter.last_cycles, &qer_entry->ul_meter.tokenc_num,
			qer_entry->ul_meter.tokenc_grow, &qer_entry->ul_meter.tokenp_num, qer_entry->ul_meter.tokenp_grow, &qer_entry->ul_meter.debt);

		/* check token status */
		if (ros_atomic64_read(&qer_entry->ul_meter.tokenp_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token use up.");
			output_color = COMM_MSG_LIGHT_RED;
		}
		else if (ros_atomic64_read(&qer_entry->ul_meter.tokenc_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token c use up.");
			output_color = COMM_MSG_LIGHT_YELLOW;
		}
		else {
			output_color = COMM_MSG_LIGHT_GREEN;
		}
		qer_entry->ul_meter.color = output_color;

		if (COMM_MSG_LIGHT_YELLOW == output_color) {
			ros_atomic64_sub(&qer_entry->ul_meter.tokenp_num, pkt_len);
		}
		else if(COMM_MSG_LIGHT_GREEN == output_color) {
			ros_atomic64_sub(&qer_entry->ul_meter.tokenp_num, pkt_len);
			ros_atomic64_sub(&qer_entry->ul_meter.tokenc_num, pkt_len);
		}

	}
	else if (qer_entry->qer_cfg.flag.s.f_um) {

		fp_qer_update_token(&qer_entry->ul_meter.last_cycles, &qer_entry->ul_meter.tokenp_num,
            qer_entry->ul_meter.tokenp_grow, &qer_entry->ul_meter.debt);

		/* check token status */
		if (ros_atomic64_read(&qer_entry->ul_meter.tokenp_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token use up.");
			output_color = COMM_MSG_LIGHT_RED;
		}
		else {
			output_color = COMM_MSG_LIGHT_YELLOW;
		}
		qer_entry->ul_meter.color = output_color;

		if (COMM_MSG_LIGHT_YELLOW == output_color) {
			ros_atomic64_sub(&qer_entry->ul_meter.tokenp_num, pkt_len);
		}

	}
	else if (qer_entry->qer_cfg.flag.s.f_ug) {

		fp_qer_update_token(&qer_entry->ul_meter.last_cycles, &qer_entry->ul_meter.tokenc_num,
            qer_entry->ul_meter.tokenc_grow, &qer_entry->ul_meter.debt);

		/* check token status */
		if (ros_atomic64_read(&qer_entry->ul_meter.tokenc_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token use up.");
			output_color = COMM_MSG_LIGHT_RED;
		}
		else {
			output_color = COMM_MSG_LIGHT_GREEN;
		}
		qer_entry->ul_meter.color = output_color;

		if (COMM_MSG_LIGHT_GREEN == output_color) {
			ros_atomic64_sub(&qer_entry->ul_meter.tokenc_num, pkt_len);
		}

	}

	output_color = fp_policer_table[input_color][output_color];
	return output_color;
}


/* 不需要对*gtpu_ext赋值，外层有赋初值，避免重复操作，特此备注 */
int fp_qer_handle_dl(int pkt_len, int pkt_num, fp_qer_entry *qer_entry, uint32_t input_color)
{
	uint32_t output_color = COMM_MSG_LIGHT_YELLOW;

	/* 1. check gate status, 0:open, 1:close */
	if (qer_entry->qer_cfg.dl_gate) {
		LOG(FASTPASS, RUNNING, "qer gate close(%d).", qer_entry->qer_cfg.ul_gate);
		return COMM_MSG_LIGHT_RED;
	}

	/* 2. check packet status */
	if (qer_entry->qer_cfg.flag.s.f_dp) {

		/* check valid time */
		if (ros_getime() > qer_entry->dl_meter.valid_cycle) {
			LOG(FASTPASS, RUNNING, "qer packet status time over(%u > %u).",
				ros_getime(), qer_entry->dl_meter.valid_cycle);
			return COMM_MSG_LIGHT_RED;
		}

		/* check pkt number */
		if (ros_atomic32_read(&qer_entry->dl_meter.pkt_num) <= 0) {
			LOG(FASTPASS, RUNNING, "qer packet status count exhausted.");
			return COMM_MSG_LIGHT_RED;
		}
		ros_atomic32_sub(&qer_entry->dl_meter.pkt_num, pkt_num);
	}

	/* 3. check bit rate */
	if (qer_entry->qer_cfg.flag.s.f_dm &&
		qer_entry->qer_cfg.flag.s.f_dg) {

		/* update token bucket */
		fp_qer_update_cp_token(&qer_entry->dl_meter.last_cycles, &qer_entry->dl_meter.tokenc_num,
			qer_entry->dl_meter.tokenc_grow, &qer_entry->dl_meter.tokenp_num, qer_entry->dl_meter.tokenp_grow, &qer_entry->dl_meter.debt);

		/* check token status */
		if (ros_atomic64_read(&qer_entry->dl_meter.tokenp_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token use up.");
			output_color = COMM_MSG_LIGHT_RED;
		}
		else if (ros_atomic64_read(&qer_entry->dl_meter.tokenc_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token c use up.");
			output_color = COMM_MSG_LIGHT_YELLOW;
		}
		else {
			output_color = COMM_MSG_LIGHT_GREEN;
		}
		qer_entry->dl_meter.color = output_color;

		if (COMM_MSG_LIGHT_YELLOW == output_color) {
			ros_atomic64_sub(&qer_entry->dl_meter.tokenp_num, pkt_len);
		}
		else if(COMM_MSG_LIGHT_GREEN == output_color) {
			ros_atomic64_sub(&qer_entry->dl_meter.tokenp_num, pkt_len);
			ros_atomic64_sub(&qer_entry->dl_meter.tokenc_num, pkt_len);
		}

	}
	else if (qer_entry->qer_cfg.flag.s.f_dm) {

		fp_qer_update_token(&qer_entry->dl_meter.last_cycles, &qer_entry->dl_meter.tokenp_num,
            qer_entry->dl_meter.tokenp_grow, &qer_entry->dl_meter.debt);

		/* check token status */
		if (ros_atomic64_read(&qer_entry->dl_meter.tokenp_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token use up.");
			output_color = COMM_MSG_LIGHT_RED;
		}
		else {
			output_color = COMM_MSG_LIGHT_YELLOW;
		}
		qer_entry->dl_meter.color = output_color;

		if (COMM_MSG_LIGHT_YELLOW == output_color) {
			ros_atomic64_sub(&qer_entry->dl_meter.tokenp_num, pkt_len);
		}

	}
	else if (qer_entry->qer_cfg.flag.s.f_dg) {

		fp_qer_update_token(&qer_entry->dl_meter.last_cycles, &qer_entry->dl_meter.tokenc_num,
            qer_entry->dl_meter.tokenc_grow, &qer_entry->dl_meter.debt);

		/* check token status */
		if (ros_atomic64_read(&qer_entry->dl_meter.tokenc_num) < 0) {
			LOG(FASTPASS, RUNNING, "qer token use up.");
			output_color = COMM_MSG_LIGHT_RED;
		}
		else {
			output_color = COMM_MSG_LIGHT_GREEN;
		}
		qer_entry->dl_meter.color = output_color;

		if (COMM_MSG_LIGHT_GREEN == output_color) {
			ros_atomic64_sub(&qer_entry->dl_meter.tokenc_num, pkt_len);
		}

	}

	output_color = fp_policer_table[input_color][output_color];
	return output_color;
}



