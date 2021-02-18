/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _CM_DEBUG_H__
#define _CM_DEBUG_H__

#ifdef __cplusplus
extern "C" {
#endif

extern void cm_dump_stack(void);
extern void cm_dump_registers(void);
extern void _cm_panic(const char *funcname , const char *format, ...);
extern void cm_print_data(char *data, int size);

#define cm_panic(...) cm_panic_(__func__, __VA_ARGS__, "dummy")
#define cm_panic_(func, format, ...) _cm_panic(func, format "%.0s", __VA_ARGS__)

#ifdef CM_ENABLE_ASSERT
#define CM_ASSERT(exp)	CM_VERIFY(exp)
#else
#define CM_ASSERT(exp) do {} while (0)
#endif
#define	CM_VERIFY(exp)	do {                                                  \
	if (unlikely(!(exp)))                                                     \
		cm_panic("line %d\tassert \"%s\" failed\n", __LINE__, #exp);          \
} while (0)


#define KM_X86_ss  	    aulReg[16]
#define KM_X86_sp		aulReg[15]
#define KM_X86_flags	aulReg[14]
#define KM_X86_cs		aulReg[13]
#define KM_X86_ip		aulReg[12]
#define KM_X86_orig_ax	aulReg[11]
#define KM_X86_gs		aulReg[10]
#define KM_X86_fs		aulReg[9]
#define KM_X86_es		aulReg[8]
#define KM_X86_ds		aulReg[7]
#define KM_X86_ax		aulReg[6]
#define KM_X86_bp		aulReg[5]
#define KM_X86_di		aulReg[4]
#define KM_X86_si		aulReg[3]
#define KM_X86_dx		aulReg[2]
#define KM_X86_cx		aulReg[1]
#define KM_X86_bx		aulReg[0]


typedef struct tag_ST_MON_REGS_CONTEXT_KM 
{
        int slPid;
        int slTgid;
        char ascComm[16];
        int slCpu;

        unsigned long aulReg[32];
} __attribute__((aligned(8))) ST_MON_REGS_CONTEXT_KM;

extern int DRV_RegInfoRead(int ulPid, ST_MON_REGS_CONTEXT_KM *pstReg);



#ifdef __cplusplus
}
#endif

#endif  /* #ifndef  _CM_DEBUG_H__ */
