/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include "platform.h"
#include "cm_debug.h"

#ifdef CM_BACKTRACE
#include <execinfo.h>
#endif
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define BACKTRACE_SIZE 256

/* dump the stack of the calling core */
void cm_dump_stack(void)
{
#ifdef CM_BACKTRACE
	void *func[BACKTRACE_SIZE];
	char **symb = NULL;
	int size;

	size = backtrace(func, BACKTRACE_SIZE);
	symb = backtrace_symbols(func, size);

	if (symb == NULL)
		return;

	while (size > 0) {
		LOG(CM, ERR,
			"%d: [%s]\n", size, symb[size - 1]);
		size --;
	}

	free(symb);
#endif /* CM_BACKTRACE */
}


extern unsigned long EOS_GetCurrentFp();
int exception_logfile;

#define DRV_DEV_OPEN                        open
#define DRV_DEV_READ                        read
#define DRV_DEV_WRITE                       write
#define DRV_DEV_IOCTL                       ioctl
#define DRV_DEV_CLOSE                       close

#define DRV_DEV_RDWR                        O_RDWR

#define DRV_REG_INFO_DEV_NAME               "/dev/regs"

#define TYPE_GREGS	'G'
#define TYPE_DON	'O'
#define TYPE_DOFF	'F'

#define NR_GREGS 	 0
#define NR_DON 	     1
#define NR_DOFF 	 2

#define CMD_GREGS	_IOR(TYPE_GREGS, NR_GREGS, struct tag_ST_MON_REGS_CONTEXT_KM)
#define CMD_DON	    _IO(TYPE_DON, NR_DON)
#define CMD_DOFF	_IO(TYPE_DOFF, NR_DOFF)


/* 设置目标线程pid */
static int DRV_RegInfoSetPid(int ulPid)
{
    int slTemp;
    int slFd = 0;
    int ulRet;

    ulRet = -1;

    slFd = DRV_DEV_OPEN(DRV_REG_INFO_DEV_NAME,DRV_DEV_RDWR);
    if (0 >= slFd)
    {
        /* REGINFO_Print(slFd, errno); */
        goto error;
    }

    slTemp = DRV_DEV_IOCTL(slFd, CMD_GREGS, ulPid);
    if (slTemp < 0)
    {
        /* REGINFO_Print(slTemp, errno); */
        goto error;
    }

    ulRet = 0;
error:
    DRV_DEV_CLOSE(slFd);
    return ulRet;
}


/* 直接读取目标线程的寄存器信息 */
static int DRV_RegInfoRead_X(ST_MON_REGS_CONTEXT_KM *pstReg)
{
    int slTemp;
    int slFd = 0;
    int ulRet;

    ulRet = -1;

    slFd = DRV_DEV_OPEN(DRV_REG_INFO_DEV_NAME,DRV_DEV_RDWR);
    if (0 >= slFd)
    {
        /* REGINFO_Print(slFd, errno); */
        goto error;
    }

    slTemp = DRV_DEV_READ(slFd, pstReg, sizeof(ST_MON_REGS_CONTEXT_KM));
    if (sizeof(ST_MON_REGS_CONTEXT_KM) != slTemp)
    {
        /* REGINFO_Print(slTemp, errno); */
        goto error;
    }

    ulRet = 0;
error:
    DRV_DEV_CLOSE(slFd);
    return ulRet;
}



/* 设置并读取目标线程的寄存器信息 */
int DRV_RegInfoRead(int ulPid, ST_MON_REGS_CONTEXT_KM *pstReg)
{

    if (-1 == DRV_RegInfoSetPid(ulPid))
    {
        return -1;
    }

    if (-1 == DRV_RegInfoRead_X(pstReg))
    {
        return -2;
    }

    return 0;
}
#if 0
typedef struct {
	int si_signo;
	int si_code;
	union sigval si_value;
	int si_errno;
	pid_t si_pid;
	uid_t si_uid;
	void *si_addr;
	int si_status;
	int si_band;
} siginfo_t;
#endif

extern unsigned long _init;
extern unsigned long _fini;

unsigned int cm_get_callpc_bysp(unsigned long *rsp, unsigned long *pc, unsigned long *bp, unsigned long *addr);



unsigned int cm_get_callstack_bypid(pid_t pid, unsigned long *pc, unsigned long *bp,unsigned long max)
{
    ST_MON_REGS_CONTEXT_KM stReg;
    unsigned long *rsp,*rbp = NULL,*pstackdata;
    unsigned long i,rip_len = 0;

    if( DRV_RegInfoRead(pid,&stReg))
    {
        return 0;
    }

#if 0
    printf("get pid(%d) info:",pid);
    printf("rbx=%016lx rcx=%016lx rdx=%016lx rsi=%016lx",
                stReg.aulReg[0],stReg.aulReg[1],stReg.aulReg[2],stReg.aulReg[3]);
    printf("rdi=%016lx rbp=%016lx rax=%016lx rds=%016lx",
                stReg.aulReg[4],stReg.aulReg[5],stReg.aulReg[6],stReg.aulReg[7]);
    //bp 栈帧基址，有时全0全F无效，有时不是当前函数的栈基址
    printf("res=%016lx rfs=%016lx rgs=%016lx roa=%016lx",
                stReg.aulReg[8],stReg.aulReg[9],stReg.aulReg[10],stReg.aulReg[11]);

    printf("rip=%016lx rcs=%016lx rfg=%016lx rsp=%016lx",
                stReg.aulReg[12],stReg.aulReg[13],stReg.aulReg[14],stReg.aulReg[15]);
    //ip 总是无效的指令地址，无法利用
    //sp 内核struct pt_regs记录的栈顶，总是有效
    printf("rss=%016lx rlr=%016lx sp1=%016lx ksp=%016lx",
                stReg.aulReg[16],stReg.aulReg[17],stReg.aulReg[18],stReg.aulReg[19]);
    //lr 总是无效的指令返回地址，无法利用
    printf("usp=%016lx tsk=%016lx",stReg.aulReg[20],stReg.aulReg[21]);
    //usp 内核struct thread_struct记录的栈顶，总是有效
#endif
    //调用栈向下生长，所以取这两个栈顶值中的较小者，尽可能的获取全部调用函数的栈数据
    rsp = (unsigned long*)(stReg.aulReg[15] < stReg.aulReg[20]? stReg.aulReg[15] : stReg.aulReg[20]);
    //printf("\n stack data =");
    for (i = 0; i < 128; i ++)
    {
        //printf("\n %016lx: %016lx %016lx %016lx %016lx",
            //(unsigned long)(rsp+ 4*i),*(rsp+ 4*i),*(rsp+ 4*i+1),*(rsp+ 4*i+2),*(rsp+ 4*i+3));
    }

    //printf("\n #### %d %016lx",__LINE__,(unsigned long)rsp);
    rip_len = 0;
    for (pstackdata = (unsigned long *)rsp; (unsigned long)pstackdata < (unsigned long)rsp + 4*1024; pstackdata ++)
    {
        //按地址顺序搜索函数栈里的第一个【栈基址 + 返回指令地址】数据结构
        if ((*(pstackdata+1) > (unsigned long)&_init)&&(*(pstackdata+1) < (unsigned long)&_fini))
        {
            //指令地址有效
            pc[rip_len] = *(pstackdata+1);
            if (((*pstackdata & 0x7) == 0)&&\
                (*pstackdata - (unsigned long)pstackdata < 4*1024))
            {
                //栈基址有效 ，匹配【栈基址 + 返回指令地址】数据结构，
                //break之后按照栈基址跳跃式找下一个【栈基址 + 返回指令地址】数据结构
                bp[rip_len] = *pstackdata;
                rbp = (unsigned long *)*pstackdata;
                //printf("\n #### found sp1:%016lx %016lx",bp[rip_len],pc[rip_len]);
                rip_len++;
                break;
            }
            else
            {
                //栈基址无效 ，仅指令地址有效的，认为是当前执行指令地址，而不是返回指令地址，继续查找栈基址
                bp[rip_len] = 0;
                //printf("\n #### found sp1:%016lx %016lx",bp[rip_len],pc[rip_len]);
                rip_len++;
            }
        }
    }

    //printf("\n #### %d %016lx",__LINE__,(unsigned long)rbp);
    //根据rbp，跳跃式找下一个【栈基址 + 返回指令地址】数据结构
    for(;((rbp > rsp)&&(rbp < rsp + 32*1024));)
    {
        //printf("\n #### %d %016lx",__LINE__,(unsigned long)rbp);
        if ((*(rbp+1) > (unsigned long)&_init)&&(*(rbp+1) < (unsigned long)&_fini))
        {
            pc[rip_len] = *(rbp+1);
            bp[rip_len] = *rbp;
            //printf("\n #### found sp3:%016lx %016lx",bp[rip_len],pc[rip_len]);
            rip_len++;

            if (rip_len >= max)
            {
                //printf("\n #### rip_len max,break!");
                break;
            }
        }
        else
        {
            //printf("\n #### lr invalid,break!, %016lx",*(rbp+1));
            break;
        }

        if (((*rbp & 0x7) == 0)&&\
            (*rbp - (unsigned long)rbp > 4*1024))
        {
            //printf("\n #### bp invalid,break!, %016lx %016lx",*rbp,(unsigned long)rbp);
            break;
        }

        rbp = (unsigned long *)(*rbp);
    }

    return rip_len;
}

unsigned int cm_get_callstack_bysp(unsigned long *rsp, unsigned long *pc, unsigned long *bp,unsigned long max)
{
    unsigned long *rbp,rip_len;

    rip_len = 0;
    rbp = (unsigned long *)(*rsp);
    //根据rbp，跳跃式找下一个【栈基址 + 返回指令地址】数据结构
    for(;((rbp > rsp)&&((unsigned long)rbp < (unsigned long)rsp + 32*1024));)
    {
        //printf("\n #### %d %016lx",__LINE__,rbp);
        if ((*(rbp+1) > (unsigned long)&_init)&&(*(rbp+1) < (unsigned long)&_fini))
        {
            pc[rip_len] = *(rbp+1);
            bp[rip_len] = *rbp;
            //printf("\n #### found sp3:%016lx %016lx",rbp,rip_array[rip_len]);
            rip_len++;

            if (rip_len >= max)
            {
                //printf("\n #### rip_len max,break!");
                break;
            }
        }
        else
        {
            //printf("\n #### lr invalid,break!, %016lx",*(rbp+1));
            break;
        }

        if (((*rbp & 0x7) == 0)&&\
            (*rbp - (unsigned long)rbp > 4*1024))
        {
            //printf("\n #### bp invalid,break!, %016lx %016lx",*rbp,(unsigned long)rbp);
            break;
        }

        rbp = (unsigned long *)(*rbp);
    }

    return rip_len;
}


//pc: 保存指令地址的指针数组 ，bp: 保存函数栈的指针数组， max:数组长度
unsigned int cm_get_callstack_self(unsigned long *pc, unsigned long *bp,unsigned long max)
{
    unsigned long rip_len,i;
    unsigned long *rsp = (unsigned long *)EOS_GetCurrentFp();

    cm_get_callpc_bysp(rsp,pc,bp,0);

    for (i = 0; i < 32; i ++)
    {
        //printf("\n %016lx: %016lx %016lx %016lx %016lx",
            //(unsigned long)rsp+ 4*i,*(rsp+ 4*i),*(rsp+ 4*i+1),*(rsp+ 4*i+2),*(rsp+ 4*i+3));
    }

    rsp = (unsigned long *)*rsp;

    rip_len = 1;
    rip_len = rip_len + cm_get_callstack_bysp(rsp,pc+1,bp+1,max-1);

    for(i=0;i<rip_len;i++)
    {
        //printf("\n %016lx  %016lx",bp[i],pc[i]);
    }

    return rip_len;
}

void EOS_GetCallersPC( unsigned long *pulAddrArray, unsigned long ulArrayNum )
{
    unsigned long bp[16];

    (void)cm_get_callstack_self(pulAddrArray,bp,ulArrayNum>16? 16:ulArrayNum);
}

unsigned int cm_get_callpc_bysp(unsigned long *rsp, unsigned long *pc, unsigned long *bp, unsigned long *addr)
{
    unsigned long *pstackdata;

    for (pstackdata = (unsigned long *)rsp; (unsigned long)pstackdata < (unsigned long)rsp + 4*1024; pstackdata ++)
    {
        //按地址顺序搜索函数栈里的第一个【栈基址 + 返回指令地址】数据结构
        if ((*(pstackdata+1) > (unsigned long)&_init)&&(*(pstackdata+1) < (unsigned long)&_fini))
        {
            //指令地址有效
            if ((*pstackdata > (unsigned long)pstackdata)&&(*pstackdata < (unsigned long)pstackdata + 4*1024))
            {
                //栈基址有效 ，匹配【栈基址 + 返回指令地址】数据结构，
                //break之后按照栈基址跳跃式找下一个【栈基址 + 返回指令地址】数据结构
                *pc = *(pstackdata+1);
                *bp = *pstackdata;
                if (addr)
                    *addr = *(pstackdata+7);
                //printf("#### found sp1:%016lx %016lx",*pc,*bp);
                return 1;
            }
        }
    }

    *pc = 0;
    *bp = 0;
    return 0;
}

void cm_signal(int signal_id, siginfo_t * p, void * pv)
{
    unsigned long * sp,i,rip_len,rip_array[32],rbp_array[32],addr,*paddr;
    char buff[128],len,date[32];
    time_t tt = time(0);

    addr = 0;
    if ((signal_id == SIGSEGV)||\
        (signal_id == SIGBUS))
    {
        paddr = &addr;
    }
    else
    {
        paddr = 0;
    }

	//产生“YYYY-MM-DD hh:mm:ss”格式的字符串。
	memset(date,0,sizeof(date));
	i = strftime(date, sizeof(buff), "%Y-%m-%d %H:%M:%S", localtime(&tt));

    sp = (unsigned long *)EOS_GetCurrentFp();
    syslog(LOG_INFO,"cm_signal %d",signal_id);
    len = sprintf(buff,"\n at %s program(build time %s %s) catch signal %d sp=%lx bp=%lx",
                        date,__DATE__,__TIME__,signal_id,(unsigned long)sp,*sp);
    printf(buff);
    write(exception_logfile,buff,len);
    for (i = 0; i < 32; i ++)
    {
        len = sprintf(buff,"\n %016lx: %016lx %016lx %016lx %016lx",
            (unsigned long)sp+ 4*i,*(sp+ 4*i),*(sp+ 4*i+1),*(sp+ 4*i+2),*(sp+ 4*i+3));
        printf(buff);
        write(exception_logfile,buff,len);
    }

    cm_get_callpc_bysp(sp,&rip_array[0],&rbp_array[0],paddr);

    sp = (unsigned long *)*sp;
    write(exception_logfile,buff,len);
    for (i = 0; i < 32; i ++)
    {
        len = sprintf(buff,"\n %016lx: %016lx %016lx %016lx %016lx",
            (unsigned long)sp+ 4*i,*(sp+ 4*i),*(sp+ 4*i+1),*(sp+ 4*i+2),*(sp+ 4*i+3));
        printf(buff);
        write(exception_logfile,buff,len);
    }

    rip_len = cm_get_callstack_bysp(sp,&rip_array[1],&rbp_array[1],sizeof(rip_array)/sizeof(rip_array[0]) - 1);
    len = sprintf(buff,"\n call stack: ");
    printf(buff);
    write(exception_logfile,buff,len);
    for(i=0;i<rip_len;i++)
    {
        len = sprintf(buff,"\n %016lx  %016lx",rbp_array[i],rip_array[i]);
        printf(buff);
        write(exception_logfile,buff,len);
    }

    if (paddr)
    {
        len = sprintf(buff,"\n write or read addr:%016lx",addr);
        printf(buff);
        write(exception_logfile,buff,len);
    }

    len = sprintf(buff,"\n ---------------------------------------------- \n");
    printf(buff);
    write(exception_logfile,buff,len);

    exit(0);
}




/* not implemented in this environment */
void cm_dump_registers(void)
{
	return;
}

/* call abort(), it will generate a coredump if enabled */
void _cm_panic(const char *funcname, const char *format, ...)
{
    int n;
    char buf[4096];
	va_list ap;

    ros_bzero((void *)buf, 4096);

	LOG(CM, ERR, "PANIC in %s():", funcname);
	va_start(ap, format);
    n = vsnprintf(buf, 4096, format, ap);
	va_end(ap);
    if (n >= 4096) {
        printf("%s(%d) Buf(%d) exceeds the specified range(%d)! \r\n",
            __FUNCTION__, __LINE__, n, 4096);
        return;
    }
	LOG(CM, ERR, "%s", buf);
	cm_dump_stack();
	cm_dump_registers();
	abort();
}

void cm_print_data(char *data, int size)
{
	int loop;
    unsigned char printbuf[100];
    int buflen;

    if (data == NULL)
    {
    	LOG(CM, DEBUG, "data is NULL, size %d bytes",size);
        return;
    }

	LOG(CM, DEBUG, " Printing %d bytes @ %p",size, data);
    buflen = 0;
	for(loop = 0; loop < size; loop++)
	{
        if (!buflen)
            buflen += sprintf((char *)printbuf + buflen, "%08d:", loop);

        buflen += sprintf((char *)printbuf + buflen, " %02x",
                            (unsigned char)data[loop]);
		if((loop & 0xf) == 0xf) {
            printbuf[buflen] = 0;
            PLog_Raw(CM, DEBUG, "%s\r\n", printbuf);
            buflen = 0;
		}
	}
    printbuf[buflen] = 0;
    if (buflen)
        PLog_Raw(CM, DEBUG, "%s\r\n", printbuf);
}

