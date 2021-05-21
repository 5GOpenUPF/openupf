/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/un.h>
#include <stdarg.h>
#include <stdio.h>
#include <termios.h>
#include <sched.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include "cli.h"


#define MAXDATASIZE 2200

void set_input_mode(int fd)
{

    struct termios stTerm;
    tcgetattr(fd,&stTerm);

    //设置为非加工模式
    stTerm.c_lflag &= ~(ICANON|ECHO|ISIG);
    //至少读一个字符
    stTerm.c_cc[VMIN]=1;
    stTerm.c_cc[VTIME]=0;
    if(!isatty(fd))
    {
            printf("fd=%d is not a tty\n",fd);
            return;
    }
    tcsetattr(fd,TCSANOW,&stTerm);

}

#define PRINT_HELP()   printf("please choice smu|lbu|fpu|stub \n");
int main(int argc,char *argv[])
{
    int sockfd, num;    /* files descriptors */

    struct sockaddr_in server;
    int rv;
    fd_set rset;
    int maxfd;
    char buf[MAXDATASIZE];    /* buf will store received text */

    if (argc < 2)
    {
        PRINT_HELP();
        return -1;
    }
    else
    {
        if ((strcmp(argv[1],"smu"))&&\
            (strcmp(argv[1],"lbu"))&&\
            (strcmp(argv[1],"fpu"))&&\
            (strcmp(argv[1],"stub")))
        {
            PRINT_HELP();
            return -1;
        }
    }

    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0,sizeof(cpu_set_t), &mask);

    if((sockfd=socket(AF_INET,SOCK_STREAM, 0))==-1)
    {
        printf("socket(SOCK_STREAM) error\n");
        return -1;
    }

    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;

    if (0 == strcmp(argv[1],"smu"))
    {
        server.sin_port = htons(CLI_SMU_PORT);
    }
    else if (0 == strcmp(argv[1],"lbu"))
    {
        server.sin_port = htons(CLI_LBU_PORT);
    }
    else if (0 == strcmp(argv[1],"fpu"))
    {
        server.sin_port = htons(CLI_FPU_PORT);
    }
    else if (0 == strcmp(argv[1],"stub"))
    {
        server.sin_port = htons(CLI_STUB_PORT);
    }
    else
    {
        PRINT_HELP();
        return -1;
    }

    if (argc >= 3)
    {
        num = 0;
        num = strtol(argv[2], NULL, 10);
        if ( num >= 2 )
        {
            server.sin_port = htons(ntohs(server.sin_port) + (num-1) * 10);
        }
    }

    server.sin_addr.s_addr= htonl(INADDR_ANY);
    if(connect(sockfd, (struct sockaddr *)&server, sizeof(server))==-1)
    {
        printf("connect() to cli server error: %s\n",strerror(errno));
        return -1;
    }

    //char str[128] = "show ip";
    //write(sockfd,"\n",1);

    set_input_mode(STDIN_FILENO);
    while(1)
    {
        FD_ZERO(&rset);
        FD_SET(sockfd, &rset);
        FD_SET(STDIN_FILENO,&rset);
        maxfd = sockfd;
        rv =  select (maxfd + 1, &rset, NULL, NULL, NULL);
        if (rv < 0)
        {
            printf( "select form cli server returned error %s\n", strerror(errno));
            continue;
        }

        if (FD_ISSET (sockfd, &rset))
        {
            if((num=recv(sockfd,buf,MAXDATASIZE,0))==-1)
            {
                printf("recv() form cli server error\n");
                return -1;
            }
            write(STDOUT_FILENO,buf,num);
        }

        if(FD_ISSET (STDIN_FILENO, &rset))
        {
            unsigned char c;
            read(STDIN_FILENO, &c, 1);
            if((num=write(sockfd,&c,1))==-1)
            {
                printf("send() to cli server error\n");
                return -1;
            }
        }
    }

    close(sockfd);
    return 0;
}

