#ifndef _FUN_H_
#define _FUN_H_

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <pthread.h>

#include "get_interface.h"

// arp请求包结构体：源ip，源mac，目的ip，目的mac。
typedef struct arpIpMac
{
    unsigned char ar_sha[ETH_ALEN];
    unsigned char ar_sip[4];
    unsigned char ar_tha[ETH_ALEN];
    unsigned char ar_tip[4];
} arpIpMac_t;

// 函数声明
// 收发数据
extern void *recv_send(void *arg);
// 获取网卡信息 插入数据库
extern void NIC_information(MYSQL *sql);
// 给所有主机发送arp请求广播获取主机ip和mac
extern void send_arp(MYSQL *sql, char *ip);
// 向数据库表Host_IPMAC插入数据
extern void insert_host(MYSQL *sql, char *ip, char *mac);
// 收到icmp用目的ip在数据库查找目的mac
extern void select_dstmac(MYSQL *sql, char *ip, char *mac);
// 向数据库表NetPort_NAMEIPMAC插入数据
extern void insert_netport(MYSQL *sql, char *name, char *ip, char *mac);
// 收到目的ip在数据库中查找网卡name
extern void select_netName(MYSQL *sql, char *ip, char *name, char *mac);

extern void ip_string_to_array(const char *ip_string, unsigned char *ip_array);
extern void replaceString(char *str);
// 输出数据库ARP缓存表
extern void *printf_Host_IPMAC(void *arg);

#endif