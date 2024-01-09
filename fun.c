#include "fun.h"

// 收发数据
void *recv_send(void *arg)
{
    MYSQL *sql = (MYSQL *)arg;
    // 创建原始套接字
    int rawfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawfd < 0)
        perror("socket");

    // 接收数据
    unsigned char buf[1500] = "";
    int buflen = 0;
    unsigned short type = 0;
    unsigned char srcip[32] = "";
    unsigned char dstip[32] = "";
    unsigned char dstmac[32] = "";
    unsigned char net_name[32] = "";
    unsigned char net_mac[32] = "";
    int ret = 0;
    char cmd[128] = "";
    while (1)
    {
        bzero(buf, sizeof(buf));
        buflen = recv(rawfd, buf, sizeof(buf), 0);

        type = ntohs(*(unsigned short *)(buf + 12));
        if (type == 0x0800)
        {
            if (buf[23] == 1)
            {
                inet_ntop(AF_INET, (void *)(buf + 30), dstip, 16);
                select_dstmac(sql, dstip, dstmac);
                if (strcmp(dstmac, "") == 0)
                {
                    send_arp(sql, dstip);
                    continue;
                }
                replaceString(dstip);
                select_netName(sql, dstip, net_name, net_mac);
                // 指定出口
                struct ifreq ethreq;
                strncpy(ethreq.ifr_name, net_name, IFNAMSIZ);
                if (ioctl(rawfd, SIOCGIFINDEX, &ethreq) == -1)
                {
                    perror("icotl");
                    close(rawfd);
                    exit(-1);
                }
                struct sockaddr_ll sll;
                bzero(&sll, sizeof(sll));
                sll.sll_ifindex = ethreq.ifr_ifindex;
                sscanf(dstmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
                sscanf(net_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buf[6], &buf[7], &buf[8], &buf[9], &buf[10], &buf[11]);
                sendto(rawfd, buf, buflen, 0, (struct sockaddr *)&sll, sizeof(sll));
            }
            else
                continue;
        }
        else if (type == 0x0806)
        {
            // 提取源ip 源mac
            inet_ntop(AF_INET, (void *)(buf + 28), srcip, 16);
            sprintf(cmd, "%02x:%02x:%02x:%02x:%02x:%02x",
                    buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
            insert_host(sql, srcip, cmd);
        }
        else
            continue;
    }
    close(rawfd);
}

// 获取网卡信息 插入数据库
void NIC_information(MYSQL *sql)
{
    getinterface();
    int network_num = get_interface_num();

    char name[32] = "";
    char ip[32] = "";
    char mac[32] = "";

    for (int i = 0; i < network_num; i++)
    {
        sprintf(name, "%s", net_interface[i].name);
        sprintf(ip, "%d.%d.%d.%d", net_interface[i].ip[0], net_interface[i].ip[1], net_interface[i].ip[2], net_interface[i].ip[3]);
        sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                net_interface[i].mac[0], net_interface[i].mac[1], net_interface[i].mac[2],
                net_interface[i].mac[3], net_interface[i].mac[4], net_interface[i].mac[5]);
        insert_netport(sql, name, ip, mac);
    }
}

// 给所有主机发送arp请求广播获取主机ip和mac
void send_arp(MYSQL *sql, char *ip)
{
    int rawfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawfd < 0)
    {
        perror("socket");
        exit(-1);
    }
    char last_ip[32] = "";
    strcpy(last_ip, ip);
    replaceString(ip);
    unsigned char net_name[32] = "";
    unsigned char net_mac[32] = "";
    select_netName(sql, ip, net_name, net_mac);
    unsigned char last_netip[4];
    unsigned char netip[4];
    ip_string_to_array(last_ip, last_netip);
    ip_string_to_array(ip, netip);
    unsigned char arpbuf[42] = "";
    unsigned char mac_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char mac_0[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char mac_msg[6];
    sscanf(net_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_msg[0], &mac_msg[1], &mac_msg[2], &mac_msg[3], &mac_msg[4], &mac_msg[5]);
    // 指定出口
    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, net_name, IFNAMSIZ);
    if (ioctl(rawfd, SIOCGIFINDEX, &ethreq) == -1)
    {
        perror("icotl");
        close(rawfd);
        exit(-1);
    }
    struct sockaddr_ll sll;
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ethreq.ifr_ifindex;
    // 组装arp数据包
    // mac头
    struct ether_header *macHead = (struct ether_header *)arpbuf;
    memcpy(macHead->ether_dhost, mac_dst, 6);
    memcpy(macHead->ether_shost, mac_msg, 6);
    macHead->ether_type = htons(0x0806);
    // arp头
    struct arphdr *arpmsg = (struct arphdr *)(arpbuf + 14);
    arpmsg->ar_hrd = htons(ARPHRD_ETHER);
    arpmsg->ar_pro = htons(ETH_P_IP);
    arpmsg->ar_hln = 6;
    arpmsg->ar_pln = 4;
    arpmsg->ar_op = htons(ARPOP_REQUEST);
    struct arpIpMac *arpIM = (struct arpIpMac *)(arpbuf + 22);
    memcpy(arpIM->ar_sha, mac_msg, ETH_ALEN);
    memcpy(arpIM->ar_sip, netip, 4);
    memcpy(arpIM->ar_tha, mac_0, ETH_ALEN);
    memcpy(arpIM->ar_tip, last_netip, 4);
    // 发送arp数据包
    sendto(rawfd, arpbuf, 42, 0, (struct sockaddr *)&sll, sizeof(sll));
    close(rawfd);
}

// 向数据库表Host_IPMAC插入数据
void insert_host(MYSQL *sql, char *ip, char *mac)
{
    // 将源ip 源mac写入数据库
    // 源ip列设置主键约束 不存在则写入 存在则更新mac
    char cmd[128] = "";
    int ret = 0;
    sprintf(cmd, "insert into Host_IPMAC values('%s','%s');", ip, mac);
    ret = mysql_real_query(sql, cmd, strlen(cmd));
    if (ret == 0)
        ;
    else
    {
        sprintf(cmd, "update Host_IPMAC set mac = '%s' where ip = '%s';", mac, ip);
        ret = mysql_real_query(sql, cmd, strlen(cmd));
    }
}

// 收到icmp用目的ip在数据库查找目的mac
void select_dstmac(MYSQL *sql, char *ip, char *mac)
{
    char cmd[128] = "";
    int ret = 0;
    sprintf(cmd, "select * from Host_IPMAC where ip = '%s';", ip);
    // printf("ip = %s\n", ip);
    ret = mysql_real_query(sql, cmd, strlen(cmd));
    if (ret == 0)
    {
        MYSQL_RES *res = mysql_store_result(sql);
        if (res != NULL)
        {
            unsigned int col = mysql_num_fields(res);
            unsigned int row = mysql_num_rows(res);
            MYSQL_ROW row_msg;
            row_msg = mysql_fetch_row(res);
            if (row_msg == NULL)
                mac = "";
            else
            {
                strcpy(mac, (char *)row_msg[1]);
                // printf("mac = %s\n", mac);
            }
        }
        mysql_free_result(res);
    }
}

// 向数据库表NetPort_NAMEIPMAC插入数据
void insert_netport(MYSQL *sql, char *name, char *ip, char *mac)
{
    // 将网卡name ip mac写入数据库
    char cmd[128] = "";
    int ret = 0;
    sprintf(cmd, "insert into NetPort_NAMEIPMAC values('%s','%s','%s');", name, ip, mac);
    ret = mysql_real_query(sql, cmd, strlen(cmd));
    if (ret == 0)
        printf("network添加name/ip/mac成功!\n");
    else
        printf("此network已存在!\n");
}

// 收到目的ip在数据库中查找网卡name
void select_netName(MYSQL *sql, char *ip, char *name, char *mac)
{
    char cmd[128] = "";
    int ret = 0;
    sprintf(cmd, "select * from NetPort_NAMEIPMAC where ip like '%s.%%';", ip);
    ret = mysql_real_query(sql, cmd, strlen(cmd));
    if (ret == 0)
    {
        MYSQL_RES *res = mysql_store_result(sql);
        if (res == NULL)
        {
            perror("mysql_store_result");
            exit(-1);
        }
        unsigned int col = mysql_num_fields(res);
        unsigned int row = mysql_num_rows(res);
        MYSQL_ROW row_msg;
        row_msg = mysql_fetch_row(res);
        strcpy(name, (char *)row_msg[0]);
        strcpy(ip, (char *)row_msg[1]);
        strcpy(mac, (char *)row_msg[2]);
        mysql_free_result(res);
    }
}

void ip_string_to_array(const char *ip_string, unsigned char *ip_array)
{
    char *token = strtok((char *)ip_string, ".");
    int i = 0;
    while (token != NULL && i < 4)
    {
        int num = atoi(token);
        ip_array[i] = (unsigned char)num;
        token = strtok(NULL, ".");
        i++;
    }
}
void replaceString(char *str)
{
    int dotCount = 0;
    int i;

    for (i = 0; str[i] != '\0'; i++)
    {
        if (str[i] == '.')
        {
            dotCount++;
            if (dotCount == 3)
            {
                break;
            }
        }
    }

    if (dotCount == 3)
    {
        str[i] = '\0';
    }
}

// 输出数据库ARP缓存表 设置防火墙ip
void *printf_Host_IPMAC(void *arg)
{
    MYSQL *sql = (MYSQL *)arg;
    unsigned char ip[32] = "";
    unsigned char net_name[32] = "";
    unsigned char net_mac[32] = "";
    while (1)
    {
        char cmd[10] = "";
        printf("------------------------------------------------\n");
        printf("请输入: \n");
        printf("\tshowarp : 查看数据库arp缓存表\n");
        printf("\tsetip : 设置ip的访问限制\n");
        printf("------------------------------------------------\n");
        fgets(cmd, sizeof(cmd), stdin);
        cmd[strlen(cmd) - 1] = '\0';
        if (strcmp(cmd, "showarp") == 0)
        {
            char cmd[128] = "select * from Host_IPMAC;";
            mysql_real_query(sql, cmd, strlen(cmd));
            MYSQL_RES *res = mysql_store_result(sql);
            if (res != NULL)
            {
                system("clear");
                printf("数据库ARP: ip-mac缓存表\n");
                unsigned int col = mysql_num_fields(res);
                unsigned int row = mysql_num_rows(res);
                MYSQL_FIELD *col_name;
                while (col_name = mysql_fetch_field(res))
                    printf("\t%s\t", col_name->name);
                printf("\n");
                MYSQL_ROW row_con;
                while (row_con = mysql_fetch_row(res))
                {
                    for (int i = 0; i < col; i++)
                        printf("%s\t", (char *)row_con[i]);
                    printf("\n");
                }
            }
            mysql_free_result(res);
        }
        else if (strcmp(cmd, "setip") == 0)
        {
            char cmd[128] = "";
            system("clear");
            printf("----------------防火墙------------------\n");
            printf("请输入你的选择(1.禁ping某ip(网段禁ping)  2.解除禁ping): ");
            int choice = 0;
            scanf("%d", &choice);
            switch (choice)
            {
            case 1:
                printf("请输入要禁ping的ip: ");
                getchar();
                fgets(ip, sizeof(ip), stdin);
                ip[strlen(ip) - 1] = '\0';
                replaceString(ip);
                select_netName(sql, ip, net_name, net_mac);
                sprintf(cmd, "sudo ifconfig %s down", net_name);
                system(cmd);
                printf("该ip所在网段已禁ping! \n");
                break;

            case 2:
                printf("请输入要解除禁ping的ip: ");
                getchar();
                fgets(ip, sizeof(ip), stdin);
                ip[strlen(ip) - 1] = '\0';
                replaceString(ip);
                select_netName(sql, ip, net_name, net_mac);
                sprintf(cmd, "sudo ifconfig %s up", net_name);
                system(cmd);
                printf("该ip所在网段已解除禁ping! \n");
                break;
            }
        }
        getchar();
    }
}
