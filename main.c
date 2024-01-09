#include "get_interface.h"
#include "fun.h"

// 主函数：连接数据库并获取网卡接口名字、ip、地址
int main(int argc, char const *argv[])
{
    // 初始化数据库
    MYSQL mysql;
    MYSQL *sql = mysql_init(&mysql);
    if (sql == NULL)
    {
        printf("mysql_init error\n");
        exit(-1);
    }
    // 连接数据库
    sql = mysql_real_connect(sql, "10.9.42.212", "root", "111111", "network", 3306, NULL, 0);
    if (sql == NULL)
    {
        printf("mysql_real_connect error\n");
        exit(-1);
    }

    // 获取网卡信息 插入数据库
    NIC_information(sql);

    // 收发数据
    pthread_t pth;
    pthread_create(&pth, NULL, recv_send, (void *)sql);

    pthread_t pth_arp;
    pthread_create(&pth_arp, NULL, printf_Host_IPMAC, (void *)sql);

    pthread_join(pth, NULL);
    pthread_join(pth_arp, NULL);

    mysql_close(sql);
    return 0;
}
