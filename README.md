# 路由器项目

#### 介绍

路由器项目，实现两个网段间通信。

1、收包
2、icmp转发，icmp目的ip解析，查看有无mac。有mac---修改源mac和目的mac，转发无mac---发arp请求
3、arp保存(源ip和源mac保存数据库，要求无重复
4、发arp广播(选用)
5、查看arp缓存功能(线程1: showarp)
6、防火墙(线程1:setip)

#### 安装教程

```linux
make
./demo
```