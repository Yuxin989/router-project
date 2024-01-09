create database if not exists network;

use network;

create table if not exists Host_IPMAC(
    ip varchar(32) primary key,
    mac varchar(32)
);

create table if not exists NetPort_NAMEIPMAC(
    name varchar(32) primary key,
    ip varchar(32),
    mac varchar(32)
);