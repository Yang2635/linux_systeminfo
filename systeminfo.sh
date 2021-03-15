#!/bin/bash

User=$(whoami)
Disk=$(df -h | grep "/$" | awk '{print "总量："$2,"，已使用"$3,"，剩余："$4,"，使用百分比："$5}')
Memory=$(free -gh | grep "^Mem" | awk '{print "总内存："$2,"，已使用："$3,"，剩余："$4}')
Swap=$(free -gh | grep "^Swap" | awk '{print "总存储："$2,"，已使用："$3,"，剩余："$4}')
Temp=$(du -sh /tmp | cut -f1)
Load_average=$(cat /proc/loadavg | awk '{print "1分钟："$1,"，5分钟："$2,"，15分钟："$3}')
Login_Users=$(users | wc -w)
Release=$(cat /etc/redhat-release | awk '{print $(NF-1)}')
Uptime=$(cat /proc/uptime | cut -f1 -d.)
Date=$(date "+%Y-%m-%d %H:%M:%S")

#System Load
Run_Day=$((Uptime/60/60/24))
Run_time_hour=$((Uptime/60/60%24))
Run_time_mins=$((Uptime/60%60))
Run_time_Secs=$((Uptime%60))

Static_Hostname=$(hostnamectl | grep "Static" | awk -F ': ' '{print $2}')
System=$(hostnamectl | grep "System" | awk -F ': ' '{print $2}')
Kernel=$(hostnamectl | grep "Kernel" | awk -F ': ' '{print $2}')
Process=$(echo "正在运行 "`ps -Afl | wc -l`" 个进程")
Max_Proc=$(/sbin/sysctl -n kernel.pid_max 2>/dev/null)

if [ $(hostnamectl | grep "Architecture" | awk -F ': ' '{print $2}')==x86-64 ];then
Architecture="64位"
else
Architecture="32位"
fi

if [ $(ifconfig &>/dev/null;echo $?) -eq 0 ];then
	Network_Pack=$(ifconfig eth0 | grep "packets" | awk '{print $5}'| awk '{printf  ("%.3f\n",$1/1024/1024/1024)}' | awk '{printf $1 " " }' | awk '{print "已接收："$1" GiB""，已发送："$2" GiB"}')
else
	yum install -y net-tools &>/dev/null
	if [ $(echo $?) -eq 0 ];then
		Network_Pack=$(ifconfig eth0 | grep "packets" | awk '{print $5}'| awk '{printf  ("%.3f\n",$1/1024/1024/1024)}' | awk '{printf $1 " " }' | awk '{print "已接收："$1" GiB""，已发送："$2" GiB"}')
	else
		Network_Pack="未找到ifconfig命令或net-tools工具未安装！"
	fi
fi

Network_IP=$(/sbin/ip route get 8.8.8.8 | head -1 | cut -d' ' -f7)

#MySQL
Mysql_Path=$(which mysql 2>/dev/null)
if [ -z $Mysql_Path ];then
	MySQL_version="MySQL数据库未安装！"
else
	MySQL_version=$($Mysql_Path --version 2>/dev/null | awk '{print $3" "$4" "$5;}' | tr -d ",")
fi

#Nginx
Nginx_Path=$(which nginx 2>/dev/null)
if [ -z $Nginx_Path ];then
	Nginx_version="Nginx未安装！"
else
	Nginx_version=$($Nginx_Path -v 2>&1 | awk '{print $3}' | tr -d " ")
fi

#PHP
PHP_Path=$(which php 2>/dev/null)
if [ -z $PHP_Path ];then
	PHP_version="PHP未安装！"
else
	PHP_version=$($PHP_Path -v | head -1 | awk '{print $2}' | tr -d " ")
fi

#JAVA
JAVA_Path=$(which java 2>/dev/null)
if [ -z $JAVA_Path ];then
	Java_version="JDK未安装！"
else
	Java_version=$($JAVA_Path -version 2>&1 | awk -F '"' '{print $2}'|tr -d "\n")
fi

echo -e "
 Welcome to this services！The following is the Device Information：\n
 ===================================================================\n
     当前登录用户：${User}
   当前登录用户数：${Login_Users} User(s)
           私网IP：${Network_IP}
   系统静态用户名：${Static_Hostname}
         系统版本：${System}
       系统版本号：${Release}
     系统内核版本：${Kernel}
            Nginx：${Nginx_version}
            MySQL：${MySQL_version}
              PHP：${PHP_version}
             JAVA：${Java_version} 
     当前系统位数：${Architecture}
     eth0网卡收发：${Network_Pack}
     当前系统负载：${Load_average}
             磁盘：${Disk}
 临时文件目录已用：${Temp}
             内存：${Memory}
     Swap虚拟内存：${Swap}
             进程：${Process}
   系统最大进程数：${Max_Proc}
       系统已运行：${Run_Day} 天 ${Run_time_hour} 小时 ${Run_time_mins} 分钟 ${Run_time_Secs} 秒
     当前登录时间：${Date}
 \n ===================================================================\n"

