#!/bin/bash

#-----------------------------------------------------------
# author：Yang2635
# blog_site：https://www.yfriend.xyz
# slogan：初次见面，欢迎来访！
# 
# 脚本仅适配了CentOS、Debian、Ubuntu系统
#-----------------------------------------------------------------

#Basic Info
User=$(whoami)
User_id=$(id | sed "s/[(][^)]*[)]//g" | awk '{print $1"，"$2"，"$3}')
Disk=$(df -h / | sed '1d' | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4,"，百分比："$5}' | tr -d " ")
Inode=$(df -i / | sed '1d' | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4,"，百分比："$5}' | tr -d " ")
Memory=$(free -gh | awk '/^(Mem|内存)/{print "总内存："$2,"，已使用："$3,"，剩余："$4}' | tr -d " ")
Swap=$(free -gh | awk '/^(Swap|交换)/{print "总存储："$2,"，已使用："$3,"，剩余："$4}' | tr -d " ")
Temp=$(du -sh /tmp 2>/dev/null | cut -f1)
Load_average=$(cat /proc/loadavg | awk '{print "1分钟："$1,"，5分钟："$2,"，15分钟："$3}')
Login_Users=$(users | wc -w)
Login_IP=$(who /var/log/wtmp | sed -n '$p' | sed  "s/[()]//g" | awk '{print $NF}')
System_Users="系统共有 `cat /etc/passwd  | wc -l` 个用户"

#System Release
Hostnamectl_Test=$(hostnamectl 2>/dev/null)
if [ -z "$Hostnamectl_Test" ];then
	Static_Hostname="未知的操作系统或脚本未适配该系统！"
	System="未知的操作系统或脚本未适配该系统！"
	Kernel="未知的操作系统或脚本未适配该系统！"
	Release="未知的操作系统或脚本未适配该系统！"
else
	Static_Hostname=$(hostnamectl 2>/dev/null | grep "Static" | awk -F ': ' '{print $2}')
	System=$(hostnamectl 2>/dev/null | grep "System" | awk -F ': ' '{print $2}')
	Kernel=$(hostnamectl 2>/dev/null | grep "Kernel" | awk -F ': ' '{print $2}')

	System_info=$(hostnamectl 2>/dev/null | awk -F ': ' '/System/{print $2}'| awk '{print $1}')
	if [  "$System_info" == "CentOS" ];then
		Release=$(cat /etc/redhat-release 2>/dev/null | awk '{print $(NF-1)}')
	elif [[ "$System_info" == "Debian"  ||  "$System_info" == "Ubuntu" ]];then
		Release=$(cat /etc/os-release | tr -d "\"" | awk -F '=' '/^VERSION=/{print $2}')
	else
		Release="未知的操作系统或脚本未适配该系统！"
	fi
fi

#Architecture
System_Bit=$(getconf LONG_BIT)
if [ "$System_Bit" == "64" ];then
	Architecture="64位"
elif [ "$System_Bit" == "32" ];then
	Architecture="32位"
else
	Architecture="未知系统位数！"
fi



#SELinux检测
SELinux_Test=$(getenforce 2>/dev/null)
if [ "$SELinux_test"];then
	SELinux_Result="未检测到SELinux！"
elif [ "$SELinux_Test" == "Permissive" ];then
	SELinux_Result="SELinux已临时关闭！"
elif [ "$SELinux_Test" == "Enforcing" ];then
	SELinux_Result="SELinux已开启！"
elif [ "$SELinux_Test" == "Disabled" ];then
	SELinux_Result="SELinux已永久关闭！"
elif [ -z "$SELinux_test" ];then
	SELinux_Result="未找到SELinux信息！"
fi

#System Allow Login User
Shadow_Test=$(cat /etc/shadow 2>/dev/null)
if [ -z "${Shadow_Test}" ];then
	Allow_Login="您没有权限查看可登录系统的用户数！"
else
	Allow_LoginUserNum=$(cat /etc/shadow | awk -F ':' '!/(\*|!!)/{print $1}' | wc -w)
	#Allow_LoginUser=$(cat /etc/shadow | awk -F ':' '!/(\*|!!)/{print $1}' | awk  '{for(i=1;i<=NR;i++)printf $i" "}')
	Allow_Login="有 ${Allow_LoginUserNum} 个可登录终端的用户！"
fi


#Time
Date=$(date "+%Y-%m-%d %H:%M:%S")

#CPU INFO
CPU_Num=$(cat /proc/cpuinfo | grep "name" | cut -f2 -d ':' | uniq | wc -l)
if [ $CPU_Num -eq 1 ];then
	CPU_Info=$(cat /proc/cpuinfo | grep "name" | awk -F ': ' '{print $2}' | uniq)
else
	CPU_Info=$(cat /proc/cpuinfo | grep "name" | uniq | sed -n '1,$p' | awk -F ': ' '{print $2" | "}' | tr -d "\n")
fi

CPU_PhysicalCoreNum=$(cat /proc/cpuinfo | grep "physical id" | sort | uniq | wc -l)
CPU_CoreNum=$(cat /proc/cpuinfo | grep "cpu cores" | uniq | awk -F ': ' '{print $2}')
CPU_ThreadNum=$(cat /proc/cpuinfo | grep "^processor"| wc -l)

#System Load
Uptime=$(cat /proc/uptime | cut -f1 -d.)
Run_Day=$((Uptime/60/60/24))
Run_time_hour=$((Uptime/60/60%24))
Run_time_mins=$((Uptime/60%60))
Run_time_Secs=$((Uptime%60))

#Process
Process=$(echo "正在运行 "`ps -A | wc -l`" 个进程")
Max_Proc=$(/sbin/sysctl -n kernel.pid_max 2>/dev/null)

#home分区
Home=$(df -h | grep "/home" 2>/dev/null)
if [ -z "$Home" ];then
	Disk_Home="home目录非独立挂载！"
else
	Disk_Home=$(df -h | grep "/home" | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4,"，百分比："$5}' | tr -d " ")
fi

#eth0网卡流量与IO流量
Ifconfig_test=$(ifconfig &>/dev/null;echo $?)
Ifconfig_eth0=$(ifconfig eth0 &>/dev/null;echo $?)

if [ $Ifconfig_test -eq 0 ] && [ $Ifconfig_eth0 -eq 0 ];then
	Network_eth0=$(ifconfig eth0 | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
	Network_lo=$(ifconfig lo | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
elif [ $Ifconfig_test -eq 0 ] && [ $Ifconfig_eth0 -ne 0 ];then
	Network_eth0="eth0网卡设备未找到！"
	Network_lo=$(ifconfig lo | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
elif [ $Ifconfig_test -ne 0 ];then
	if [ "$System_info" == "CentOS" ];then
		yum install net-tools -y &>/dev/null
		if [ $(echo $?) -eq 0 ] && [ $(ifconfig eth0 &>/dev/null;echo $?) -eq 0 ];then
			Network_eth0=$(ifconfig eth0 | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
			Network_lo=$(ifconfig lo | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
		elif [ $(echo $?) -eq 0 ] && [ $(ifconfig eth0 &>/dev/null;echo $?) -ne 0 ];then
			Network_eth0="net-tools工具安装成功但eth0网卡设备未找到！"
			Network_lo=$(ifconfig lo | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
		else
			Network_eth0="net-tools工具安装失败！"
			Network_lo="net-tools工具安装失败！"
		fi
	elif [[ "$System_info" == "Debian"  ||  "$System_info" == "Ubuntu" ]];then
		apt install net-tools -y &>/dev/null
		if [ $(echo $?) -eq 0 ] && [ $(ifconfig eth0 &>/dev/null;echo $?) -eq 0 ];then
			Network_eth0=$(ifconfig eth0 | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
			Network_lo=$(ifconfig lo | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
		elif [ $(echo $?) -eq 0 ] && [ $(ifconfig eth0 &>/dev/null;echo $?) -ne 0 ];then
			Network_eth0="net-tools工具安装成功但eth0网卡设备未找到！"
			Network_lo=$(ifconfig lo | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
		else
			Network_eth0="net-tools工具安装失败！"
			Network_lo="net-tools工具安装失败！"
		fi
	fi
fi

#Private IP address
Network_IP=$(/sbin/ip route get 8.8.8.8 | head -1 | cut -d' ' -f7)

#MySQL
Mysql_Path=$(which mysql 2>/dev/null)
if [ -z $Mysql_Path ];then
	MySQL_version="MySQL未安装！"
else
	MySQL_version=$($Mysql_Path --version 2>/dev/null | awk '{print $3,$4,$5}' | tr -d ",")
fi

#Nginx
Nginx_Path=$(which nginx 2>/dev/null)
if [ -z $Nginx_Path ];then
	Nginx_version="Nginx未安装！"
else
	Nginx_version=$($Nginx_Path -v 2>&1 | awk -F ': '  '{print $2}')
fi

#PHP
PHP_Path=$(which php 2>/dev/null)
if [ -z $PHP_Path ];then
	PHP_version="PHP未安装！"
else
	PHP_version=$($PHP_Path -v | head -1 | awk '{print $2}')
fi

#JAVA
JAVA_Path=$(which java 2>/dev/null)
if [ -z $JAVA_Path ];then
	Java_version="JAVA未安装！"
else
	Java_version=$($JAVA_Path -version 2>&1 | awk -F '"' '{print $2}' | tr -d "\n")
fi

echo -e "
 Welcome to this services！The following is the Device Information：\n
 ===================================================================\n
     当前登录用户：${User}
       当前用户id：${User_id}
   当前登录用户数：${Login_Users} User(s)
     系统用户统计：${System_Users}，${Allow_Login}
           私网IP：${Network_IP}
      SELinux信息：${SELinux_Result}
   系统静态用户名：${Static_Hostname}
         系统版本：${System}
       系统版本号：${Release}
     系统内核版本：${Kernel}
            Nginx：${Nginx_version}
            MySQL：${MySQL_version}
              PHP：${PHP_version}
             JAVA：${Java_version}
          CPU型号：${CPU_Info}
      CPU个数信息：${CPU_PhysicalCoreNum} 个物理CPU，每个物理CPU有 ${CPU_CoreNum} 个物理核心数，共 ${CPU_ThreadNum} 个线程
         系统位数：${Architecture}
         eth0流量：${Network_eth0}
           lo流量：${Network_lo}
         系统负载：${Load_average}
           主磁盘：${Disk}
         home分区：${Disk_Home}
        Inode信息：${Inode}
 临时文件目录已用：${Temp}
             内存：${Memory}
     Swap虚拟内存：${Swap}
             进程：${Process}
   系统最大进程数：${Max_Proc}
       系统已运行：${Run_Day} 天 ${Run_time_hour} 小时 ${Run_time_mins} 分钟 ${Run_time_Secs} 秒
     当前登录时间：${Date}
   当前您登录的IP：${Login_IP}
 \n ===================================================================\n"
