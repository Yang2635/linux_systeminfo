#!/bin/bash
PATH="$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin"
export PATH
################ Print System Info ########################
# author：Yang2635
# blog_site：https://www.yfriend.xyz
#
# Github：https://github.com/Yang2635/linux_systeminfo
#
############################################################

# GetPackManager
if [ -f "/usr/bin/yum" ] && [ -f "/etc/yum.conf" ];then
	PM="yum"
elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ];then
	PM="apt-get"
fi

#Basic Info
User=$(whoami)
User_id=$(id | sed "s/[(][^)]*[)]//g" | awk '{print $1"，"$2"，"$3}')
Disk=$(df -h / | sed '1d' | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4,"，百分比："$5}' | tr -d " ")
Inode=$(df -i / | sed '1d' | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4,"，百分比："$5}' | tr -d " ")
Memory=$(free -gh | grep -E "^Mem|^内存" | tr -d 'i' | awk '{print "总量："$2"，已使用："$3"，剩余："$4"\n\t\t   shared："$5"，buff/cache："$6"，available："$7}')
Swap=$(free -gh | grep -E "^Swap|^交换" | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4}' | tr -d " |i")
Temp=$(du -sh /tmp 2>/dev/null | cut -f1)
Load_average=$(awk '{print "1分钟："$1,"，5分钟："$2,"，15分钟："$3}' /proc/loadavg)
Login_Users=$(users | wc -w)
Login_IP=$(who /var/log/wtmp |  sed -n '$p' | sed  "s/[()]//g" | awk '{print $NF}')
System_Users="系统共有 `cat /etc/passwd  | wc -l` 个用户"

#System Release
Hostnamectl_Test=$(hostnamectl 2>/dev/null)
Kernel=$(uname -sr)
if [ -z "$Hostnamectl_Test" ];then
	Static_Hostname="未知的系统静态用户名或脚本未适配该系统！"
	System="未知的系统版本或脚本未适配该系统！"
	Release="未知的系统版本号或脚本未适配该系统！"
	Virtualization="未知的系统所使用的虚拟平台或脚本未适配该系统！"
else
	Static_Hostname=$(echo -e "${Hostnamectl_Test}\n" | grep "Static" | awk -F ': ' '{print $2}')
	System=$(echo -e "${Hostnamectl_Test}\n" | grep "System" | awk -F ': ' '{print $2}')
	System_info=$(echo -e "${Hostnamectl_Test}\n" | awk -F ': ' '/System/{print $2}'| awk '{print $1}')
	if [  "${PM}" == "yum" ];then
		Release=$(awk '{print $(NF-1)}' /etc/redhat-release)
	elif [ "${PM}" == "apt-get" ];then
		Release=$(cat /etc/os-release | tr -d "\"" | awk -F '=' '/^VERSION_ID=/{print $2}')
	else
		Release="未知的操作系统或脚本未适配该系统！"
	fi
	Virtualization_Test=$(echo -e "${Hostnamectl_Test}\n" | grep "Virtualization" 2>/dev/null )
	if [ -z "$Virtualization_Test" ];then
		Virtualization="未检测到当前系统所用虚拟平台！"
	else
		Virtualization=$(echo -e "${Hostnamectl_Test}\n" | awk -F ': ' '/Virtualization/{print $2}')
	fi
fi

#Architecture
System_Bit="`getconf LONG_BIT` 位操作系统"

#SELinux检测
SELinux_Test=$(getenforce 2>/dev/null)
if [ -z "$SELinux_Test" ];then
	SELinux_Result="未检测到SELinux！"
elif [ "$SELinux_Test" == "Permissive" ];then
	SELinux_Result="SELinux已临时关闭！"
elif [ "$SELinux_Test" == "Enforcing" ];then
	SELinux_Result="SELinux已开启！"
elif [ "$SELinux_Test" == "Disabled" ];then
	SELinux_Result="SELinux已永久关闭！"
fi

#System Allow Login User
Shadow_Test=$(cat /etc/shadow 2>/dev/null)
if [ -z "${Shadow_Test}" ];then
	Allow_Login="您没有权限查看可密码登录终端系统的用户数与用户！"
else
	Allow_LoginUserNum=$(awk -F ':' '$2~/^\$.*\$/{print $1}' /etc/shadow | wc -w)
	Allow_LoginUser=$(awk -F ':' '$2~/^\$.{*\$/{print $1}' /etc/shadow | xargs)
	Allow_Login="有 ${Allow_LoginUserNum} 个可密码登录终端的用户！分别是：${Allow_LoginUser}"
fi


#Time
Date=$(date "+%Y-%m-%d %H:%M:%S")

#CPU INFO
CPU_Num=$(grep "name" /proc/cpuinfo | cut -f2 -d ':' | uniq | wc -l)
if [ $CPU_Num -eq 1 ];then
	CPU_Info=$(grep "name" /proc/cpuinfo | awk -F ': ' '{print $2}' | uniq)
else
	CPU_Info=$(grep "name" /proc/cpuinfo | uniq | sed -n '1,$p' | awk -F ': ' '{print $2" |"}' | xargs)
fi

CPU_PhysicalCoreNum=$(grep "physical id" /proc/cpuinfo | sort | uniq | wc -l)
CPU_CoreNum=$(grep "cpu cores" /proc/cpuinfo | uniq | awk -F ': ' '{print $2}')
CPU_ThreadNum=$(getconf _NPROCESSORS_ONLN)

#System Uptime
Uptime=$(cut -f1 -d. /proc/uptime)
Run_Day=$((Uptime/60/60/24))
Run_time_hour=$((Uptime/60/60%24))
Run_time_mins=$((Uptime/60%60))
Run_time_Secs=$((Uptime%60))

#Process
Process=$(echo "正在运行 `ps -A | wc -l` 个进程")
Max_Proc=$(sysctl -n kernel.pid_max 2>/dev/null)

#home分区
Home=$(df -h | grep "/home" 2>/dev/null)
if [ -z "$Home" ];then
	Disk_Home="home目录非独立挂载！"
else
	Disk_Home=$(echo "$Home" | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4,"，百分比："$5}' | tr -d " ")
fi

#eth0网卡流量与IO流量
Ifconfig_test=$(ifconfig &>/dev/null;echo $?)
Ifconfig_eth0=$(ifconfig eth0 &>/dev/null;echo $?)

Network_TrafficEth0(){
	Network_eth0=$(ifconfig eth0 | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
}
Network_TrafficLo(){
	Network_lo=$(ifconfig lo | tr -d "()" | awk '/bytes/{printf $(NF-1) " " $NF "|"}' | awk -F '|' '{print "已接收："$1,"，已发送："$2}')
}

if [ $Ifconfig_test -eq 0 ] && [ $Ifconfig_eth0 -eq 0 ];then
	Network_TrafficEth0
	Network_TrafficLo
elif [ $Ifconfig_test -eq 0 ] && [ $Ifconfig_eth0 -ne 0 ];then
	Network_eth0="eth0网卡设备未找到！"
	Network_TrafficLo
elif [ $Ifconfig_test -ne 0 ];then
	${PM} install net-tools -y &>/dev/null
	if [ $(echo $?) -eq 0 ] && [ $(ifconfig eth0 &>/dev/null;echo $?) -eq 0 ];then
		Network_TrafficEth0
		Network_TrafficLo
	elif [ $(echo $?) -eq 0 ] && [ $(ifconfig eth0 &>/dev/null;echo $?) -ne 0 ];then
		Network_eth0="net-tools工具安装成功但eth0网卡设备未找到！"
		Network_TrafficLo
	else
		Network_eth0="net-tools工具安装失败！"
		Network_lo="net-tools工具安装失败！"
	fi
fi

#Private IP address
Network_IP=$(ip route get 8.8.8.8 | head -1 | cut -d' ' -f7)

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
     系统用户统计：${System_Users}
 可密码登录用户数：${Allow_Login}
           私网IP：${Network_IP}
      SELinux信息：${SELinux_Result}
   系统静态用户名：${Static_Hostname}
         系统版本：${System}
       系统版本号：${Release}
     系统内核版本：${Kernel}
 系统所用虚拟平台：${Virtualization}
            Nginx：${Nginx_version}
            MySQL：${MySQL_version}
              PHP：${PHP_version}
             JAVA：${Java_version}
          CPU型号：${CPU_Info}
      CPU个数信息：${CPU_PhysicalCoreNum} 个物理CPU，每个物理CPU有 ${CPU_CoreNum} 个物理核心数，共 ${CPU_ThreadNum} 个线程
         系统位数：${System_Bit}
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