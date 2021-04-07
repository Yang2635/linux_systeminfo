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
if [ -f "/usr/bin/yum" ] && [ -f "/etc/yum.conf" ]; then
	PM="yum"
elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ]; then
	PM="apt-get"
fi

#User_Info
User=$(whoami)
User_id=$(id | sed "s/[(][^)]*[)]//g" | awk '{print $1"，"$2"，"$3}')
System_Users="系统共有 `cat /etc/passwd  | wc -l` 个用户"

#Disk_Info
Disk=$(df -h / 2>/dev/null | sed '1d' | awk '{printf("总量：%s，已使用：%s，剩余：%s，使用率：%s",$2,$3,$4,$5)}')
Inode=$(df -i -h / 2>/dev/null | sed '1d' | awk '{printf("总量：%s，已使用：%s，剩余：%s，使用率：%s",$2,$3,$4,$5)}')

Temp=$(du -sh /tmp 2>/dev/null | cut -f1)
Load_average=$(awk '{printf("1分钟：%s，5分钟：%s，15分钟：%s",$1,$2,$3)}' /proc/loadavg)

#System Run Level
System_RunLvel(){
if [[ "${Runlevel_Test}" =~ "chroot" ]];then
	Runlevel="当前系统运行于Chroot环境中！"
elif [ "${Runlevel_Test}" == "unknown" ];then
	Runlevel="当前脚本可能在容器环境中执行！"
else
	Runlevel="未知运行级别或脚本未适配！"
fi
}

#Login Users
System_Login_Users(){
Users=$(users 2>&1)
if [[ "${Runlevel_Test}" =~ "chroot" ]] && [ -z ${Users} ];then
	Login_Users="当前系统运行于Chroot环境中！"
elif [[ "${Runlevel_Test}" == "unknown" ]] && [ -z ${Users} ];then
	Login_Users="当前脚本可能在容器环境中执行！"
elif [ -z ${Users} ];then
	Login_Users="当前无登录用户！"
fi
}

#Login IP
System_Login_IP(){
Login_IP_Test=$(who /var/log/wtmp)
if [[ "${Runlevel_Test}" =~ "chroot" ]] && [ -z ${Login_IP_Test} ];then
	Login_IP="当前系统运行于Chroot环境中！"
elif [ "${Runlevel_Test}" == "unknown" ] && [ -z ${Login_IP_Test} ];then
	Login_IP="当前脚本可能在容器环境中执行！"
elif [ -z ${Login_IP_Test} ];then
	Login_IP="当前无登录用户IP信息!"
fi
}

Runlevel_Test=$(runlevel 2>&1)
if [ $? -ne 0 ] || [[ -z `runlevel 2>/dev/null` ]];then
	System_RunLvel
	System_Login_Users
	System_Login_IP
else
	Runlevel=$(echo "${Runlevel_Test}" | awk '{print $2}')
	Login_Users="`users | wc -w` User(s)"
	Login_IP=$(who /var/log/wtmp |  sed -n '$p' | sed  "s/[()]//g" | awk '{print $NF}')
fi

#System Info
Kernel=$(uname -sr)
Static_Hostname=$(hostname)
if [ "${PM}" == "yum" ];then
	Release=$(cat /etc/*-release 2>&1 | grep -Eo "[0-9]{,2}\.[0-9]{,2}\.[0-9]{,4}" | uniq)
elif [ "${PM}" == "apt-get" ];then
	Release=$(cat /etc/*-release | tr -d "\"" | awk -F '=' '/^VERSION_ID/{print $2}')
else
	Release="未知的系统版本号或脚本未适配该系统！"
fi

System_Info(){
cat /etc/*-release &>/dev/null
if [ $? -eq 0 ];then
	System=$(awk -F '=' '/^PRETTY_NAME/{print $2}' /etc/*-release | tr -d "\"")
else
	System="未知的系统版本或脚本未适配该系统！"
fi
}

Hostnamectl_Comm_Test=$(hostnamectl 2>/dev/null)
if [[ "${Runlevel_Test}" =~ [1-5]$ ]] && [ -n "${Hostnamectl_Comm_Test}" ];then
	System=$(echo -e "${Hostnamectl_Comm_Test}\n" | grep "System" | awk -F ': ' '{print $2}')
elif [[ "${Runlevel_Test}" =~ chroot|^unknown ]];then
	System_Info
else
	System="未知的系统版本或脚本未适配该系统！"
fi

#Virtualization
Virtualization_Test_1=$(echo -e "${Hostnamectl_Comm_Test}\n" | grep "Virtualization")
Virtualization_Test_2=$(systemd-detect-virt)
if [ -n "$Virtualization_Test_1" ];then
	Virtualization=$(echo -e "${Hostnamectl_Comm_Test}\n" | awk -F ': ' '/Virtualization/{print $2}')
elif [ -n "${Virtualization_Test_2}" ];then
	if [ "${Virtualization_Test_2}" == "none" ];then
		Virtualization="当前系统运行于物理设备上！"
	else
		Virtualization="${Virtualization_Test_2}"
	fi
else
	Virtualization="未检测到当前系统所用虚拟平台！"
fi

#System Bit and Architecture
System_Bit_Architecture="基于 `uname -m` 架构的 `getconf LONG_BIT` 位操作系统"

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

#CPU_Info
CPU_INFO_1(){
CPU_Model_INFO=$(lscpu 2>/dev/null | grep "^Model name" | awk -F ':' '{print $2}' | xargs)
CPU_PhysicalCoreNum=$(lscpu 2>/dev/null | grep "^Socket(s)" | awk -F ':' '{print $2}' | tr -d " ")
CPU_CoreNum=$(lscpu 2>/dev/null | grep "^Core(s)" | awk -F ':' '{print $2}' | tr -d " ")
CPU_ThreadNum=$(lscpu 2>/dev/null | grep "^CPU(s)" | awk -F ':' '{print $2}' | tr -d " ")
CPU_Basic_Info=$(echo "${CPU_PhysicalCoreNum} 个物理CPU，每个物理CPU有 ${CPU_CoreNum} 个物理核心数，共 ${CPU_ThreadNum} 个线程")
}

CPU_INFO_2(){
CPU_Num=$(grep "name" /proc/cpuinfo | cut -f2 -d ':' | uniq | wc -l)
if [ $CPU_Num -eq 1 ];then
	CPU_Model_INFO=$(grep "name" /proc/cpuinfo | awk -F ': ' '{print $2}' | uniq)
else
	CPU_Model_INFO=$(grep "name" /proc/cpuinfo | uniq | sed -n '1,$p' | awk -F ': ' '{print $2" |"}' | xargs)
fi
CPU_PhysicalCoreNum=$(grep "physical id" /proc/cpuinfo | sort | uniq | wc -l)
CPU_CoreNum=$(grep "cpu cores" /proc/cpuinfo | uniq | awk -F ': ' '{print $2}')
CPU_ThreadNum=$(getconf _NPROCESSORS_ONLN)
CPU_Basic_Info=$(echo "${CPU_PhysicalCoreNum} 个物理CPU，每个物理CPU有 ${CPU_CoreNum} 个物理核心数，共 ${CPU_ThreadNum} 个线程")
}

lscpu &>/dev/null
if [ $? -eq 0 ];then
	CPU_INFO_1
else
	CPU_INFO_2
fi

#Memory & Swap
Memory=$(free -m | grep -E "^Mem|^内存" | awk '{printf("总量：%sM，已使用：%sM，剩余：%sM，使用率：%.2f%%",$2,$3,($2-$3),($3/$2*100))}')
Swap=$(free -m | grep -E "^Swap|^交换" | awk '{printf("总量：%sM，已使用：%sM，剩余：%sM，使用率：%.2f%%",$2,$3,$4,($3/$2*100))}')

#System Uptime
Uptime=$(cut -f1 -d. /proc/uptime)
Run_time_Day=$((Uptime/60/60/24))
Run_time_Hour=$((Uptime/60/60%24))
Run_time_Mins=$((Uptime/60%60))
Run_time_Secs=$((Uptime%60))

#Process
Process=$(echo "正在运行 `ps -A | wc -l` 个进程")
Max_Proc=$(sysctl -n kernel.pid_max 2>/dev/null)

#home分区
Home=$(df -h 2>/dev/null | grep "/home")
if [ -z "$Home" ];then
	Disk_Home="home目录非独立挂载！"
else
	Disk_Home=$(echo "$Home" | awk '{print "总量："$2,"，已使用："$3,"，剩余："$4,"，使用率："$5}' | tr -d " ")
fi

#主网卡流量与IO流量
Network_IP_Address=$(hostname -I | cut -d ' ' -f1)
Network_Traffic_Detect=$(ip a | grep -E "${Network_IP_Address}" | awk '{print $NF}')
#Network_Traffic_Detect=$(ip link show | grep 'state UP' | awk -F ': ' '{print $2}' | head -1)
Network_Traffic_Acquisition=$(ip -s -h link | grep -A 5 "${Network_Traffic_Detect}")
Main_Network_Traffic=$(echo -e "${Network_Traffic_Acquisition}\n" | sed -n '4p;6p' | awk '{print $1}' | xargs | awk '{print "已接收："$1"，已发送："$2}')
Network_Traffic_lo=$(ip -s -h link | grep -A 5 "lo" | sed -n '4p;6p' | awk '{print $1}' | xargs | awk '{print "已接收："$1"，已发送："$2}')

#Private IP address
Network_IP_Private=$(ip route get 8.8.8.8 | head -1 | cut -d' ' -f7)
if [ "${Network_IP_Private}" == "${Network_IP_Address}" ];then
	Network_IP=${Network_IP_Private}
else
	Network_IP=${Network_IP_Address}
fi

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
   当前登录用户数：${Login_Users}
     系统用户统计：${System_Users}
 可密码登录用户数：${Allow_Login}
           私网IP：${Network_IP}
      SELinux信息：${SELinux_Result}
       系统用户名：${Static_Hostname}
         系统版本：${System}
       系统版本号：${Release}
     系统内核版本：${Kernel}
 系统所用虚拟平台：${Virtualization}
            Nginx：${Nginx_version}
            MySQL：${MySQL_version}
              PHP：${PHP_version}
             JAVA：${Java_version}
          CPU型号：${CPU_Model_INFO}
      CPU个数信息：${CPU_Basic_Info}
   系统架构与位数：${System_Bit_Architecture}
       主网卡流量：${Main_Network_Traffic}
           lo流量：${Network_Traffic_lo}
         系统负载：${Load_average}
           主磁盘：${Disk}
         home分区：${Disk_Home}
        Inode信息：${Inode}
 临时文件目录已用：${Temp}
             内存：${Memory}
     Swap虚拟内存：${Swap}
             进程：${Process}
   系统最大进程数：${Max_Proc}
       系统已运行：${Run_time_Day} 天 ${Run_time_Hour} 小时 ${Run_time_Mins} 分钟 ${Run_time_Secs} 秒
     当前登录时间：${Date}
 当前系统运行级别：${Runlevel}
   当前您登录的IP：${Login_IP}
 \n ===================================================================\n"