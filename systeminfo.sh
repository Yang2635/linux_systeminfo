#!/bin/bash
PATH="$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin"
export PATH
LANG=en_US.UTF-8
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

#User_id=$(id | sed "s/[(][^)]*[)]//g" | awk '{print $1"，"$2"，"$3}')
User_id="用户id(uid)=`id -u`，组id(gid)=`id -g`"
System_Users="系统共有 `cat /etc/passwd  | wc -l` 个用户"

#Disk_Info
Disk=$(df -h / 2>/dev/null | sed '1d' | awk '{printf("总量：%s，已使用：%s，剩余：%s，使用率：%s",$2,$3,$4,$5)}')
Inode=$(df -i -h / 2>/dev/null | sed '1d' | awk '{printf("总量：%s，已使用：%s，剩余：%s，使用率：%s",$2,$3,$4,$5)}')

#Tmp Dir
Temp=$(du -sh /tmp 2>/dev/null | cut -f1)

#System Load average
Load_average=$(awk '{printf("1分钟：%s，5分钟：%s，15分钟：%s",$1,$2,$3)}' /proc/loadavg)

#System RunLevel
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

##Login_IP_Test
if [ -n "$SSH_CLIENT" ];then
	Login_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
else
	Login_IP="当前无登录用户IP信息！"
fi


Runlevel_Test=$(runlevel 2>&1)
if [ $? -ne 0 ] || [[ -z "`runlevel 2>/dev/null`" ]];then
	System_RunLvel
	System_Login_Users
	#System_Login_IP
else
	Runlevel=$(echo "${Runlevel_Test}" | awk '{print $2}')
	Login_Users="`users | wc -w` User(s)"
	#Login_IP=$(who /var/log/wtmp |  sed -n '$p' | sed  "s/[()]//g" | awk '{print $NF}')
fi

#System Info
Kernel=$(uname -sr)
Static_Hostname=$(hostname)

if [ -n "`lsb_release -a 2>/dev/null`" ];then
	Release=$(lsb_release -a 2>/dev/null | awk -F':' '/^Release/{print $2}' | xargs)
elif [ "${PM}" == "yum" ];then
	Release=$(cat /etc/*-release 2>&1 | grep -Eo "[0-9]{,2}\.[0-9]{,2}\.[0-9]{,4}" | uniq)
elif [ "${PM}" == "apt-get" ];then
	Release=$(cat /etc/*-release | tr -d "\"" | awk -F '=' '/^VERSION_ID/{print $2}')
else
	Release="未知的系统版本号或脚本未适配该系统！"
fi

System_Info(){
if [ -n "`lsb_release -a 2>/dev/null`" ];then
	System=$(lsb_release -a 2>/dev/null | awk -F ':' '/^Description/{print $2}' | xargs)
elif [ -n "`cat /etc/*-release 2>/dev/null`" ];then
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

#Time
Date=$(date "+%Y-%m-%d %H:%M:%S")

#CPU_Info
CPU_INFO(){
case $1 in
	0)
		CPU_Model_INFO=$(lscpu 2>/dev/null | grep "^Model name" | awk -F ':' '{print $2}' | xargs)
		CPU_PhysicalCoreNum=$(lscpu 2>/dev/null | grep "^Socket(s)" | awk -F ':' '{print $2}' | tr -d " ")
		CPU_CoreNum=$(lscpu 2>/dev/null | grep "^Core(s)" | awk -F ':' '{print $2}' | tr -d " ")
		CPU_ThreadNum=$(lscpu 2>/dev/null | grep "^CPU(s)" | awk -F ':' '{print $2}' | tr -d " ")
		CPU_Basic_Info=$(echo "${CPU_PhysicalCoreNum} 个物理CPU，每个物理CPU有 ${CPU_CoreNum} 个物理核心数，共 ${CPU_ThreadNum} 个线程")
	;;
	1)
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
	;;
esac
}

lscpu &>/dev/null
if [ $? -eq 0 ];then
	CPU_INFO 0
else
	CPU_INFO 1
fi

#Memory & Swap
Memory=$(free -m | grep -E "^Mem|^内存" | awk '{printf("总量：%sM，已使用：%sM，剩余：%sM，使用率：%.2f%%",$2,$3,($2-$3),($3/$2*100))}')
if [ -n "`swapon -s`" ];then
	Swap=$(free -m | grep -E "^Swap|^交换" | awk '{printf("总量：%sM，已使用：%sM，剩余：%sM，使用率：%.2f%%",$2,$3,$4,($3/$2*100))}')
else
	Swap="未检测到Swap分区！"
fi

#System Uptime
Uptime=$(cut -f1 -d. /proc/uptime)
Run_time_Day=$((Uptime/60/60/24))
Run_time_Hour=$((Uptime/60/60%24))
Run_time_Mins=$((Uptime/60%60))
Run_time_Secs=$((Uptime%60))

#Process
Process_Num_Info(){
ALL_Process=$(ls /proc/ | egrep '[0-9]+')

running_count=0
stoped_count=0
sleeping_count=0
zombie_count=0

for pid in ${ALL_Process[*]}
do
    test -f /proc/$pid/status && state=$(egrep "State" /proc/$pid/status | awk '{print $2}')
    case "$state" in
        R)
            running_count=$((running_count+1))
        ;;
        T)
            stoped_count=$((stoped_count+1))
        ;;
        S)
            sleeping_count=$((sleeping_count+1))
        ;;
        Z)
            zombie_count=$((zombie_count+1))
        ;;
    esac
done
Process="总进程数：$((running_count+stoped_count+sleeping_count+zombie_count))，运行进程：$running_count，停止进程：$stoped_count，睡眠进程：$sleeping_count，僵尸进程：$zombie_count"
}
Process="当前进程数：`ps -A | wc -l`（指定[-T]可查看详细信息！）"

#Max_Process_Num
Max_Proc=$(sysctl -n kernel.pid_max 2>/dev/null)

#Max_Threads_Num
Max_Threads=$(sysctl -n kernel.threads-max 2>/dev/null)


#home分区
Home=$(df -h 2>/dev/null | grep "/home")
if [ -z "$Home" ];then
	Disk_Home="home目录非独立挂载！"
else
	Disk_Home=$(echo "$Home" | awk '{printf("总量：%s，已使用：%s，剩余：%s，使用率：%s"),$2,$3,$4,$5}')
fi

#主网卡流量与IO流量统计
Network_Test_Info=$(ip route get 8.8.8.8 | grep -Eo "dev.*")
Network_Eth=$(echo "${Network_Test_Info}" |  cut -d ' ' -f2)
##echo private ip
#Network_IP_Private=$(echo "${Network_Test_Info}" | grep -Eo "[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}")
Network_IP_Private=$(echo "${Network_Test_Info}" | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
eval `grep "${Network_Eth}" /proc/net/dev | sed 's/^[ \t]*//g' | grep "^${Network_Eth}" | awk '{printf("Eth_Rx=%s;Eth_Tx=%s;",$2,$10)}'`
eval `grep "lo" /proc/net/dev | awk '{printf("lo_Rx=%s;lo_Tx=%s",$2,$10)}'`

declare -A Traffic=([Main_Eth_Rx]=${Eth_Rx} [Main_Eth_Tx]=${Eth_Tx} [lo_Rx]=${lo_Rx} [lo_Tx]=${lo_Tx})
for i in ${!Traffic[*]}
do
	if [[ "${Traffic[$i]}" -ge "((1024**3))" ]];then
		Traffic[$i]=$(echo "${Traffic[$i]}" | awk '{printf("%.2f GB",$1/1024/1024/1024)}')
	elif [[ "${Traffic[$i]}" -ge "((1024**2))" ]];then
		Traffic[$i]=$(echo "${Traffic[$i]}" | awk '{printf("%.2f MB",$1/1024/1024)}')
	elif [[ "${Traffic[$i]}" -ge 1024 ]];then
		Traffic[$i]=$(echo "${Traffic[$i]}" | awk '{printf("%.2f KB",$1/1024)}')
	else
		Traffic[$i]=$(echo "${Traffic[$i]}" | awk '{printf("%s B",$1)}' )
	fi
done
Main_Network_Traffic="网络接口：${Network_Eth}，已接收：${Traffic[Main_Eth_Rx]}，已发送：${Traffic[Main_Eth_Tx]}"
lo_Network_Traffic="已接收：${Traffic[lo_Rx]}，已发送：${Traffic[lo_Tx]}"


#System Allow Login User
Allow_Login_User(){
	if [ `id -u` -ne 0 ];then
		Allow_Login="您没有权限查看可密码登录终端系统的用户数与用户！"
	else
		Allow_LoginUserNum=$(awk -F ':' '$2~/^\$(.|..)\$/{print $1}' /etc/shadow | wc -w)
		Allow_LoginUser=$(awk -F ':' '$2~/^\$(.|..)\$/{print $1}' /etc/shadow | xargs)
		Allow_Login="有 ${Allow_LoginUserNum} 个可密码登录终端的用户！分别是：${Allow_LoginUser}"
	fi
}
Allow_Login="为保护用户相关隐私，若查看可登录用户信息请指定[-L]参数！"

#Public Network IP Info
Public_Network(){
	Curl_Path=$(which curl 2>/dev/null)
	if [ -n "${Curl_Path}" ];then
		Public_Network_IP_Info=$(${Curl_Path} -s myip.ipip.net)
	else
		${PM} install curl -y &>/dev/null
		if [ $? -eq 0 ];then
			Public_Network_IP_Info=$(curl -s myip.ipip.net)
		else
			Public_Network_IP_Info="curl命令安装失败！"
		fi
	fi
}
Public_Network_IP_Info="为保护公网IP隐私信息，若查看公网IP信息请使用[-P]参数！"

# Get the installed environment software and version
arr_Install_Software=(#请在此处添加需检测的安装软件，一行一个；默认使用which命令检测软件是否在系统变量里存在
mysql
nginx
php
java
memcached
redis-cli
tomcat
docker
node
python
python3
apache2
)
	
Check_Install_Software_And_Version(){
	unset new_arr_Install_Software[*]
	for i in ${arr_Install_Software[*]}
	do
		Software_Path=$(which $i 2>/dev/null)
		if [ -n "$Software_Path" ];then
			case $i in
			mysql)
				version=$($Software_Path --version | awk '{print $5}' | tr -d ",")
			;;
			nginx)
				version=$($Software_Path -v 2>&1 | awk -F ': |/'  '{print $3}')
			;;
			php)
				version=$($Software_Path -v | head -1 | awk '{print $2}')
			;;
			java)
				version=$($Software_Path -version 2>&1 | awk -F '"' '{print $2}' | tr -d "\n")
			;;
			memcached)
				version=$($Software_Path --version | awk '{print $2}')
			;;
			redis-cli)
				version=$($Software_Path -v | awk '{print $2}')
			;;
			tomcat)
				version=$($Software_Path version | awk '/^Server number/{print $3}')
			;;
			docker)
				version=$($Software_Path --version | awk '{print $3}' | tr -d ",")
			;;
			node)
				version=$($Software_Path -v | sed 's/v//g')
			;;
			python|python3)
				version=$($Software_Path --version 2>&1| awk '{print $2}')
			;;
			apache2)
				version=$($Software_Path -v | awk -F ' |/' '/^Server version/{print $4}')
			;;
			*)
				version="null"
			;;
			esac
			new_arr_Install_Software+=("${i}:${version}")
		fi
	done

	if [ ${#new_arr_Install_Software[@]} -eq 0 ];then
		Install_Software="未检测到相关环境组件！"
	else
		Install_Software=$(echo "${new_arr_Install_Software[@]}")
	fi
}

Default_Check_Install_Software(){
for i in ${arr_Install_Software[*]}
do
	Software_Path=$(which $i 2>/dev/null)
	if [ -n "$Software_Path" ];then
		new_arr_Install_Software+=("${i}")
	fi
done

if [ ${#new_arr_Install_Software[@]} -eq 0 ];then
	Install_Software="未检测到相关环境组件！"
else
	Install_Software=$(echo "${new_arr_Install_Software[@]}（指定[-V]参数可查看版本！）")
fi

}
Default_Check_Install_Software


while getopts ":PLVT" opt
do
	case $opt in
		P)
			Public_Network
		;;
		L)
			Allow_Login_User
		;;
		V)
			Check_Install_Software_And_Version
		;;
		T)
			Process_Num_Info
		;;
	esac
done

echo -e "
 Welcome to this services！The following is the Device Information：\n
 ===================================================================\n
     当前登录用户：${USER}
       当前用户id：${User_id}
   当前登录用户数：${Login_Users}
     系统用户统计：${System_Users}
 可密码登录用户数：${Allow_Login}
           私网IP：${Network_IP_Private}
 设备公网IP及信息：${Public_Network_IP_Info}
      SELinux信息：${SELinux_Result}
       系统用户名：${Static_Hostname}
         系统版本：${System}
       系统版本号：${Release}
     系统内核版本：${Kernel}
 系统所用虚拟平台：${Virtualization}
   已安装环境软件：${Install_Software}
          CPU型号：${CPU_Model_INFO}
      CPU个数信息：${CPU_Basic_Info}
   系统架构与位数：${System_Bit_Architecture}
     网络接口流量：${Main_Network_Traffic}
           lo流量：${lo_Network_Traffic}
         系统负载：${Load_average}
           主磁盘：${Disk}
         home分区：${Disk_Home}
        Inode信息：${Inode}
 临时文件目录已用：${Temp}
             内存：${Memory}
     Swap虚拟内存：${Swap}
             进程：${Process}
 最大进程与线程数：最大进程数：${Max_Proc}，最大线程数：${Max_Threads}
       系统已运行：${Run_time_Day} 天 ${Run_time_Hour} 小时 ${Run_time_Mins} 分钟 ${Run_time_Secs} 秒
     当前登录时间：${Date}
 当前系统运行级别：${Runlevel}
   当前您登录的IP：${Login_IP}
 \n ===================================================================\n"