
`systeminfo.sh`是基于CentOS、Debian、Ubuntu的一个获取系统信息的shell脚本，第一次编写提交（待完善）

食用方法：
将该脚本下载至系统，`bash systeminfo.sh`命令执行即可（记得给于脚本赋可执行权限！）
脚本运行时，会检测系统是否拥有`ifconfig`命令，该命令用于统计相关网卡数据流量，若机器无该命令，脚本会自行安装`net-tools`工具，您也可提前安装上`net-tools`工具，命令如下：

CentOS：
```shell
yum install net-tools -y
```

Debian、Ubuntu：
```shell
apt install net-tools -y
```
## 一键脚本食用：
更新软件库并安装wget
CentOS：
```shell
yum update -y && yum install wget -y
```
Debian、Ubuntu：
```shell
apt update && apt install wget -y
```

一键脚本下载执行
```shell
wget --no-check-certificate https://raw.githubusercontent.com/Yang2635/linux_scripts/main/systeminfo.sh && chmod +x systeminfo.sh && bash systeminfo.sh
```

后期查看可使用`bash systeminfo.sh`再次执行该脚本，若需要用户登录terminal终端时就执行，可编辑当前用户的`.bashrc`文件（`.bashrc`文件仅当前用户生效），将该脚本的绝对路径添加上即可，下次用户登录terminal终端即可自动执行。也可直接在`/etc/profile`中添加脚本的绝对路径，此时则为全局生效（不建议）

显示效果如图所示：

![图片](https://user-images.githubusercontent.com/60431848/111312569-61dea980-869a-11eb-923c-e602b895b888.png)

