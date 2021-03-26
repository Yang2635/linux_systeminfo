
`systeminfo.sh`是基于主流Linux系统的一个简单获取系统信息的shell脚本，目的为使用户登录terminal终端时显示系统相关信息，第一次编写提交，若存在适配的问题欢迎提issue

## 食用方法：
将该脚本下载至系统，命令`chmod +x systeminfo.sh`赋脚本可执行权限，并用`bash systeminfo.sh`命令执行即可输出信息至终端

脚本运行时，会检测系统是否拥有`ifconfig`命令，使用该命令用于获取并统计相关网卡数据流量，若机器无该命令，脚本会自行安装`net-tools`工具，您也可提前安装上`net-tools`工具，命令如下：

CentOS：
```shell
yum install net-tools -y
```

Debian、Ubuntu：
```shell
apt-get install net-tools -y
```
## 一键脚本食用：
更新软件库并安装wget

CentOS：
```shell
yum update -y && yum install wget -y
```
Debian、Ubuntu：
```shell
apt-get update -y && apt install wget -y
```

一键脚本下载执行：

```shell
wget --no-check-certificate https://raw.githubusercontent.com/Yang2635/linux_systeminfo/main/systeminfo.sh && chmod +x systeminfo.sh && bash systeminfo.sh
```


后期查看可使用`bash systeminfo.sh`命令再次执行该脚本，若需要用户登录terminal终端时就执行，可编辑当前用户的`.bashrc`文件（`.bashrc`文件仅当前用户生效），将该脚本的执行路径添加上即可；若脚本在当前用户目录下，可使用命令`echo "./systeminfo.sh" >> .bashrc`进行添加，下次用户登录terminal终端即可自动执行输出。也可直接在`/etc/profile`中添加脚本的绝对路径，此时则为全局生效（非常不建议）

显示效果如图所示：

![图片](https://user-images.githubusercontent.com/60431848/111864695-7920de00-899d-11eb-97a8-5daf8d5df60a.png)
