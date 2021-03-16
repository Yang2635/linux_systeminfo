# linux_scripts
linux shell脚本

`Systeminfo.sh`是基于CentOS 7的一个获取系统信息的shell脚本，第一次编写提交（待完善）

食用方法：

```shell
# 更新软件库并安装wget
yum update && yum install wget

# 一键脚本
wget --no-check-certificate https://raw.githubusercontent.com/Yang2635/linux_scripts/main/systeminfo.sh && chmod +x systeminfo.sh && bash systeminfo.sh
```

后期查看可使用`bash systeminfo.sh`再次执行该脚本，若需要用户登录terminal终端时就执行，可编辑当前用户的`.bashrc`文件（`.bashrc`文件仅当前用户生效），将该脚本的绝对路径添加上即可，下次用户登录terminal终端即可自动执行。也可直接在`/etc/profile`中添加脚本的绝对路径，此时则为全局生效（不建议）

显示效果如图所示：

![图片](https://user-images.githubusercontent.com/60431848/111312569-61dea980-869a-11eb-923c-e602b895b888.png)

