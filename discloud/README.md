# singbox-nodejs

游戏机使用代码

单端口模式：启用 HY2 + HTTP(订阅) + Argo  可以手动选择tuic
多端口模式：TUIC + HTTP(订阅) + Argo + HY2 + REALITY

订阅链接： http://IP:PORT/sub

如果系统无法自动获取到可用端口，则需自己手动新建 ${FILE_PATH}/ports.txt 文件，一行一个端口号

修复了固定隧道支持，增加了哪吒支持，留空不安装哪吒，增加了Python版本兼容。

感谢：https://github.com/yinmmhh/sb-nodejs
