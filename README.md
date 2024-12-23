# mitm_mock
这是一个mock工具，原理是使用代理，拦截指定的http协议的请求，然后直接返回响应值。<br>

详细教程，请在服务启动成功后，点击教程按钮查看 <br>

### 功能
1、自定义http协议拦截规则，支持通过域名和url路径拦截<br>
2、可设置任意状态码，响应值可设置成任意字符串，支持设置读取本地文件的路径<br>
3、支持篡改请求参数，或篡改响应值<br>
4、使用sqlite数据库储存规则<br>

# 使用
1、克隆
```shell script
git clone https://github.com/leeyoshinari/mitm_mock.git
```

2、修改配置文件`config.ini`

3、安装依赖包  `pip3 install -r requirements.txt`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Mac 需要最新版的pip，如果不是最新版本的pip，请先升级pip，执行命令 `pip3 install --upgrade pip`

4、配置mitmproxy环境变量<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Windows 在环境变量的 path 中添加 mitmproxy 的可执行文件路径<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Linux 将 mitmproxy 的可执行文件软连接到 /usr/bin/mitmproxy<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Mac 将 mitmproxy 的可执行文件软连接到 /usr/local/bin/mitmproxy<br>

5、启动 `python3 server.py`，开启前端规则配置页面

6、设置系统代理<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Windows设置方法：`打开“设置——>网络和Internet——>代理——>手动设置代理”`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Linux设置方法：`export http_proxy=http://ip:port`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Mac设置方法：`打开“系统偏好设置——>网络——>高级——>代理——>网页代理(HTTP) 或 安全网页代理(HTTPS)”`<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;取消代理设置<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Windows取消方法：直接在“手动设置代理”的地方关闭即可<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Linux取消方法：`unset http_proxy` <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Mac取消方法：直接在“代理”页面关闭即可<br>

7、访问页面 http://IP:PORT/context(配置文件中的context)<br>
&nbsp;&nbsp;&nbsp;&nbsp;添加/编辑拦截规则，使拦截规则生效<br>
![](https://github.com/leeyoshinari/mitm_mock/blob/main/static/shoot.jpg)

8、所有规则配置完成后，执行 `python3 mitm.py` 就可以拦截和篡改请求了，这里只获取“启用”的规则。每次修改完规则，需要重新执行 `python3 mitm.py`

# 注意
1、每次mock时，需开启系统代理；mock完成后，须关闭代理；

2、由于该工具是拦截 http 请求，所以拦截时，目标IP地址和目标端口必须存在，必须能够完成 TCP 三次握手；

3、如果需要拦截（mock）https的请求，需要安装证书，其他操作和http的基本一样；证书在用户目录下的 .mitmproxy 文件夹中，安装 mitmproxy-ca-cert.cer，且必须信任该证书。

# Requirements
1、python 3.11+<br>
2、mitmproxy<br>
3、aiohttp<br>
