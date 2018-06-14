# Security Knowledge Structure

## 企业安全

### 黑盒扫描

- [静态xss检测](http://blog.wils0n.cn/archives/160/)
- [对AWVS一次简单分析](http://blog.wils0n.cn/archives/145/)
- [初见Chrome Headless Browser](https://lightless.me/archives/first-glance-at-chrome-headless-browser.html)
- [用phantomJS检测URL重定向](https://joychou.org/web/dom-url-redirect.html)
- [用SlimerJS检测Flash XSS](https://joychou.org/web/Flash-Xss-Dynamic-Detection.html)

### 白盒扫描器

- [Cobra](https://github.com/FeeiCN/cobra)

### WAF自建

- [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)
- [VeryNginx](https://github.com/alexazhou/VeryNginx)
- [lua-resty-waf](https://github.com/p0pr0ck5/lua-resty-waf)
- [如何建立云WAF](https://joychou.org/web/how-to-build-cloud-waf.html)
- [如何建立HTTPS的云WAF](https://joychou.org/web/how-to-build-https-cloud-waf.html)

### 堡垒机

- [jumpserver](https://github.com/jumpserver/jumpserver)

### HIDS

- [yulong-hids](https://github.com/ysrc/yulong-hids)

### 子域名爆破

- [ESD](https://github.com/FeeiCN/ESD)
- [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)

### 命令监控

- [Netlink Connector](https://www.ibm.com/developerworks/cn/linux/l-connector/)
- [Netlink(Go版本)](https://github.com/vishvananda/netlink)
- [「驭龙」Linux执行命令监控驱动实现解析](https://mp.weixin.qq.com/s/ntE5FNM8UaXQFC5l4iKUUw)

### 文件监控和同步

- [lsyncd (文件监控)](https://github.com/axkibe/lsyncd)

### Java安全开发组件

- [Trident](https://github.com/JoyChou93/trident)
- [Java安全测试代码](https://github.com/JoyChou93/java-sec-code)

### Github信息泄露监控

- [GSIL](https://github.com/FeeiCN/GSIL)
- [Hawkeye](https://github.com/0xbug/Hawkeye)

### 解析域名后端IP

- [Nginx Parser](https://github.com/WhaleShark-Team/nginxparser)


## 运维安全

### NGINX配置安全

- [Gixy (一款开源的Nginx配置安全扫描器)](https://github.com/yandex/gixy)
- [三个案例看Nginx配置安全](https://www.leavesongs.com/PENETRATION/nginx-insecure-configuration.html)
- [Nginx Config Security](https://joychou.org/web/nginx-config-security.html)

### Tomcat配置安全

- [Tomcat Config Security](https://joychou.org/operations/tomcat-config-security.html)

## Backdoor

### Nginx后门

- [pwnnginx](https://github.com/t57root/pwnginx)
- [浅谈nginx + lua在安全中的一些应用](https://zhuanlan.zhihu.com/p/21362834)


### Webshell

- [Github上webshell大杂烩](https://github.com/tennc/webshell)
- [入侵分析发现的webshell](https://github.com/JoyChou93/webshell)


### Linux SSH 后门

- [Linux SSH Backdoor](https://joychou.org/hostsec/linux-ssh-backdoor.html)
- [sshLooter（一款Python的PAM后门）](https://github.com/mthbernardes/sshLooter)
- [Pam my Unix](https://github.com/LiGhT1EsS/pam_my_unix)

### 反弹Shell

- [Linux Crontab定时任务反弹shell的坑](https://joychou.org/hostsec/linux-crontab-rebound-shell-hole.html)

### 清除Linux挖矿后门

- [Linux Ddos后门清除脚本](https://joychou.org/hostsec/linux-ddos-backdoor-killer-script.html)
- [Kill Ddos Backdoor](https://github.com/JoyChou93/kill_ddos_backdoor)


## WAF Bypass

- [文件上传和WAF的功与防](https://joychou.org/web/bypass-waf-of-file-upload.html)
- [Nginx Lua WAF通用绕过方法](https://joychou.org/web/nginx-Lua-waf-general-bypass-method.html)

### 菜刀

- [新版菜刀@20141213一句话不支持php assert分析](https://joychou.org/web/caidao-20141213-does-not-support-php-assert-oneword-backdoor-analysis.html)
- [菜刀连接密码不是可显示字符的一句话](https://joychou.org/web/913.html)
- [花式Bypass安全狗对菜刀特征的拦截规则](https://joychou.org/web/bypass-safedog-blocking-rules-for-chopper.html)
- [定制过狗菜刀](https://joychou.org/web/make-own-chopper-which-can-bypass-dog.html)
- [Cknife (一款开源菜刀)](https://github.com/Chora10/Cknife)


## 主机安全

### 提权

- [脏牛CVE-2016-5195提权](https://github.com/FireFart/dirtycow/blob/master/dirty.c)


## 前端安全

- [JavaScript反调试技巧](http://www.freebuf.com/articles/system/163579.html)
- [Devtools detect](https://github.com/sindresorhus/devtools-detect)
- [代码混淆](https://github.com/javascript-obfuscator/javascript-obfuscator)


## 业务安全

### PC设备指纹

- [fingerprintjs2](https://github.com/Valve/fingerprintjs2)
- [跨浏览器设备指纹](https://github.com/Song-Li/cross_browser)
- [2.5代指纹追踪技术—跨浏览器指纹识别](https://paper.seebug.org/350/)

### 安全水印

- [水印开发](https://github.com/saucxs/watermark)
- [水印的攻击与防御](https://joychou.org/business/watermark-security.html)


## 移动安全

## 小程序安全

## JAVA安全


- [find-sec-bug](http://find-sec-bugs.github.io/bugs.htm)



### RASP

- [OpenRASP](https://github.com/baidu/openrasp)
- [JAVA Apache-CommonsCollections 序列化漏洞分析以及漏洞高级利用](https://www.iswin.org/2015/11/13/Apache-CommonsCollections-Deserialized-Vulnerability/)

### Java反序列化

- [Lib之过？Java反序列化漏洞通用利用分析](https://blog.chaitin.cn/2015-11-11_java_unserialize_rce/)
- [JAVA Apache-CommonsCollections 序列化漏洞分析以及漏洞高级利用](https://www.iswin.org/2015/11/13/Apache-CommonsCollections-Deserialized-Vulnerability/)
- [Java反序列化漏洞-玄铁重剑之CommonsCollection(上)](https://xz.aliyun.com/t/2028)
- [Commons Collections Java反序列化漏洞分析](https://joychou.org/java/commons-collections-java-deserialize-vulnerability-analysis.html)

### JDWP

这个漏洞可能会有意想不到的收获。

- [Hacking the Java Debug Wire Protocol](http://blog.ioactive.com/2014/04/hacking-java-debug-wire-protocol-or-how.html)
- [Java Debug Remote Code Execution](https://joychou.org/web/Java-Debug-Remote-Code-Execution.html)
- [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier)


### SSRF

- [Java SSRF 漏洞代码](https://github.com/JoyChou93/java-sec-code/blob/master/src/main/java/org/joychou/controller/SSRF.java)
- [SSRF in Java](https://joychou.org/web/javassrf.html)
- [Use DNS Rebinding to Bypass SSRF in JAVA](https://joychou.org/web/use-dnsrebinding-to-bypass-ssrf-in-java.html)

### XXE

- [Java XXE Vulnerability](https://joychou.org/web/java-xxe-vulnerability.html)
- [Java XXE 漏洞代码](https://github.com/JoyChou93/java-sec-code/blob/master/src/main/java/org/joychou/controller/XMLInjection.java)

### URL白名单绕过

- [URL白名单绕过](https://joychou.org/web/url-whitelist-bypass.html)


## PHP安全

### SSRF

- [Typecho SSRF漏洞分析和利用](https://joychou.org/web/typecho-ssrf-analysis-and-exploit.html)
- [SSRF in PHP](https://joychou.org/web/phpssrf.html)

### PHP反序列化

- [Typecho反序列化漏洞分析](https://joychou.org/web/typecho-unserialize-vulnerability.html)
- [浅谈php反序列化漏洞](https://chybeta.github.io/2017/06/17/%E6%B5%85%E8%B0%88php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)

## Python安全

- [Exploit SSTI in Flask/Jinja2](https://joychou.org/web/exploit-ssti-in-flask-jinja2.html)
- [Ptyhon沙盒绕过](https://joychou.org/web/python-sandbox-bypass.html)
- [Python安全代码审计](https://joychou.org/web/python-sec-code-audit.html)
- [Python任意命令执行漏洞修复](https://joychou.org/codesec/fix-python-arbitrary-command-execution-vulnerability.html)
- [从一个CTF题目学习Python沙箱逃逸](https://www.anquanke.com/post/id/85571)


## Lua安全

- [Nginx Lua Web应用安全](https://joychou.org/web/nginx-lua-web-application-security.html)

## 漏洞修复

- [Python任意命令执行漏洞修复](https://joychou.org/codesec/fix-python-arbitrary-command-execution-vulnerability.html)
- [CVE-2016-5195 Dirty Cow漏洞修复](https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-dirty-cow-linux-vulnerability)


## 黑科技

- [微博PC版去广告]()

## 基本技能

- Linux RPM理解及使用
- PIP理解及使用
- Python、PHP、Java、Bash
- iptables、定时任务、反弹shell
- 正向和反向代理
- Nginx使用及配置
- 域名配置
- HTTP协议
- 工具使用BurpSuite

## 安全面试问题

>面试的问题跟自己简历相关，只是面试官会根据你回答的点继续深挖，看看你有没有回答他想要的答案。

### 甲方

- TCP/IP协议
- 如果服务器上有一个phpspy.php，如何做入侵分析
- XXE常用payload
- DDOS如何人工防御
- 邮件伪造如何防御
- 拿到WEBSHELL，无法提权，还有什么思路？
- SDL流程
- 安全如何闭环
- 觉得自己哪方面比较牛逼
- 越权有什么检测方式
    - 黑盒两个账户Cookie
    - 鉴权函数 + 数据库查询
- 类似JDWP这种传统HTTP层WAF不能拦截，可以如何检测？
    - RASP
    - 命令监控(父进程是Java，并且执行了恶意命令)
    
    
非技术面：

- 为什么离开之前公司
- 在之前公司的成长
- 工作成就感
- 做的最大、最牛逼的项目
- 对未来规划是什么
- 安全培训怎样衡量价值
- 后面安全的方向是什么
