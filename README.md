# Security Knowledge Structure

欢迎大家提交ISSUE和Pull Requests。

## 1. 企业安全

### 1.1 黑盒扫描

- [静态xss检测](http://blog.wils0n.cn/archives/160/)
- [对AWVS一次简单分析](http://blog.wils0n.cn/archives/145/)
- [初见Chrome Headless Browser](https://lightless.me/archives/first-glance-at-chrome-headless-browser.html)
- [用phantomJS检测URL重定向](https://joychou.org/web/dom-url-redirect.html)
- [用SlimerJS检测Flash XSS](https://joychou.org/web/Flash-Xss-Dynamic-Detection.html)

### 1.2 白盒扫描器

- [Cobra](https://github.com/FeeiCN/cobra)

### 1.3 WAF自建

- [如何建立云WAF](https://joychou.org/web/how-to-build-cloud-waf.html)
- [如何建立HTTPS的云WAF](https://joychou.org/web/how-to-build-https-cloud-waf.html)
- [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)
- [VeryNginx](https://github.com/alexazhou/VeryNginx)
- [lua-resty-waf](https://github.com/p0pr0ck5/lua-resty-waf)

### 1.4 堡垒机

- [jumpserver](https://github.com/jumpserver/jumpserver)

### 1.5 HIDS

- [yulong-hids](https://github.com/ysrc/yulong-hids)

### 1.6 子域名爆破

- [ESD](https://github.com/FeeiCN/ESD)
- [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)

### 1.7 命令监控

- [Netlink Connector](https://www.ibm.com/developerworks/cn/linux/l-connector/)
- [Netlink(Go版本)](https://github.com/vishvananda/netlink)
- [Linux执行命令监控驱动实现解析](https://mp.weixin.qq.com/s/ntE5FNM8UaXQFC5l4iKUUw)

### 1.8 文件监控和同步

- [lsyncd (文件监控)](https://github.com/axkibe/lsyncd)

### 1.9 Java安全开发组件

- [Trident](https://github.com/JoyChou93/trident)
- [Java安全测试代码](https://github.com/JoyChou93/java-sec-code)

### 1.10 Github信息泄露监控

- [GSIL](https://github.com/FeeiCN/GSIL)
- [Hawkeye](https://github.com/0xbug/Hawkeye)

### 1.11 解析域名后端IP

- [Nginx Parser](https://github.com/WhaleShark-Team/nginxparser)


## 2. 运维安全

### 2.1 NGINX配置安全

- [Gixy (一款开源的Nginx配置安全扫描器)](https://github.com/yandex/gixy)
- [三个案例看Nginx配置安全](https://www.leavesongs.com/PENETRATION/nginx-insecure-configuration.html)
- [Nginx Config Security](https://joychou.org/web/nginx-config-security.html)

### 2.2 Tomcat配置安全

- [Tomcat Config Security](https://joychou.org/operations/tomcat-config-security.html)

## 3. Backdoor

### 3.1 Nginx后门

- [pwnnginx](https://github.com/t57root/pwnginx)
- [浅谈nginx + lua在安全中的一些应用](https://zhuanlan.zhihu.com/p/21362834)


### 3.2 Webshell

- [Github上webshell大杂烩](https://github.com/tennc/webshell)
- [入侵分析发现的webshell](https://github.com/JoyChou93/webshell)


### 3.3 Linux SSH 后门

- [Linux SSH Backdoor](https://joychou.org/hostsec/linux-ssh-backdoor.html)
- [sshLooter（一款Python的PAM后门）](https://github.com/mthbernardes/sshLooter)
- [Pam my Unix](https://github.com/LiGhT1EsS/pam_my_unix)

### 3.4 反弹Shell

- [Linux Crontab定时任务反弹shell的坑](https://joychou.org/hostsec/linux-crontab-rebound-shell-hole.html)

### 3.5 清除Linux挖矿后门

- [Linux Ddos后门清除脚本](https://joychou.org/hostsec/linux-ddos-backdoor-killer-script.html)
- [Kill Ddos Backdoor](https://github.com/JoyChou93/kill_ddos_backdoor)


## 4. WAF Bypass

- [文件上传和WAF的功与防](https://joychou.org/web/bypass-waf-of-file-upload.html)
- [Nginx Lua WAF通用绕过方法](https://joychou.org/web/nginx-Lua-waf-general-bypass-method.html)

### 4.1 菜刀

- [新版菜刀@20141213一句话不支持php assert分析](https://joychou.org/web/caidao-20141213-does-not-support-php-assert-oneword-backdoor-analysis.html)
- [菜刀连接密码不是可显示字符的一句话](https://joychou.org/web/913.html)
- [花式Bypass安全狗对菜刀特征的拦截规则](https://joychou.org/web/bypass-safedog-blocking-rules-for-chopper.html)
- [定制过狗菜刀](https://joychou.org/web/make-own-chopper-which-can-bypass-dog.html)
- [Cknife (一款开源菜刀)](https://github.com/Chora10/Cknife)


## 5. 主机安全

### 5.1 提权

- [脏牛CVE-2016-5195提权](https://github.com/FireFart/dirtycow/blob/master/dirty.c)


## 6. 前端安全

- [JavaScript反调试技巧](http://www.freebuf.com/articles/system/163579.html)
- [Devtools detect](https://github.com/sindresorhus/devtools-detect)
- [代码混淆](https://github.com/javascript-obfuscator/javascript-obfuscator)


## 7. 业务安全

### 7.1 PC设备指纹

- [fingerprintjs2](https://github.com/Valve/fingerprintjs2)
- [跨浏览器设备指纹](https://github.com/Song-Li/cross_browser)
- [2.5代指纹追踪技术—跨浏览器指纹识别](https://paper.seebug.org/350/)

### 7.2 安全水印

- [水印开发](https://github.com/saucxs/watermark)
- [水印的攻击与防御](https://joychou.org/business/watermark-security.html)



## 8. JAVA安全


- [find-sec-bug](http://find-sec-bugs.github.io/bugs.htm)
- [Java安全漏洞及漏洞代码](https://github.com/JoyChou93/java-sec-code)


### 8.1 RASP

- [OpenRASP](https://github.com/baidu/openrasp)
- [RASP，从 Java 反序列化命令执行说起](https://toutiao.io/posts/4kt0al/preview)

### 8.2 Java反序列化

- [Lib之过？Java反序列化漏洞通用利用分析](https://blog.chaitin.cn/2015-11-11_java_unserialize_rce/)
- [JAVA Apache-CommonsCollections 序列化漏洞分析以及漏洞高级利用](https://www.iswin.org/2015/11/13/Apache-CommonsCollections-Deserialized-Vulnerability/)
- [Java反序列化漏洞-玄铁重剑之CommonsCollection(上)](https://xz.aliyun.com/t/2028)
- [Commons Collections Java反序列化漏洞分析](https://joychou.org/java/commons-collections-java-deserialize-vulnerability-analysis.html)

### 8.3 JDWP

这个漏洞可能会有意想不到的收获。

- [Hacking the Java Debug Wire Protocol](http://blog.ioactive.com/2014/04/hacking-java-debug-wire-protocol-or-how.html)
- [Java Debug Remote Code Execution](https://joychou.org/web/Java-Debug-Remote-Code-Execution.html)
- [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier)


### 8.4 Java SSRF

- [Java SSRF 漏洞代码](https://github.com/JoyChou93/java-sec-code/blob/master/src/main/java/org/joychou/controller/SSRF.java)
- [SSRF in Java](https://joychou.org/web/javassrf.html)
- [Use DNS Rebinding to Bypass SSRF in JAVA](https://joychou.org/web/use-dnsrebinding-to-bypass-ssrf-in-java.html)

### 8.5 Java XXE

- [Java XXE Vulnerability](https://joychou.org/web/java-xxe-vulnerability.html)
- [Java XXE 漏洞代码](https://github.com/JoyChou93/java-sec-code/blob/master/src/main/java/org/joychou/controller/XMLInjection.java)

### 8.6 URL白名单绕过

- [URL白名单绕过](https://joychou.org/web/url-whitelist-bypass.html)


## 9. PHP安全

### 9.1 PHP SSRF

- [Typecho SSRF漏洞分析和利用](https://joychou.org/web/typecho-ssrf-analysis-and-exploit.html)
- [SSRF in PHP](https://joychou.org/web/phpssrf.html)

### 9.2 PHP反序列化

- [Typecho反序列化漏洞分析](https://joychou.org/web/typecho-unserialize-vulnerability.html)
- [浅谈php反序列化漏洞](https://chybeta.github.io/2017/06/17/%E6%B5%85%E8%B0%88php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)

## 10. Python安全

- [Exploit SSTI in Flask/Jinja2](https://joychou.org/web/exploit-ssti-in-flask-jinja2.html)
- [Ptyhon沙盒绕过](https://joychou.org/web/python-sandbox-bypass.html)
- [Python安全代码审计](https://joychou.org/web/python-sec-code-audit.html)
- [Python任意命令执行漏洞修复](https://joychou.org/codesec/fix-python-arbitrary-command-execution-vulnerability.html)
- [从一个CTF题目学习Python沙箱逃逸](https://www.anquanke.com/post/id/85571)


## 11. Lua安全

- [Nginx Lua Web应用安全](https://joychou.org/web/nginx-lua-web-application-security.html)

## 12. 漏洞修复

- [Python任意命令执行漏洞修复](https://joychou.org/codesec/fix-python-arbitrary-command-execution-vulnerability.html)
- [CVE-2016-5195 Dirty Cow漏洞修复](https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-dirty-cow-linux-vulnerability)


## 13. 黑科技

- [微博PC版去广告]()

## 14. 基本技能

- Linux RPM理解及使用
- PIP理解及使用
- Python、PHP、Java、Bash
- iptables、定时任务、反弹shell
- 正向和反向代理
- Nginx使用及配置
- 域名配置
- TCP/IP、HTTP协议
- BurpSuite工具使用

## 15. 安全面试问题

>面试的问题跟自己简历相关，只是面试官会根据你回答的点继续深挖，看看你有没有回答他想要的答案。

### 15.1 甲方

#### 15.1.1 技术

基础


- 服务器的Web目录发现一个一句话webshell后门，如何排查入侵原因、后门如何清除以及排查数据是否有泄露？
- XXE常用payload
- DDOS如何人工防御？
- 邮件伪造如何防御？
- 拿到WEBSHELL，无法提权，还有什么思路？
- Linux服务器中了DDOS木马，如何使用系统自带命令清除木马？
- Linux服务器被抓鸡后的入侵原因检测思路？
- Webshell检测有什么方法？
    - 静态文本匹配，存在误报和漏洞
    - 动态hook，但要运行php代码，存在风险
    - D盾的方式
    - AST
    - 离线大数据算法
- Redis未授权访问漏洞的修复方式有哪些？入侵方式有哪些？
- 简述JSON劫持原理以及利用方式？
- SSRF一般如何利用和修复？
- 入侵分析和应急响应一般如何操作？
- XSS（反射、dom）黑盒方式一般如何检测？
- 动态检测Webshell存在什么弊端和安全风险？
- 新应用上线的安全流程？
    1. 应用设计阶段 - 整个架构、逻辑、框架的安全评估
    2. 应用开发阶段 - 提供安全相关组件
    3. 应用测试阶段 - 进行黑盒和白盒安全测试
    4. 应用上线阶段 - 外部SRC、日常黑白盒安全测试以及主机等监控等
- 在PHP中，LFI如何转变为RCE？
- CSRF漏洞一般出现在什么接口？并简述下原理以及修复方式。
- CORS绕过有什么风险，有什么利用场景？
- URL常见的绕过方式？
- 哪些漏洞WAF不好拦截？
    - JDWP这种非HTTP协议请求（主机WAF另说）
    - CSRF、JSONP、CORS绕过等Referer绕过的漏洞
    - 未授权、匿名访问、弱口令等主机漏洞
    - URL跳转
    - 信息泄露
    - SSRF利用http、file协议的攻击
- CSRF Token防御方式的整个流程？前后端分离和不分离防御有什么不同？
- WAF漏报如何统计？

深入

- SDL流程
- 挖过哪些牛逼的、有意思的漏洞？
- 安全如何闭环？
- 越权有什么检测方式？
    - 黑盒两个账户Cookie
    - 鉴权函数 + 数据库查询
- 类似JDWP这种传统HTTP层WAF不能拦截，可以如何检测？
    - RASP
    - 命令监控(父进程是Java，并且执行了恶意命令)
- Java反序列化如何检测和防御？
- HTTP请求日志和数据库日志都有的情况下，如何检测存储型XSS？
    - 只要数据库存在未编码、过滤的xss payload其实已经存在存储型XSS了，HTTP请求日志作用不是很大。
- 如何判断WAF拦截的攻击请求中，哪些请求是人为请求，哪些是扫描器请求？

#### 15.1.2 非技术

- 觉得自己哪方面比较牛逼
- 为什么离开之前公司
- 在之前公司的成长
- 工作成就感
- 做的最大、最牛逼的项目
- 对未来规划是什么
- 安全培训怎样衡量价值？
- 后面安全的方向是什么？
-﻿对自己在安全的定位是什么？
