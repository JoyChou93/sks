# Security Knowledge Structure


## 企业安全

### 黑盒扫描器


#### 扫描姿势


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

### 文件监控和同步

- [lsyncd (文件监控)](https://github.com/axkibe/lsyncd)

### Java安全开发组件

- [trident](https://github.com/JoyChou93/trident)



## WEB安全


### CSRF

- [JSON格式的CSRF利用](https://joychou.org/web/exploiting-json-csrf.html)

### XSS

- [Flash XSS](https://joychou.org/web/flash-xss.html)

## 运维安全

### NGINX配置安全

- [Gixy (一款开源的Nginx配置安全扫描器)](https://github.com/yandex/gixy)
- [三个案例看Nginx配置安全](https://www.leavesongs.com/PENETRATION/nginx-insecure-configuration.html)
- [Nginx Config Security](https://joychou.org/web/nginx-config-security.html)

## Backdoor

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

### 菜刀

- [新版菜刀@20141213一句话不支持php assert分析](https://joychou.org/web/caidao-20141213-does-not-support-php-assert-oneword-backdoor-analysis.html)
- [菜刀连接密码不是可显示字符的一句话](https://joychou.org/web/913.html)
- [花式Bypass安全狗对菜刀特征的拦截规则](https://joychou.org/web/bypass-safedog-blocking-rules-for-chopper.html)
- [定制过狗菜刀](https://joychou.org/web/make-own-chopper-which-can-bypass-dog.html)
- [Cknife (一款开源菜刀)](https://github.com/Chora10/Cknife)

## 主机安全

### 提权



## 前端安全

- [JavaScript反调试技巧](http://www.freebuf.com/articles/system/163579.html)
- [Devtools detect](https://github.com/sindresorhus/devtools-detect)
- [代码混淆](https://github.com/javascript-obfuscator/javascript-obfuscator)


## 业务安全

### PC设备指纹

- [fingerprintjs2](https://github.com/Valve/fingerprintjs2)
- [跨浏览器设备指纹](https://github.com/Song-Li/cross_browser)
- [2.5代指纹追踪技术—跨浏览器指纹识别](https://paper.seebug.org/350/)


## 移动安全

## 小程序安全

## JAVA安全


- [find-sec-bug](http://find-sec-bugs.github.io/bugs.htm)

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

## Python安全

### SSTI

- [Exploit SSTI in Flask/Jinja2](https://joychou.org/web/exploit-ssti-in-flask-jinja2.html)

### Python沙盒绕过

- [Ptyhon沙盒绕过](https://joychou.org/web/python-sandbox-bypass.html)

### Python代码审计

- [Python安全代码审计](https://joychou.org/web/python-sec-code-audit.html)

## Lua安全

- [Nginx Lua Web应用安全](https://joychou.org/web/nginx-lua-web-application-security.html)

## 漏洞修复

- [修复Python任意命令执行漏洞](https://joychou.org/codesec/fix-python-arbitrary-command-execution-vulnerability.html)


### CVE-2016-5195 Dirty Cow
- [阿里云官方修复](https://help.aliyun.com/knowledge_detail/44786.html)
- [如何保护你的服务器修复Dirty COW (CVE-2016-5195) Linux漏洞](https://www.howtoing.com/how-to-protect-your-server-against-the-dirty-cow-linux-vulnerability)



## 黑科技

- [微博PC版去广告]()

## 安全面试问题

- TCP/IP协议
- 如果服务器上有一个phpspy.php，如何做入侵分析
- XXE常用payload
- DDOS如何人工防御
- 邮件伪造如何防御
- 拿到WEBSHELL，无法提权，还有什么思路？
- SDL流程
