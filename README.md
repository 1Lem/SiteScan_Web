<h1 align="center" >SiteScan</h1>



## 0x01 介绍

功能：包括域名ip历史解析、nmap常见端口爆破、子域名信息收集、旁站信息收集、whois信息收集、网站架构分析、cms解析、备案号信息收集、CDN信息解析、是否存在waf检测、后台寻找以及生成检测结果html报告表等。
增加web端功能
基于kracer127/SiteScan源项目进行的二次开发；
增加了web端使用功能；
支持web端输入数据自动进行信息收集；
支持web端资产批量自动信息收集；
支持在线查询信息收集报表；
http://ip:8124/index

## 0x02 安装使用

1、所需库安装

```python
pip3 install -r requirements.txt
```

2、使用

```python
>>python3 main.py -u http://www.xxx.com
>>python3 main.py -f url.txt
>>python3 main.py -u http://www.xxx.com -p http://127.0.0.1:8080
```

3、说明

```python
文件夹：lib文件夹 --- 配置文件。
文件夹: output文件夹 --- 探测结果生成的html报告表。
文件夹：Third --- 第三方模块, 包含wafwoof识别云waf、JSFinder爬取js文件。
文件：commom.py --- 用户输入处理、网址存活检测及处理最终结果并生成html报告。
文件：config.py --- requests库的请求设置：header头部、超时时间、google的url提取量、网络错误尝试次数、重定向和代理设置，以及定义扫描的端口。
文件：main.py --- 主函数入口。
文件：request_scan.py --- 封装的所有请求类。
```



## 0x03 参考
https://github.com/kracer127/SiteScan/releases/tag/v.1.5 
