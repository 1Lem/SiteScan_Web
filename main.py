# -*- coding:utf-8 -*-
# by:1Lem

# 引入模块、包部分
import datetime
import os

from request_scan import *   # 获取返回内容
from common import *
from threading import Thread
from colorama import init
init(autoreset=True)  # 让终端输出字体变色效果只对当前输出起作用
import warnings
from flask import Flask, request, jsonify,redirect,url_for,send_from_directory, render_template_string
from flask_cors import CORS
from datetime import datetime
warnings.filterwarnings("ignore")

app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = 'uploads'  # 设置上传文件夹名
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # 告诉 Flask 在哪里找到上传的文件夹

# 定义的常量、变量
t = []  # 线程组
logo = '''\033[1;32m
  ____   *     _                ____ 
   _____  _  _          _____                                   _     
  / ____|(_)| |        / ____|                                 | |    
 | (___   _ | |_  ___ | (___    ___  __ _  _ __ __      __ ___ | |__  
  \___ \ | || __|/ _ \ \___ \  / __|/ _` || '_ \\ \ /\ / // _ \| '_ \ 
  ____) || || |_|  __/ ____) || (__| (_| || | | |\ V  V /|  __/| |_) |
 |_____/ |_| \__|\___||_____/  \___|\__,_||_| |_| \_/\_/  \___||_.__/ 
                                              ______                  
                                             |______|                 

                                                        \033[1;36mBy:1Lem
                                                        \033[1;36mGithub:https://github.com/1Lem\033[0m
'''


# 对allDict的数据进行清空处理
def clearAll():
    '''
    allDict = {'nowIP': [], 'domain': [], 'ports': [], 'whois': [], 'beiAn': [], 'framework': [[], {}, {}], 'urlPATH': [], 'isCDN': [], 'pangZhan': [], 'historyIP': [], 'error': []}
    '''
    try:
        allDict['nowIP'] = []
        allDict['domain'] = []
        allDict['ports'] = []
        allDict['whois'] = []
        allDict['beiAn'] = []
        allDict['framework'] = [[], {}, {}]
        allDict['urlPATH'] = []
        allDict['isCDN'] = []
        allDict['pangZhan'] = []
        allDict['historyIP'] = []
        allDict['error'] = []
    except Exception as e:
        pass


# 多线程解决批查询(暂未实现，不稳定)
def startMainThread(ip_url):
    ''' 判断网址是否有误 '''    ## 可改进地方 ##
    test = processUrl(ip_url)
    if test == []:
        print('\033[1;31m[-] 网址输入有误，请检查后再试！\033[0m')
        return None
    ''' 正确进入主函数查询 '''
    url = processUrl(ip_url)[0]
    subDomain = processUrl(ip_url)[-1]
    if isAlive(url) == True:  # 检测用户输入网址是否有效
        main(url, subDomain)
    else:
        print('\033[1;35m[-] 当前网址 {0} 不可访问, 尝试根域名信息查询!!\033[0m'.format(url))
        request_scan(subDomain).IP138()
        request_scan(subDomain).Icp()
        request_scan(subDomain).getCrtDomain()
        request_scan(subDomain).Chaziyu()
        request_scan(subDomain).virusDomain()
        request_scan(subDomain).googleHack()
        print('\033[1;34m[-] 根域名 {0} 信息查询完毕!!\033[0m'.format(subDomain))
    print('[*] 网址：{0} 所有检测任务完成, 开始生成检测报告......'.format(url))
    all2HTML(url, allDict)
    clearAll()


# 主函数入口
def main(url, subDomain):
    tasks = []
    print('[+] ============ 网址：{0} 检测任务开启, 预估需要3~5min ============'.format(url))

    """ 入口一: 域名资产清查"""
    # 1.进入<domain2ip函数>获取当前url的ip解析及粗略地理位置
    t1 = request_scan(url).domain2ip()
    t1_1 = Thread(target=t1)
    tasks.append(t1_1)
    # 2.进入<IP138函数>获取备案、子域名、历史ip绑定信息
    t2 = request_scan(url).IP138()
    t2_1 = Thread(target=t2)
    tasks.append(t2_1)
    # 3.进入<Icp函数>获取备案信息
    t3 = request_scan(subDomain).Icp()
    t3_1 = Thread(target=t3)
    tasks.append(t3_1)
    # 4.进入<crt.sh函数>获取子域名信息
    t4 = request_scan(subDomain).getCrtDomain()
    t4_1 = Thread(target=t4)
    tasks.append(t4_1)
    # 5.进入<virusTotal函数>获取子域名信息
    t5 = request_scan(subDomain).virusDomain()
    t5_1 = Thread(target=t5)
    tasks.append(t5_1)
    # 6.进入<Chaziyu函数>获取子域名函数
    t6 = request_scan(subDomain).Chaziyu()
    t6_1 = Thread(target=t6)
    tasks.append(t6_1)
    # 7.进入<isCDN函数>判断是否存在CDN信息
    t7 = request_scan(url).isCDN()
    t7_1 = Thread(target=t7)
    tasks.append(t7_1)


    """ 入口二: 网站资产清查 """
    # 1.进入<whatweb函数>获取网站的架构信息
    t8 = request_scan(url).whatWeb()
    t8_1 = Thread(target=t8)
    tasks.append(t8_1)
    # 2.进入<JSfinder函数>获取子所有域名+url路径
    t9 = request_scan(url).jsFinder()
    t9_1 = Thread(target=t9)
    tasks.append(t9_1)
    # 3.进入<GoogleHacking>函数 查找js文件及提取子域名
    t10 = request_scan(url).googleHack()
    t10_1 = Thread(target=t10)
    tasks.append(t10_1)
    # 4.进入<wafw00f>函数 侦探网站的waf
    def mainDetect():
        domain = allDict['urlPATH']
        keyURL_list = []
        for k in domain:
            if ('=' in k) and ('?' in k):
               keyURL_list.append(k)
        if len(keyURL_list) >= 2:
            request_scan(keyURL_list[0]).detectWaf()
            request_scan(keyURL_list[1]).detectWaf()
        elif len(keyURL_list) == 1:
            request_scan(keyURL_list[0]).detectWaf()
            request_scan(url).detectWaf()
        else:
            request_scan(url).detectWaf()
            if len(domain) > 0:
                request_scan(domain[0]).detectWaf()
        print("\033[1;34m[*] 完成网站waf信息侦测, 共"+str(len(allDict['framework'][2]))+"条数据!!\033[0m")
    t11 = mainDetect()
    t11_1 = Thread(target=t11)
    tasks.append(t11_1)


    """ 入口三: 不存在CDN下网站IP资产清查 """
    # 1.进入<PangZhan函数>获取当前域名IP下的同服务器网站
    t12 = request_scan(url).pangZhan()
    t12_1 = Thread(target=t12)
    tasks.append(t12_1)
    # 2.进入<getPorts函数>获取网站开发端口信息
    t13 = request_scan(url).getPorts()
    t13_1 = Thread(target=t13)
    tasks.append(t13_1)

    for i in tasks:
        i.start()
    for j in tasks:
        j.join()


def web_server_scan(url,file):
    urlList = []
    print(f"url: {url}")
    print(f"file: {file}")
    if url:
        urlList.append(url)
    if file:
        try:
            with open(file, 'r', encoding='utf-8') as u:
                dataURL = u.readlines()
                for i in dataURL:
                    urlList.append(i.strip())
                if urlList == []:  # 文件判空
                    print('\033[1;31m[-] 文件错误，请检查后再试！\033[0m')
        except Exception as e:
            print('\033[1;31m[-] 文件错误，请检查后再试！\033[0m')
    start = time.time()
    for ip_url in urlList:
        startMainThread(ip_url)
    end = time.time()
    print("\033[1;36m[*] 本次检测共消耗时间:{:.2f}s\033[0m".format(end - start))

@app.route('/web_sitescan', methods=['POST'])
def web_sitescan():
    web_url = request.form['web_url']
    url = web_url
    print(f"url: {url}")
    web_server_scan(url,None)
    return jsonify({"ScanOut":"扫描完成,访问报表列表查看详情"})
@app.route('/web_sitescan_file', methods=['POST'])
def web_sitescan_file():
    web_urls_file = request.files['web_urls_file']
    # 获取当前的时间戳
    timestamp = time.time()
    # 将时间戳格式化为字符串，这里使用了 datetime 对象来更容易地进行格式化
    timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{timestamp_str}.txt")
    web_urls_file.save(filepath)
    #file = filepath
    print(f"file: {filepath}")
    web_server_scan(None,filepath)
    return jsonify({"ScanOut":"扫描完成,访问报表列表查看详情"})

@app.route('/index', methods=['GET', 'POST'])
def web_index():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    index_html_path = os.path.join(current_dir, 'html', 'index.html')
    #print(index_html_path)
    try:
        with open(index_html_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return "Error: index not found."

@app.route('/files', methods=['GET'])
def list_files():
    # 获取 output 目录的绝对路径
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
    # 获取目录下的所有文件
    files = os.listdir(output_dir)
    # 创建一个 HTML 模板字符串来展示文件列表
    html_template = """  
    <!DOCTYPE html>  
    <html>  
    <head>  
        <title>File Browser</title>  
    </head>  
    <body>  
        <h1>Output Directory Files</h1>  
        <ul>  
            {% for file in files %}  
            <li><a href="/files/{{ file }}">{{ file }}</a></li>  
            {% endfor %}  
        </ul>  
    </body>  
    </html>  
    """

    # 渲染模板并返回文件列表
    return render_template_string(html_template, files=files)


@app.route('/files/<path:filename>')
def read_report_file(filename):
    # 获取 output 目录的绝对路径
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')

    # 拼接文件的完整路径
    file_path = os.path.join(output_dir, filename)

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return "File not found", 404

@app.route('/<path:path>')
def serve_static_file(path):
    root_dir = os.path.dirname(os.path.abspath(__file__))
    static_folder = os.path.join(root_dir, '')
    #print(static_folder)
    return send_from_directory(static_folder, path)

def web_server_start():
    app.run(debug=False, port=8124, host='0.0.0.0')

def cmd_start():
    urlList = []
    args = parse_args()
    if args.url:
        print(args.url)
        urlList.append(args.url)
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as u:
                dataURL = u.readlines()
                for i in dataURL:
                    urlList.append(i.strip())
                if urlList == []:  # 文件判空
                    print('\033[1;31m[-] 文件错误，请检查后再试！\033[0m')
        except Exception as e:
            print('\033[1;31m[-] 文件错误，请检查后再试！\033[0m')
    start = time.time()
    for ip_url in urlList:
        startMainThread(ip_url)
    end = time.time()
    print("\033[1;36m[*] 本次检测共消耗时间:{:.2f}s\033[0m".format(end - start))


if __name__ == '__main__':
    print(logo)
    args = parse_args()
    if args.url is None and args.file is None:
        web_server_start()
    else:
        cmd_start()





