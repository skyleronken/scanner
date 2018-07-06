#!/usr/bin/env python

import os
import socket, ssl
import json
from pymongo import MongoClient


def connect(cmd, args):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(s,
                               ca_certs="api_cert.pem",
                               cert_reqs=ssl.CERT_REQUIRED,
                               ssl_version=ssl.PROTOCOL_TLSv1)
    ssl_sock.connect(('127.0.0.1',9999))
    request = {'cmd':cmd, 'args':args}
    ssl_sock.send(json.dumps(request) + "\n")
    response = ssl_sock.recv(4096)
    ssl_sock.close()
    print response
    return json.loads(response)
    
def dropdb():
    c = MongoClient()
    c.drop_database('scan_db')

dropdb()

rargs = {}
rargs['ips'] = ''
rargs['ports'] = '20-50'
#rargs['agents'] = ['a','b']
rargs['default_scan'] = 'syn'
rargs['firewalk'] = False
res1 = connect('create_scan',rargs)['results']
print res1
scan_id = res1['scan_id']
rargs = {'scan_id':scan_id}
res2 = connect('start_scan', rargs)



