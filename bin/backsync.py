# coding:utf-8
import os, sys
from Crypto.Cipher import AES
import base64
from zbase3.server.rpcserver import RPCClient
from zbase3.server.defines import *
import queue
import traceback
import time
import datetime
import gevent
import logging
import config
import backdata

log = logging.getLogger()

# 所有已经连接的节点
servers = {}

q = queue.Queue()
 
class AESCrypt():
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC
     
    def enc(self, text):
        cryptor = AES.new(self.key, self.mode, self.key[:16])
        if isinstance(text, str):
            text = text.encode('utf-8')
        text = text + (b'\0' * (16-len(text)%16))
        ctext = cryptor.encrypt(text)
        return base64.b64encode(ctext)
     
    def dec(self, text):
        cryptor = AES.new(self.key, self.mode, self.key[:16])
        plain_text = cryptor.decrypt(base64.b64decode(text))
        return plain_text.rstrip(b'\0').decode('utf-8')

class SyncOneServer:
    def __init__(self, conf):
        # 已经建立连接的server信息
        self.name = conf['name']
        self.addr = conf['addr']
        self.ac = AESCrypt(config.AUTH_KEY)
        self.authstr = self.ac.enc('%s|%s' % (config.GROUP_NAME, config.SERVER_NAME)).decode('utf-8')
        self.token = ''
        self.c = None
        self.q = queue.Queue()

        if not self.addr:
            raise ValueError('server name %s error' % name)

    def close(self):
        if self.c:
            self.c._close()
            self.c = None

    def is_connected(self):
        if self.c:
            return True
        return False

    def push(self, msg):
        msg['ctime'] = int(time.time())
        log.debug('push %s %s', self.name, msg)
        self.q.put(msg)

    def connect(self):
        self.c = RPCClient({'addr':self.addr, 'timeout':1000})
        ret, result = self.c.auth(key=self.authstr)
        if ret == OK:
            self.token = result['token']
            return True
        else:
            self.close()
            return False

    def check_server(self):
        try:
            if not self.c:
                self.connect()
            self.c.ping(data='ping')
        except:
            self.close()
            log.warn(traceback.format_exc())

    def send(self, msg):
        msg['token'] = self.token
        try:
            log.debug('msg:%s', msg)
            self.c.sync(**msg)
        except:
            self.c._close()
            self.c = None
            log.warn(traceback.format_exc())
                
    def run(self):
        log.debug('start run sync %s', self.name)
        while True:
            try:
                if not self.c:
                    self.connect()

                log.info('%s sync len:%d', self.name, self.q.qsize())
                now = int(time.time())

                try:
                    msg = self.q.get(True, 10)
                except queue.Empty: 
                    self.check_server()
                    continue
                # 超过30s的数据已经太旧了，丢弃
                log.debug('get msg:%s', msg)
                if now - msg['ctime'] > config.EXPIRE:
                    log.debug('msg too old, skip %s', msg)
                    continue
                self.send(msg)
            except KeyboardInterrupt:
                raise
            except:
                self.close()
                gevent.sleep(1)
                log.warn(traceback.format_exc())


def push(msg):
    global servers

    for name,serv in servers.items():
        serv.push(msg)

def run_sync(server):
    server.run()

def sync_servers():
    if not config.GROUP_SYNC:
        return
   
    global servers
    for one in config.GROUP_SERVER:
        if one['name'] == config.SERVER_NAME:
            continue
        s = SyncOneServer(one)
        servers[one['name']] = s
        gevent.spawn(run_sync, s)
    

