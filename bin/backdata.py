# coding:utf-8
import os, sys
import config
import traceback
import time
import datetime
import logging

log = logging.getLogger()

# 支持的后端存储，leveldb/etcd
backends = {}
db = None

class Backend (object):
    def __init__(self, path='', expire=300):
        self.path = path
        self.expire = expire

    def close(self):
        pass

    def get(self, key):
        pass

    def set(self, key):
        pass

    def getall(self):
        pass

    def remove(self, key):
        pass


import plyvel

class BackendLevelDB (Backend):
    def __init__(self, path='', expire=300):
        Backend.__init__(self, path, expire)
        self.nodata = False
        self.db = plyvel.DB(self.path, create_if_missing=True)
        self._check()

    def _check(self):
        key = None
        for k,v in self.db:
            key = k
            break
        if not key:
            self.nodata = True

    def close(self):
        self.db.close()

    def get(self, key):
        return self.db.get(key)

    def set(self, key, value):
        self.nodata = True
        return self.db.put(key, value)

    def getall(self):
        ret = []
        for key,val in self.db:
            ret.append([key.decode('utf-8'), val.decode('utf-8')])
        return ret

    def remove(self, key):
        return self.db.delete(key)

backends['leveldb'] = BackendLevelDB


try:
    import etcd

    class BackendEtcd (Backend):
        def __init__(self, addr, expire=300):
            Backend.__init__(self, path, expire)
            self.db = etcd.Client(host=addr[0], port=addr[1])

        def close(self):
            pass
            #self.db.close()

        def get(self, key):
            path = '/named/' + '/'.join(key.split('.'))
            ret = self.db.read(path)
            return ret.value

        def set(self, key, value):
            path = '/named/' + '/'.join(key.split('.'))
            return self.db.write(path, value)

        def getall(self):
            pass

        def remove(self):
            pass

    backends['etcd'] = BackendEtcd

except:
    log.info(traceback.format_exc())
    log.warn('not found etcd')

def create(name='leveldb'):
    global backends, db
    db = backends[name](config.DATA_DIR)
    return db

