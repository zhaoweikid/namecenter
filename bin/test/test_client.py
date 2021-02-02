# coding:utf-8
import sys, os
HOME = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(HOME))
import random
import time, datetime
from zbase3.base import logger
log = logger.install('stdout')
from zbase3.server import rpcserver
from zbase3.server.defines import *

port = 6001
addr1 = {'addr':('127.0.0.1', port), 'timeout':1000}
addr2 = {'addr':('127.0.0.1', port+1), 'timeout':1000}
addr3 = {'addr':('127.0.0.1', port+2), 'timeout':1000}

class BaseTest:
    def setup_class(self):
        self.name = 'test1'
        self.c1 = rpcserver.RPCClient(addr1)
        self.c2 = rpcserver.RPCClient(addr2)
        self.c3 = rpcserver.RPCClient(addr3)

class TestPing (BaseTest):
    def test_ping(self):
        ret, data = self.c1.ping(data='ping')
        print(ret, data)
        assert ret == OK
        ret, data = self.c2.ping(data='ping')
        print(ret, data)
        assert ret == OK
        ret, data = self.c3.ping(data='ping')
        print(ret, data)
        assert ret == OK

class TestQuery (BaseTest):
    '''
    1. 不存在的服务名，查询不到数据
    2. 存在服务名下所有的server信息都会返回
    3. 如果服务名下有server的上报时间已经过期，不会被返回
    '''
    
    def test_1(self):
        name = 'notestname'
        ret,data = self.c1.query(name=name)
        print(ret)
        assert ret == OK
        assert not data[name]

    def test_2(self):
        name = 'name_test_02'
        addr1 = ('127.0.0.1', 10000)
        addr2 = ('127.0.0.1', 10001)
        addr3 = ('127.0.0.1', 10003)
        self.c1.remove(name=name, addr=None)
        
        now = int(time.time())
        self.c1.report(name=name, server={'addr':addr1,'timeout':1000}, weight=1, rtime=now)
        time.sleep(0.5)

        for c in [self.c1, self.c2, self.c3]:
            print('server:', c._server)
            ret,data = c.query(name=name)
            print(ret)
            assert ret == OK
            assert len(data[name]) == 1
            addr = data[name][0]['server']['addr']
            assert addr[0] == addr1[0] and addr[1] == addr1[1]


        now = int(time.time())
        self.c1.report(name=name, server={'addr':addr2,'timeout':1000}, weight=1, rtime=now)
        self.c1.report(name=name, server={'addr':addr3,'timeout':1000}, weight=1, rtime=now)
        time.sleep(0.5)

        for c in [self.c1, self.c2, self.c3]:
            print('server:', c._server)
 
            ret,data = c.query(name=name)
            print(ret)
            assert ret == OK
            assert len(data[name]) == 3



    def test_3(self):
        name = 'name_test_03'
        addr1 = ('127.0.0.1', 10000)

        self.c1.remove(name=name, addr=None)

        now = int(time.time())
        self.c1.report(name=name, server={'addr':addr2,'timeout':1000}, weight=1, rtime=now)
        
        ret,data = self.c1.query(name=name)
        print(ret)
        assert ret == OK
        assert len(data[name]) == 1

        time.sleep(11)

        ret,data = self.c1.query(name=name)
        print(ret)
        assert ret == OK
        assert len(data[name]) == 0


class TestReport (BaseTest):
    '''
    1. 上报的服务地址可以立即查询到
    '''
    def test_1(self):
        name = 'name_report_test_01'
        now = int(time.time())
        ip = '127.0.0.%d' % (random.randint(1,250))
        port = 20000
        addr1 = (ip, port)

        self.c1.remove(name=name, addr=None)

        self.c1.report(name=name, server={'addr':addr1,'timeout':1000}, weight=1, rtime=now)
        time.sleep(0.5)

        for c in [self.c1, self.c2, self.c3]:
            print('server:', c._server)
            ret,data = c.query(name=name)
            print(ret)
            assert ret == OK
            assert len(data[name]) > 0
            addr = data[name][0]['server']['addr']
            assert addr[0] == addr1[0] and addr[1] == addr1[1]


class TestSync (BaseTest):
    def test_1(self):
        '''未认证不能访问其他接口'''
        ret,data = self.c1.sync(token='xxxxx', method="report", 
            data={"server":{"addr":(), "timeout":1000}, "weight":1}, ctime=int(time.time()))
        print(ret)
        assert ret != OK

    def test_2(self):
        '''token错误不能auth成功，就不能访问其他接口'''
        ret,data = self.c1.auth(key='11111111111111111111111111111111')
        print(ret)
        assert ret != OK

        ret,data = self.c1.sync(token='xxxxx', method="report", 
            data={"server":{"addr":(), "timeout":1000}, "weight":1}, ctime=int(time.time()))
        print(ret)
        assert ret != OK


        
def main():
    f = globals()[sys.argv[1]]
    f()

if __name__ == '__main__':
    main()



