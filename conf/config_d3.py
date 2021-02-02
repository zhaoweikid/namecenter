# vim: set ts=4 et sw=4 sts=4 fileencoding=utf-8 :
import os, sys

HOME = os.path.dirname(os.path.abspath("__file__"))
if os.path.basename(HOME).isdigit():
    HOME = os.path.dirname(HOME)
print(HOME)

# 服务地址
HOST = '0.0.0.0'

# 服务端口
PORT = 6003

# 调试模式: True/False
# 生产环境必须为False
DEBUG = True

# 日志文件配置
if DEBUG:
    LOGFILE = 'stdout'
else:
    LOGFILE = os.path.join(HOME, 'log/%s.d3.log' % os.path.basename(HOME))

# 数据目录
DATA_DIR = os.path.join(HOME, 'data3')

# 数据过期时间(s)
EXPIRE = 10

# 服务名称，在一组服务中名字必须唯一
SERVER_NAME = 'name03'
# 服务组名
GROUP_NAME = 'mygroup'
# 组内的所有服务地址
GROUP_SERVER = [
    {'addr':('127.0.0.1', 6001), 'name':'name01'}, 
    {'addr':('127.0.0.1', 6002), 'name':'name02'}, 
    {'addr':('127.0.0.1', 6003), 'name':'name03'},
]
GROUP_SERVER_MAP = { x['name']:x  for x in GROUP_SERVER }
# 服务组内认证KEY
AUTH_KEY = 'dcb9c29daed54c15bb41bab9df6f487b'

# 是否需要在组内同步数据
GROUP_SYNC = True

