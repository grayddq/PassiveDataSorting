# -*- coding: utf-8 -*-
# redis信息
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_PASSWORD = '11111'
REDIS_DB = 5

# field 代表5元素中字段名称，method/protocol/domain/ng_request_url_short/arg
# rule 代表需要匹配的正则
# remarks 代表备注信息
# action代表行为，open匹配放过不匹配拦截、lock匹配拦截，replace匹配替换
# replace代表，当action为replace为时，匹配替换
conf_sniffer_rule = [
    {'field': 'method', 'rule': '^(GE|POS)T$', 'remarks': '方法过滤只允许GET/POST', 'action': 'open'},
    {'field': 'protocol', 'rule': '^http://$', 'remarks': '协议过滤只允许http://', 'action': 'open'},
    {'field': 'domain', 'rule': 'www\.test\.com', 'remarks': '禁止www.test.com', 'action': 'lock'},
    {'field': 'ng_request_url_short', 'rule': '(.+)\.(ico|mp3|js|jpg|jped|gif|xml|zip|css|png|txt|ttf|rar|gz)$',
     'remarks': '排除静态文件', 'action': 'lock'},
    {'field': 'ng_request_url_short', 'rule': '(\d+){5,}', 'replace': 'xxxxxx', 'remarks': '接口出现5位以上数字进行替换',
     'action': 'replace'},
    {'field': 'ng_request_url_short', 'rule': '/$', 'replace': '', 'remarks': '假如接口最后一位为/进行删除',
     'action': 'replace'}
]
