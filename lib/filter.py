# -*- coding: utf-8 -*-\
import re, redis


class Filter():
    def __init__(self, target, rules):
        self.protocol = target['protocol']
        self.ng_request_url_short = target['ng_request_url_short']
        self.domain = target['domain']
        self.method = target['method']
        self.arg = target['arg']
        self.rules = rules

    def filter(self):
        # 1、排除静态文件
        # 2、排除接口中出现一长串数字的,
        # .......
        # 排除重复接口,直接借助redis[KEY,VAULE]
        self.rules = [
            {'field': 'method', 'rule': '^(GE|POS)T$', 'remarks': '方法过滤', 'action': 'open'},
            {'field': 'protocol', 'rule': '^http(|s)://$', 'remarks': '协议过滤', 'action': 'open'},
            {'field': 'ng_request_url_short',
             'rule': '(.+)\.(htm|html|ico|mp3|js|jpg|jped|gif|xml|zip|css|png|txt|ttf|rar|gz)$', 'remarks': '排除静态文件',
             'action': 'lock'},
            {'field': 'ng_request_url_short', 'rule': '(\d+){4,}', 'remarks': '排除接口中出现一长串数字,4位以上', 'action': 'lock'},
            {'field': 'ng_request_url_short', 'rule': '\/$', 'remarks': '排除接口最后一位为/', 'action': 'lock'}
        ]
        for rule in self.rules:
            pattern = re.compile(rule['rule'])
            if rule['rule'] == 'domain':
                str = self.domain
            elif rule['rule'] == 'arg':
                str = self.domain
            else:
                str = self.ng_request_url_short
            if pattern.search(str):
                if rule['action'] == 'open':
                    continue
                else:
                    return True
        return False
