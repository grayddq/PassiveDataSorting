# -*- coding: utf-8 -*-\
import re

NAME, VERSION, AUTHOR, LICENSE = "PublicDataSorting", "V0.1", "咚咚呛", "Public (FREE)"


class Filter():
    def __init__(self, target, rules):
        self.target = target
        self.protocol = target['protocol']
        self.ng_request_url_short = target['ng_request_url_short']
        self.domain = target['domain']
        self.method = target['method']
        self.arg = target['arg']
        self.rules = rules

    def filter(self):
        for rule in self.rules:
            pattern = re.compile(rule['rule'])
            short_list = []
            if rule['field'] == 'method':
                str = self.method
            elif rule['field'] == 'protocol':
                str = self.protocol
            elif rule['field'] == 'domain':
                str = self.domain
            elif rule['field'] == 'arg':
                str = self.arg
            else:
                short_list = self.ng_request_url_short.split('?')
                str = short_list[0]

            if rule['action'] == 'open':
                if pattern.search(str):
                    continue
                else:
                    return True
            elif rule['action'] == 'replace':
                if pattern.search(str):
                    result, number = pattern.subn(rule['replace'], str)
                    if rule['field'] == 'method':
                        self.method = result
                        self.target['method'] = result
                    elif rule['field'] == 'protocol':
                        self.protocol = result
                        self.target['protocol'] = result
                    elif rule['field'] == 'domain':
                        self.domain = result
                        self.target['domain'] = result
                    elif rule['field'] == 'arg':
                        self.arg = result
                        self.target['arg'] = result
                    else:
                        short_list[0] = result
                        self.ng_request_url_short = '?'.join(short_list)
                        self.target['ng_request_url_short'] = '?'.join(short_list)
            else:
                if pattern.search(str):
                    return True
        return False
