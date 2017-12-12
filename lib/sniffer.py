# -*- coding: utf-8 -*-
import scapy_http.http as HTTP
from scapy.all import *
from filter import *
from config import *
import time, hashlib, redis


class Capute():
    def __init__(self):
        self.port = 80
        self.redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
        self.rules = self.redis_r.hget('passive_config', 'conf_sniffer_rule') \
            if 'conf_sniffer_rule' in self.redis_r.hkeys('passive_config') else []

    def md5(self, str):
        m = hashlib.md5()
        m.update(str)
        return m.hexdigest()

    def pktTCP(self, pkt):
        if HTTP.HTTPRequest in pkt:
            request_py = pkt[TCP].payload
            request_json = {}
            if request_py.Method == "POST":
                if 'application/x-www-form-urlencoded' in pkt[HTTP.HTTPRequest].fields['Content-Type'].strip().lower() \
                        and int(pkt[HTTP.HTTPRequest].fields['Content-Length'].strip().lower()) > 0:
                    headers, body = str(request_py).split("\r\n\r\n", 1)
                    if len(body) > 0:
                        host, ng_request_url_short = request_py.Host, request_py.Path
                        request_json = {'method': 'POST',
                                        'protocol': 'http://',
                                        'domain': host,
                                        'ng_request_url_short': ng_request_url_short,
                                        'arg': body}
                        time.sleep(0.01)
            elif (request_py.Method == "GET"):
                if request_py.Path.find('?') > 0:
                    query, ng_request_url_short = \
                        request_py.Path[request_py.Path.find('?') + 1:], request_py.Path[0:request_py.Path.find('?')]
                    if query and ng_request_url_short:
                        host = request_py.Host
                        request_json = {'method': 'POST',
                                        'protocol': 'http://',
                                        'domain': host,
                                        'ng_request_url_short': ng_request_url_short,
                                        'arg': query}
                        time.sleep(0.01)
            else:
                pass
            if request_json:
                if Filter(request_json, self.rules): return
                MD5 = self.md5(request_json['method'] + request_json['ng_request_url_short'])
                self.redis_r.set('DataSort_' + MD5, request_json)

    def run(self):
        while True:
            try:
                sniff(filter='tcp and port %d' % self.port, prn=self.pktTCP, store=1)
            except BaseException, e:
                print e


if __name__ == "__main__":
    Capute().run()
