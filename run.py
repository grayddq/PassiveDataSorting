# -*- coding: utf-8 -*-
from lib.sniffer import *
from lib.config import *

NAME, VERSION, AUTHOR, LICENSE = "PublicDataSorting", "V0.1", "咚咚呛", "Public (FREE)"

if __name__ == "__main__":
    redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
    if not 'conf_sniffer_rule' in redis_r.hkeys('passive_config'):
        redis_r.hset('passive_config', 'conf_sniffer_rule',conf_sniffer_rule)
    Capute().run()
