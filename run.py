from lib.sniffer import *
from lib.config import *

if __name__ == "__main__":
    redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
    if not 'conf_sniffer_rule' in redis_r.hkeys('passive_config'):
        redis_r.hset('passive_config', 'conf_sniffer_rule',conf_sniffer_rule)
    Capute().run()
