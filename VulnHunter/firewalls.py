import logging.config
from settings import logger_config

from abc import ABCMeta, abstractmethod


logging.config.dictConfig(logger_config)
logger = logging.getLogger('ResponseParser_logger')


class BaseWAF(metaclass=ABCMeta):
    _footprints = {'headers': '',
                   'server': '',
                   'cookie': '',
                   'status_code': '',
                   'body': ''}

    def __init__(self, *args, **kwargs):
        self.check(*args, **kwargs)

    @abstractmethod
    def check(self, *args, **kwargs):
        pass


class Wallarm(BaseWAF):
    _footprints = {'headers': 'nginx-wallarm',
                   'server': 'wallarm'}

    def check(self, response):
        if self._footprints['headers'] in response.headers or self._footprints['server'] in response.headers['server']:
            logger.info('WAF "Wallarm" detected')


class Citrix(BaseWAF):
    _footprints = {}

    def check(self, response):
        pass


class Varnish(BaseWAF):
    _footprints = {}

    def check(self, response):
        pass


class Cloudflare(BaseWAF):
    _footprints = {'server': 'cloudflare'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            logger.info('WAF "Cloudflare" detected')


class Qrator(BaseWAF):
    _footprints = {'server': 'QRATOR'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            logger.info('WAF "Qrator" detected')


class ModSecurity(BaseWAF):
    _footprints = {}

    def check(self, response):
        pass


class NAXSI(BaseWAF):
    _footprints = {}

    def check(self, response):
        pass


class Nemesida(BaseWAF):
    _footprints = {}

    def check(self, response):
        pass


wafs = [Wallarm, Citrix, Varnish, Cloudflare, Qrator, ModSecurity, NAXSI, Nemesida]
