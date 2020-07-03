from abc import ABCMeta, abstractmethod


class BaseWAF(metaclass=ABCMeta):
    name = ''
    _detected = False
    _footprints = {'headers': '',
                   'server': '',
                   'cookie': '',
                   'status_code': '',
                   'body': ''}

    def __init__(self, *args, **kwargs):
        self.check(*args, **kwargs)

    @classmethod
    def is_detected(cls):
        return cls._detected

    @classmethod
    def set_detected(cls, value):
        cls._detected = value

    @abstractmethod
    def check(self, *args, **kwargs):
        pass


class Wallarm(BaseWAF):
    name = 'Wallarm'
    _detected = False
    _footprints = {'headers': 'nginx-wallarm',
                   'server': 'wallarm'}

    def check(self, response):
        if self._footprints['headers'] in response.headers or self._footprints['server'] in response.headers['server']:
            self.set_detected(True)


class Varnish(BaseWAF):
    name = 'xVarnish'
    _detected = False
    _footprints = {'body': 'Request rejected by xVarnish-WAF'}

    def check(self, response):
        if self._footprints['body'] in response.text:
            self.set_detected(True)


class Cloudflare(BaseWAF):
    name = 'Cloudflare'
    _detected = False
    _footprints = {'server': 'cloudflare'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            self.set_detected(True)


class Qrator(BaseWAF):
    name = 'Qrator'
    _detected = False
    _footprints = {'server': 'QRATOR'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            self.set_detected(True)


class ModSecurity(BaseWAF):
    name = 'ModSecurity'
    _detected = False
    _footprints = {}

    def check(self, response):
        pass


class NAXSI(BaseWAF):
    name = 'NAXSI'
    _detected = False
    _footprints = {}

    def check(self, response):
        pass


class Nemesida(BaseWAF):
    name = 'Nemesida'
    _detected = False
    _footprints = {}

    def check(self, response):
        pass


wafs = [Wallarm, Varnish, Cloudflare, Qrator, ModSecurity, NAXSI, Nemesida]
