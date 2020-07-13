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
    _footprints = {'headers': 'nginx-wallarm',
                   'server': 'wallarm'}

    def check(self, response):
        if self._footprints['headers'] in response.headers or self._footprints['server'] in response.headers['server']:
            self.set_detected(True)


class Varnish(BaseWAF):
    name = 'xVarnish'
    _footprints = {'body': 'Request rejected by xVarnish-WAF'}

    def check(self, response):
        if self._footprints['body'] in response.text:
            self.set_detected(True)


class Cloudflare(BaseWAF):
    name = 'Cloudflare'
    _footprints = {'server': 'cloudflare'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            self.set_detected(True)


class Qrator(BaseWAF):
    name = 'Qrator'
    _footprints = {'server': 'QRATOR'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            self.set_detected(True)


class ModSecurity(BaseWAF):
    name = 'ModSecurity'
    _footprints = {'server': ('mod_security', 'NOYB'),
                   'body': 'mod_security'}

    def check(self, response):
        if response.headers['server'] in self._footprints['server'] or self._footprints['body'] in response.text:
            self.set_detected(True)


class NAXSI(BaseWAF):
    name = 'NAXSI'
    _footprints = {'server': 'naxsi',
                   'body': 'blocked by naxsi'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server'] or self._footprints['body'] in response.text:
            self.set_detected(True)


class Nemesida(BaseWAF):
    name = 'Nemesida'
    _footprints = {'body': ('nemesida',
                            'Suspicious activity detected. Access to the site is blocked',
                            'nwaf')}

    def check(self, response):
        for content in self._footprints['body']:
            if content in response.text:
                self.set_detected(True)
                break


wafs = [Wallarm, Varnish, Cloudflare, Qrator, ModSecurity, NAXSI, Nemesida]
