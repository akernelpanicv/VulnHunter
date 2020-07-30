class WAFInspector:
    name = ''
    _footprints = {'headers': '',
                   'server': '',
                   'cookie': '',
                   'status_code': '',
                   'body': ''}

    def __init__(self, *args, **kwargs):
        self.detected = False
        self.check(*args, **kwargs)

    def check(self, *args, **kwargs):
        raise NotImplementedError


class Wallarm(WAFInspector):
    name = 'Wallarm'
    _footprints = {'headers': 'nginx-wallarm',
                   'server': 'wallarm'}

    def check(self, response):
        if self._footprints['headers'] in response.headers or self._footprints['server'] in response.headers['server']:
            self.detected = True


class Varnish(WAFInspector):
    name = 'xVarnish'
    _footprints = {'body': 'Request rejected by xVarnish-WAF'}

    def check(self, response):
        if self._footprints['body'] in response.text:
            self.detected = True


class Cloudflare(WAFInspector):
    name = 'Cloudflare'
    _footprints = {'server': 'cloudflare'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            self.detected = True


class Qrator(WAFInspector):
    name = 'Qrator'
    _footprints = {'server': 'QRATOR'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server']:
            self.detected = True


class ModSecurity(WAFInspector):
    name = 'ModSecurity'
    _footprints = {'server': ('mod_security', 'NOYB'),
                   'body': 'mod_security'}

    def check(self, response):
        if response.headers['server'] in self._footprints['server'] or self._footprints['body'] in response.text:
            self.detected = True


class NAXSI(WAFInspector):
    name = 'NAXSI'
    _footprints = {'server': 'naxsi',
                   'body': 'blocked by naxsi'}

    def check(self, response):
        if self._footprints['server'] in response.headers['server'] or self._footprints['body'] in response.text:
            self.detected = True


class Nemesida(WAFInspector):
    name = 'Nemesida'
    _footprints = {'body': ('nemesida',
                            'Suspicious activity detected. Access to the site is blocked',
                            'nwaf')}

    def check(self, response):
        for content in self._footprints['body']:
            if content in response.text:
                self.detected = True
                break
