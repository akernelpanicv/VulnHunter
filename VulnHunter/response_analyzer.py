import sys
import logging.config

import requests
from requests.exceptions import ConnectionError

from settings import logger_config
from firewalls import WAFInspector


logging.config.dictConfig(logger_config)
logger = logging.getLogger('ResponseParser_logger')


class ResponseParser:
    def __init__(self, url):
        logger.info(' --- start response analysis ---')

        self._url = url
        self.response = self._get_response()

        for cls in BaseHandler.__subclasses__():
            cls(self.response)

    def _get_response(self):
        try:
            return requests.get(self._url)
        except ConnectionError:
            logger.critical('The page is not available!')
            sys.exit(1)


class BaseHandler:
    def __init__(self, *args, **kwargs):
        self.handle(*args, **kwargs)

    def handle(self, *args, **kwargs):
        raise NotImplementedError


class StatusCodeHandler(BaseHandler):
    def handle(self, response):
        status_code = response.status_code

        if status_code != 200:
            logger.warning(f'The response status code is {status_code}')


class WAFHandler(BaseHandler):
    def handle(self, response):
        for waf in WAFInspector.__subclasses__():
            waf = waf(response)

            if waf.detected:
                logger.info(f'WAF "{waf.name}" detected')


class CSPHandler(BaseHandler):
    def handle(self, response):
        headers = response.headers

        if 'Content-Security-Policy' not in headers:
            logger.info('CSP not detected')
        else:
            logger.info('CSP detected')
