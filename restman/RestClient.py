import ssl
import http.client
from urllib.parse import urlparse
import json
import logging


#
# user defined exception
#
class RestManError(Exception):
    value = ''

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class SSLError(RestManError):
    pass


class ServerCertError(SSLError):
    pass


class ClientCertError(SSLError):
    pass


class ClientKeyError(SSLError):
    pass


class JSONFormatError(RestManError):
    pass


#
# Rest client class
#
class RestClient:
    name = 'RestClient'
    debug = False
    logger = None

    default_headers = {
        'User-Agent': 'RestClient/1.0',
        'Accept': 'application/json',
        'Connection': 'Keep-Alive'
    }

    def __init__(self, **kwargs):
        # set name
        if 'name' in kwargs and type(kwargs['name']) == str:
            self.name = kwargs['name']
        # create logger
        if 'debug' in kwargs and type(kwargs['debug']) == bool:
            self.debug = kwargs['debug']
        self.logger = self.__create_logger(debug=self.debug)

    def __create_logger(self, debug):
        if debug:
            logging.basicConfig(level=logging.DEBUG,
                                format='%(asctime)s %(name)s %(levelname)s %(message)s')
        else:
            logging.basicConfig(level=logging.INFO,
                                format='%(asctime)s %(name)s %(levelname)s %(message)s')
        logger = logging.getLogger('RestClient')
        return logger

    def __is_json(self, json_string):
        try:
            json.loads(json_string)
        except ValueError as e:
            return False
        return True

    def __print_json(self, json_string):
        try:
            _json_object = json.loads(json_string)
        except ValueError as e:
            self.logger.error("input data is not JSON format, please check the format.")
        print(json.dumps(_json_object, indent=4, sort_keys=True))

    def __convert_ssl_settings(self, ssl_settings):
        if 'ssl_mutual_auth' in ssl_settings:
            _ssl_mutual_auth = ssl_settings['ssl_mutual_auth']
        else:
            _ssl_mutual_auth = None
        if 'server_cert' in ssl_settings:
            _server_cert = ssl_settings['server_cert']
        else:
            _server_cert = None
        if 'client_cert' in ssl_settings:
            _client_cert = ssl_settings['client_cert']
        else:
            _client_cert = None
        if 'client_key' in ssl_settings:
            _client_key = ssl_settings['client_key']
        else:
            _client_key = None
        return _ssl_mutual_auth, _server_cert, _client_cert, _client_key

    #
    # inputs:
    # server_cert: string
    # check_hostname: bool (optional, False)
    # client_cert: string (optional, None)
    # client_key: string (optional, None)
    #
    # outputs:
    # context: SSLContext
    #
    def __get_ssl_context(self, server_cert, **kwargs):
        # ssl settings
        _context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        _context.verify_mode = ssl.CERT_REQUIRED
        _context.load_verify_locations(server_cert)

        if 'check_hostname' in kwargs and type(kwargs['check_hostname']) == bool:
            _check_hostname = kwargs['check_hostname']
        else:
            _check_hostname = False
        _context.check_hostname = _check_hostname

        if 'client_cert' in kwargs and 'client_key' in kwargs:
            _context.load_cert_chain(kwargs['client_cert'], kwargs['client_key'])
        return _context

    #
    # inputs:
    # url: string
    # timeout:  int (optional,10)
    # outputs:
    # conn: HTTPConnection
    #
    def __get_http_connection(self, url, **kwargs):
        if 'timeout' in kwargs and type(kwargs['timeout']) == int:
            _timeout = kwargs['timeout']
        else:
            _timeout = 30
        _url_o = urlparse(url)

        # http connection
        if _url_o.scheme == 'http':
            _conn = http.client.HTTPConnection(_url_o.netloc, timeout=_timeout)
        else:
            self.logger.error("Wrong protocol, url should start with HTTP.")
        return _conn

    #
    # inputs:
    # url: string
    # timeout: int (optional, 10)
    # ssl_mutual_auth: bool (optional, False)
    # server_cert: string
    # client_cert: string (optional, None)
    # client_key: string (optional, None)
    # outputs:
    # conn: HTTPSConnection
    #
    def __get_https_connection(self, url, **kwargs):
        if 'timeout' in kwargs and type(kwargs['timeout']) == int:
            _timeout = kwargs['timeout']
        else:
            _timeout = 30

        if 'ssl_mutual_auth' in kwargs and type(kwargs['ssl_mutual_auth']) == bool:
            _ssl_mutual_auth = kwargs['ssl_mutual_auth']
        else:
            _ssl_mutual_auth = False
        _url_o = urlparse(url)

        if _url_o.scheme == 'https':
            if _ssl_mutual_auth is False:
                _ssl_context = self.__get_ssl_context(kwargs['server_cert'])
            elif _ssl_mutual_auth is True:
                _ssl_context = self.__get_ssl_context(kwargs['server_cert'], client_cert=kwargs['client_cert'],
                                                    client_key=kwargs['client_key'])
        _conn = http.client.HTTPSConnection(_url_o.netloc, timeout=_timeout, context=_ssl_context)
        return _conn

    #
    # inputs:
    # url: string
    # ssl_settings: dict (optional, None)
    # outputs:
    # conn: HTTPConnection/HTTPSConnection
    #
    def get_connection(self, url, ssl_settings=None):
        _url_o = urlparse(url)
        _conn = None
        try:
            if _url_o.scheme == 'http' and not ssl_settings:
                _conn = self.__get_http_connection(url)
            elif _url_o.scheme == 'https' and type(ssl_settings) == dict and ssl_settings:
                _ssl_mutual_auth, _server_cert, _client_cert, _client_key = self.__convert_ssl_settings(ssl_settings)
                # ssl server authentication
                if _ssl_mutual_auth is False:
                    if _server_cert:
                        _conn = self.__get_https_connection(url,
                                                           ssl_mutual_auth=_ssl_mutual_auth,
                                                           server_cert=_server_cert)
                    else:
                        raise ServerCertError
                # ssl mutual authentication
                elif _ssl_mutual_auth is True:
                    if _server_cert and _client_cert and _client_key:
                        _conn = self.__get_https_connection(url,
                                                           ssl_mutual_auth=_ssl_mutual_auth,
                                                           server_cert=_server_cert,
                                                           client_cert=_client_cert,
                                                           client_key=_client_key)
                    elif not _server_cert:
                        raise ServerCertError('ServerCertError')
                    elif not _client_cert:
                        raise ClientCertError('ClientCertError')
                    elif not _client_key:
                        raise ClientKeyError('ClientKeyError')
                else:
                    self.logger.error("ssl_mutual_auth is missing in ssl_settings, or ssl_mutual_auth value is not valid.")
            else:
                self.logger.error("you may use wrong protocol, or using https protocol but ssl_settings is missing")
        except ServerCertError:
            str(ServerCertError)
            self.logger.error("please specify server certificate location")
        except ClientCertError:
            str(ClientCertError)
            self.logger.error("please specify client certificate location")
        except ClientKeyError:
            str(ClientKeyError)
            self.logger.error("please specify client key location")
        finally:
            if not _conn:
                self.logger.error("create connection failure")
            else:
                return _conn

    #
    # inputs:
    # url: string
    # conn: HTTPConnection/HTTPSConnection
    # addon_headers: dict (optional, None)
    # outputs:
    #
    #
    def get_request(self, url, conn, addon_headers=None):
        _url_o = urlparse(url)
        _headers = self.default_headers
        _headers.update({'Host': _url_o.hostname})
        if addon_headers:
            _headers.update(addon_headers)

        if conn:
            try:
                conn.request('GET', _url_o.path.rstrip('/'), headers=_headers)
                _res = conn.getresponse()
                print(_res.status, _res.reason)
                _res_data = _res.read()
                if self.__is_json(_res_data):
                    self.__print_json(_res_data)
                else:
                    print(_res_data)
            except http.client.HTTPException:
                self.logger.error("send request failure")
            finally:
                conn.close()
        else:
            self.logger.error("connection is not valid, can not send request.")

    #
    # inputs:
    # url: string
    # conn: HTTPConnection/HTTPSConnection
    # post_body: json
    # addon_headers: dict (optional, None)
    # outputs:
    #
    #
    def post_request(self, url, conn, post_body, addon_headers=None):
        _url_o = urlparse(url)
        _headers = self.default_headers
        _headers.update({'Host': _url_o.hostname,
                         'Content-Type': 'application/json'})
        if addon_headers:
            _headers.update(addon_headers)

        if not self.__is_json(post_body):
            self.logger.error("post body should be JSON format")
            raise JSONFormatError

        if conn:
            try:
                conn.request('POST', _url_o.path.rstrip('/'), body=post_body, headers=_headers)
                _res = conn.getresponse()
                print(_res.status, _res.reason)
                _res_data = _res.read()
                if self.__is_json(_res_data):
                    self.__print_json(_res_data)
                else:
                    print(_res_data)
            except http.client.HTTPException:
                self.logger.error("send request failure")
            finally:
                conn.close()
        else:
            self.logger.error("connection is not valid, can not send request.")

    #
    # inputs:
    # url: string
    # conn: HTTPConnection/HTTPSConnection
    # put_body: json
    # addon_headers: dict (optional, None)
    # outputs:
    #
    #
    def put_request(self, url, conn, put_body, addon_headers=None):
        _url_o = urlparse(url)
        _headers = self.default_headers
        _headers.update({'Host': _url_o.hostname,
                         'Content-Type': 'application/json'})
        if addon_headers:
            _headers.update(addon_headers)

        if not self.__is_json(put_body):
            self.logger.error("post body should be JSON format")
            raise JSONFormatError("JSONFormatError")

        if conn:
            try:
                conn.request('PUT', _url_o.path.rstrip('/'), body=put_body, headers=_headers)
                _res = conn.getresponse()
                print(_res.status, _res.reason)
                _res_data = _res.read()
                if self.__is_json(_res_data):
                    self.__print_json(_res_data)
                else:
                    print(_res_data)
            except http.client.HTTPException:
                self.logger.error("send request failure")
            finally:
                conn.close()
        else:
            self.logger.error("connection is not valid, can not send request.")

    #
    # inputs:
    # url: string
    # conn: HTTPConnection/HTTPSConnection
    # addon_headers: dict (optional, None)
    # outputs:
    #
    #
    def delete_request(self, url, conn, addon_headers=None):
        _url_o = urlparse(url)
        _headers = self.default_headers
        _headers.update({'Host': _url_o.hostname})
        if addon_headers:
            _headers.update(addon_headers)

        if conn:
            try:
                conn.request('DELETE', _url_o.path.rstrip('/'), headers=_headers)
                _res = conn.getresponse()
                print(_res.status, _res.reason)
                _res_data = _res.read()
                if self.__is_json(_res_data):
                    self.__print_json(_res_data)
                else:
                    print(_res_data)
            except http.client.HTTPException:
                self.logger.error("send request failure")
            finally:
                conn.close()
        else:
            self.logger.error("connection is not valid, can not send request.")

