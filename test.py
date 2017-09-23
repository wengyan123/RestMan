from restman.RestClient import *
import unittest
import subprocess

class HTTPTestCase(unittest.TestCase):

    def test_post_http(self):
        name = 'restman'
        url = 'http://127.0.0.1:5000/todo/api/v1.0/tasks'
        data = '{"title":"Read a book"}'
        restclient = RestClient(name)
        conn = restclient.get_connection(url)
        restclient.post_request(url, conn, data)

    def test_post_http(self):
        name = 'restman'
        url = 'http://127.0.0.1:5000/todo/api/v1.0/tasks'
        data = '{"title":"Read a book"}'
        restclient = RestClient(name)
        conn = restclient.get_connection(url)
        restclient.post_request(url, conn, data)


class HTTPSTestCase(unittest.TestCase):

    def test_get_https_server_auth(self):
        name = 'restman'
        url = 'https://127.0.0.1:5000/todo/api/v1.0/tasks'
        ssl_settings = {
            'ssl_mutual_auth': False,
            'server_cert': 'certs/server.chain'
        }
        restclient = RestClient(name)
        conn = restclient.get_connection(url, ssl_settings)
        restclient.get_request(url, conn)

    def test_post_https_server_auth(self):
        name = 'restman'
        url = 'https://127.0.0.1:5000/todo/api/v1.0/tasks'
        ssl_settings = {
            'ssl_mutual_auth': False,
            'server_cert': 'certs/server.chain'
        }
        data = '{"title":"Read a book"}'
        restclient = RestClient(name)
        conn = restclient.get_connection(url, ssl_settings)
        restclient.post_request(url, conn, data)


class HTTPSMutualAuthTestCase(unittest.TestCase):

    def test_get_https_mutual_auth(self):
        name = 'restman'
        url = 'https://127.0.0.1:5000/todo/api/v1.0/tasks'
        ssl_settings = {
            'ssl_mutual_auth': True,
            'server_cert': 'certs/server.chain',
            'client_cert': 'certs/client.crt',
            'client_key': 'certs/client.key'
        }
        restclient = RestClient()
        conn = restclient.get_connection(url, ssl_settings)
        restclient.get_request(url, conn)

    def test_post_https_mutual_auth(self):
        name = 'restman'
        url = 'https://127.0.0.1:5000/todo/api/v1.0/tasks'
        ssl_settings = {
            'ssl_mutual_auth': True,
            'server_cert': 'certs/server.chain',
            'client_cert': 'certs/client.crt',
            'client_key': 'certs/client.key'
        }
        data = '{"title":"Read a book"}'
        restclient = RestClient()
        conn = restclient.get_connection(url, ssl_settings)
        restclient.post_request(url, conn, data)

    def test_put_https_mutual_auth(self):
        name = 'restman'
        url = 'https://localhost:5000/todo/api/v1.0/tasks/2'
        ssl_settings = {
            'ssl_mutual_auth': True,
            'server_cert': 'certs/server.chain',
            'client_cert': 'certs/client.crt',
            'client_key': 'certs/client.key'
        }
        data = '{"done":true}'
        restclient = RestClient()
        conn = restclient.get_connection(url, ssl_settings)
        restclient.put_request(url, conn, data)

    #def test_delete_https_mutual_auth(self):
    #    name = 'restman'
    #    url = 'https://127.0.0.1:5000/todo/api/v1.0/tasks/3'
    #    ssl_settings = {
    #        'ssl_mutual_auth': True,
    #        'server_cert': 'restman/certs/server.chain',
    #        'client_cert': 'restman/certs/client.crt',
    #        'client_key': 'restman/certs/client.key'
    #    }
    #    restclient = RestClient(name)
    #    conn = restclient.get_connection(url, ssl_settings)
    #    restclient.delete_request(url, conn)

class WesimHTTPSTestCase(unittest.TestCase):

    def test_ussdreq(self):
        name = 'restman'
        url = 'https://127.0.0.1:8201/gtoapi/ussdreq'
        ssl_settings = {
            'ssl_mutual_auth': False,
            'server_cert': 'certs/wesim.chain'
        }
        data = '{"systemid":"WESIM","vlraddr":"192.160.1.1","imsi":"000000000000012","msisdn":"21313432324242324","message":"*140207*30*2000001167800123*460#","sign":"quwJ3epwdzj7dPHuiLfDqfAxyyFedPkertw6QwFMx54jCHysAvYgkAojqsZYqy2221cjq+Rl/sQyC/w7HK7CCQ=="}'
        restclient = RestClient(name)
        conn = restclient.get_connection(url, ssl_settings)
        restclient.post_request(url, conn, data)


if __name__ == '__main__':

    testSuite = unittest.TestLoader().loadTestsFromTestCase(HTTPSMutualAuthTestCase)
    unittest.TextTestRunner(verbosity=2).run(testSuite)




