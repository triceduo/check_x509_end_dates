import unittest
from tlsx509check import check_host, check_tls_response, main
import contextlib, io


class MyTestCase(unittest.TestCase):

    def test_args_empty(self):
        f = io.StringIO()
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(f):
            main([])
            self.assertEqual(2, cm.exception.code)
            self.assertTrue("the following arguments are required: hostname" in f.getvalue())

    def test_args_help(self):
        f = io.StringIO()
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(f):
            main(['-h', 'hostname'])
        self.assertEqual(0, cm.exception.code)
        print(f.getvalue())
        # self.assertTrue("the following arguments are required: hostname" in f.getvalue())
        self.assertTrue("Checks TLS posture for given host or list of hosts" in f.getvalue())
        for attr in ['--help', '--min_tls_version', '--unacceptable', '--tls_versions', '--ciphersuitelist', '--port', '--csv']:
            self.assertTrue(attr in f.getvalue(), f'did not find {attr} in --help output')

    # @unittest.skip('')
    def test_duo_com(self):
        # these are the expected failures for duo.com as of 2024-06-24
        list = [
                'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA256',
                'TLS_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_RSA_WITH_AES_256_CBC_SHA256',
                'TLS_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA256',
                'TLS_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_RSA_WITH_AES_256_CBC_SHA256',
                ]
        main(['duo.com', '--ciphersuitelist', ",".join(list), '--unacceptable', '--tls_versions', '1.2', '-V'])
        # report = check_host('www.duo.com', min_tls_version=1.2,
        #            tls_versions=[1.0, 1.1, 1.2],
        #            target_security_type='unacceptable', ciphersuitelist=list)
        #
        # self.assertFalse('TLS1.0'in report)
        # self.assertTrue('TLS1.2'in report)
        # self.assertTrue('weak cipher suite TLS_RSA_WITH_AES_128_CBC_SHA' in report['TLS1.2'])

    def test_google(self):
        f = io.StringIO()

        list = [
                'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA256',
                'TLS_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_RSA_WITH_AES_256_CBC_SHA256',
                'TLS_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA256',
                'TLS_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_RSA_WITH_AES_256_CBC_SHA256',
                ]
        main(['www.google.com', '--ciphersuitelist', ",".join(list), '--unacceptable', '--tls_versions', '1.2', '-V'])


if __name__ == '__main__':
    unittest.main()
