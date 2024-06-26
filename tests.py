import unittest
from tlsx509check import check_host, check_tls_response


class MyTestCase(unittest.TestCase):

    def test_main(self):
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
        report = check_host('www.duo.com', min_tls_version=1.2,
                   tls_versions=[1.0, 1.1, 1.2],
                   target_security_type='unacceptable', ciphersuitelist=list)

        self.assertFalse('TLS1.0'in report)
        self.assertTrue('TLS1.2'in report)
        self.assertTrue('weak cipher suite TLS_RSA_WITH_AES_128_CBC_SHA' in report['TLS1.2'])


if __name__ == '__main__':
    unittest.main()
