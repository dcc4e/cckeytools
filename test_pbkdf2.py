#!/usr/bin/python
# -*- coding: ascii -*-

import unittest
from pbkdf2 import crypt, b, PBKDF2
import pbkdf2

import sys 

class TestPBKDF2(unittest.TestCase):
    def _test_pbkdf2(self, password, salt, iterations, read, expected):
        kdf = PBKDF2(password, salt, iterations)
        
        if read[1] == 'byte':
            result = kdf.read(read[0])
        elif read[1] == 'hex':
            result = kdf.hexread(read[0])
        print "password:", password, " salt:", salt, " iterations:", iterations, " bytes:", read[1], " result:", result, " expected:", expected
        self.assertEqual(expected, result)
    
    def test_pbkdf2(self):
        """Module self-test"""
        from binascii import a2b_hex as _a2b_hex
        def a2b_hex(s):
            return _a2b_hex(b(s))

        #
        # Test vectors from RFC 3962
        #

        # Test 1
        self._test_pbkdf2("password", "ATHENA.MIT.EDUraeburn", 1, (16, 'byte'), a2b_hex("cdedb5281bb2f801565a1122b2563515"))

        # Test 2 
        self._test_pbkdf2("password", "ATHENA.MIT.EDUraeburn", 1200, (32, 'hex'),
                          ("5c08eb61fdf71e4e4ec3cf6ba1f5512b" "a7e52ddbc5e5142f708a31e2e62b1e13"))

        # Test 3
        self._test_pbkdf2("X"*64, "pass phrase equals block size", 1200, (32, 'hex'),
                          ("139c30c0966bc32ba55fdbf212530ac9" "c5ec59f1a452f5cc9ad940fea0598ed1"))

        # Test 4
        self._test_pbkdf2("X"*65, "pass phrase exceeds block size", 1200, (32, 'hex'),
                          ("9ccad6d468770cd51b10e6a68721be61" "1a8b4d282601db3b36be9246915ec82a"))

        #
        # Other test vectors
        #

        # Chunked read
        f = PBKDF2("kickstart", "workbench", 256)
        result = f.read(17)
        result += f.read(17)
        result += f.read(1)
        result += f.read(2)
        result += f.read(3)
        expected = PBKDF2("kickstart", "workbench", 256).read(40)
        self.assertEqual(expected, result)

        #
        # crypt() test vectors
        #

        # crypt 1
        result = crypt("cloadm", "exec")
        expected = '$p5k2$$exec$r1EWMCMk7Rlv3L/RNcFXviDefYa0hlql'
        self.assertEqual(expected, result)

        # crypt 2
        result = crypt("gnu", '$p5k2$c$u9HvcT4d$.....')
        expected = '$p5k2$c$u9HvcT4d$Sd1gwSVCLZYAuqZ25piRnbBEoAesaa/g'
        self.assertEqual(expected, result)

        # crypt 3
        result = crypt("dcl", "tUsch7fU", iterations=13)
        expected = "$p5k2$d$tUsch7fU$nqDkaxMDOFBeJsTSfABsyn.PYUXilHwL"
        self.assertEqual(expected, result)

        # crypt 4 (unicode)
        result = crypt(b('\xce\x99\xcf\x89\xce\xb1\xce\xbd\xce\xbd\xce\xb7\xcf\x82').decode('utf-8'),
            '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ')
        expected = '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ'
        self.assertEqual(expected, result)

        # crypt 5 (UTF-8 bytes)
        result = crypt(b('\xce\x99\xcf\x89\xce\xb1\xce\xbd\xce\xbd\xce\xb7\xcf\x82'),
            '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ')
        expected = '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ'
        self.assertEqual(expected, result)

    def test_crypt(self):
        result = crypt("secret")
        self.assertEqual(result[:6], "$p5k2$")

        result = crypt("secret", "XXXXXXXX")
        expected = '$p5k2$$XXXXXXXX$L9mVVdq7upotdvtGvXTDTez3FIu3z0uG'
        self.assertEqual(expected, result)

        # 400 iterations (the default for crypt)
        result = crypt("secret", "XXXXXXXX", 400)
        expected = '$p5k2$$XXXXXXXX$L9mVVdq7upotdvtGvXTDTez3FIu3z0uG'
        self.assertEqual(expected, result)

        # 400 iterations (keyword argument)
        result = crypt("spam", "FRsH3HJB", iterations=400)
        expected = '$p5k2$$FRsH3HJB$SgRWDNmB2LukCy0OTal6LYLHZVgtOi7s'
        self.assertEqual(expected, result)

        # 1000 iterations
        result = crypt("spam", "H0NX9mT/", iterations=1000)
        expected = '$p5k2$3e8$H0NX9mT/$wk/sE8vv6OMKuMaqazCJYDSUhWY9YB2J'
        self.assertEqual(expected, result)

        # 1000 iterations (iterations count taken from salt parameter)
        expected = '$p5k2$3e8$H0NX9mT/$wk/sE8vv6OMKuMaqazCJYDSUhWY9YB2J'
        result = crypt("spam", expected)
        self.assertEqual(expected, result)

if __name__ == '__main__':
    unittest.main()

# vim:set ts=4 sw=4 sts=4 expandtab:
