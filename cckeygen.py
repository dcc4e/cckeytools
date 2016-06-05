#!/usr/bin/env python
'''
@author: dcc4e
@version: 0.1.0
Distributed under the MIT software license, see the accompanying
file LICENSE or http://www.opensource.org/licenses/mit-license.php.
'''

import argparse
from getpass import getpass
from binascii import hexlify
from time import time
import sys

from pbkdf2 import PBKDF2
import hashlib
from hashlib import sha512, sha256, sha1
from ecdsa.ecdsa import Public_key, int_to_string
from ecdsa.ecdsa import generator_secp256k1
import hmac as HMAC
from Crypto.PublicKey import RSA

def main():
    args = loadArguments()
    settings = processArguments(args)
    
    salt, passphrase = getSaltAndPassphrase(settings) 
    
    quickTest(settings.verbose)
    try:
        genOutput1 = generateAndCheckOutput(settings, salt, passphrase)
        printOutput(settings, genOutput1)
    except DoubleCheckError:
        sys.stderr.write('Keys generated from first and second run did not match.\n')   
    

def quickTest(verbose):        
    class Settings(): pass
    testSettings = Settings()
    testSettings.verbose = False
    testSettings.doubleCheck = False
    testSettings.outType = 'address'
    testSettings.isTestnet = False
    
    #SHA-1
    testSettings.hashFunction = keyDerivationFunctions['pbkdf2-hmac-sha-1'][1]
    testSettings.iterations = 1
    test(testSettings, '', '', ('1e437a1c79d75be61e91141dae20affc4892cc99abcc3fe753887bccc8920176', '1KX19bUFcHEBxAR4BTZX4JXzuUUcLEXPKS'))
    test(testSettings, 'salt', 'passphrase', ('7f7042f41820d039e1163bdaa58c671df1e4eb559e4b2d114daf254858399cf3', '1Q4k1fSTRtUmRV5kjrYBCDRcsxGwimmuht'))    
    testSettings.iterations = 2
    test(testSettings, 'salt', 'passphrase', ('350f26912d1d82a7a20e64440e11e2cc5200478a63cf4f68084ec68e0c5643f3', '1F2PC7yAjViihs8bcSujzmbonKMAf6uz89'))
    testSettings.outType = 'armory'
    test(testSettings, 'S'*65, 'P'*65, ('jksk niaa eido uken stid dkig ffkr ohed wnai sjtf dofs auwh jfgu hsee konn dsns fojk ftfa', 
                                         'nsjg fugn drja twoi ujif ifge jwwo idgr hnaw eioa fnwh nasj owun wneo rjtg hnee irfi ukse'))
    testSettings.outType = 'address'
    #SHA-256
    testSettings.hashFunction = keyDerivationFunctions['pbkdf2-hmac-sha-256'][1]
    testSettings.iterations = 1
    test(testSettings, '', '', ('f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad', '18WB96h5RgZMJ3beZw1PEZgosHiPetEgs5'))
    test(testSettings, 'salt', 'passphrase', ('2ef9aabdeca6241881d1898162a15a37a4d68715ba97c42eb21fd739b5df713e', '19sFChjbqCdhakDyeKeoRpBzEVC3FZzXK1'))
    testSettings.iterations = 4
    test(testSettings, 'salt', 'passphrase', ('ecf81a628b7715e86c4f59146f84d985d8d8c270b7af0d2b98a3514364ba73bd', '1CDitDLQq1HXB1zYnc5hHrZG4LoF2Uxvom'))
    test(testSettings, 'S'*65, 'P'*65, ('d649e3315ebbe0595d518995c03738aa7cf3554443eb6c4943a8d994dc1001c7', '1Kgym8nVzQcznWRTWFxokkCpd9zhy8fW3g'))
    testSettings.outType = 'armory'
    test(testSettings, 'S'*65, 'P'*65, ('ijge offs hott oahe hihs weeh uafk fwrr hfiw kunf hhgg gfot juge gfrw ieeg iusa asuk nhfk', 
                                        'wiie efwo aatg hrtw ewne hgkf gsif fhrr jhtt nana uhoa erus ohet enen kiis ootw fars gdnj'))    
    testSettings.outType = 'address'
    #SHA-512
    testSettings.hashFunction = keyDerivationFunctions['pbkdf2-hmac-sha-512'][1]
    testSettings.iterations = 1
    test(testSettings, '', '', ('6d2ecbbbfb2e6dcd7056faf9af6aa06eae594391db983279a6bf27e0eb228614', '12xGf1BCp5NjTDWSwuk6qnpxEHyrJePCMS'))
    test(testSettings, '', 'passphrase', ('66b9a29aae7cfeaf5950deed2d636a4eb1979fdd87d89b2664a1f625fb4bbd41', '1CVaB2TJHCnmejyXYfphZKLvdLzhJjt359'))
    test(testSettings, 'salt', 'passphrase', ('58700dce6cf6c584936cf5d2ca746d8f4b8a8ccf620f06e2bcc475d4a091e8d4', '19LbZUBEeJqezLtZJB8NzBgCL5bv2HppSx'))
    testSettings.iterations = 4
    test(testSettings, 'salt', 'passphrase', ('944c4e136bad356ae01512c03a1195b14265fc2eba3dabd5c7edf1c4ce14dd94', '16xxU2o8no2peiMN7XCnGF2t8AWrx7KJ6x'))
    test(testSettings, 'S'*129, 'P'*129, ('af18c7bbdd6caab13f153e512171d62e79dae0027a5d2c470db951b53294ff14', '1BZedTwhpTE6WK9MLWhRPNNYpLwRezBnPj'))
    testSettings.outType = 'electrum'
    test(testSettings, 'salt', 'passphrase', '944c4e136bad356ae01512c03a1195b1')
    testSettings.outType = 'armory'
    test(testSettings, 'S'*129, 'P'*129, ('rnsw uktt iiju rrts fnsh fohs dsks ijdo eohw keir oaad krhi dugk aite hsth fdeg nnsg jnui', 
                                          'heut fgdi osui gfhi gkeh aaun gesk raff jdee sndg hajt dsfo uwuj hsht ojjr ffsu eehe gduj'))
        
    if verbose:
        print 'Passed quick self test.'

def test(settings, salt, passphrase, expected):
    genOut = generateOutput(settings, passphrase, salt, 0, 1, False)
    if settings.outType == 'electrum':
        if expected != genOut[1]:
             raise Exception('Failed self test.')
    elif not (expected[0] == genOut[1] and expected[1] == genOut[3]):
        raise Exception('Failed self test.')   
    

class DoubleCheckError(Exception):
    pass

def getSaltAndPassphrase(settings):
    if settings.showPassphrase:
        inputFunc = raw_input
    else:
        inputFunc = getpass
    
    while True:
        salt = raw_input('Salt:')
        passphrase = inputFunc('Passphrase:')
        if settings.confirmPassphrase:
            if salt != raw_input('Confirm Salt:'):
                print "Salts don't match. Try again."
                continue
            if passphrase != inputFunc('Confirm Passphrase:'):
                print "Passphrases don't match. Try again."
                continue
        break
    
    return salt, passphrase

def printOutput(settings, genOutput):
    if settings.outType == 'armory':
        rootKey, chainCode = genOutput[1], genOutput[3]
        #print hexlify(genOutput[0])
        #print hexlify(genOutput[2])
                
        if settings.hideLabels:
            print >>settings.out, rootKey[0:44]
            print >>settings.out, rootKey[45:89]
            print >>settings.out, chainCode[0:44]
            print >>settings.out, chainCode[45:89]
        else:
            print >>settings.out, 'Root Key:', rootKey[0:44]
            print >>settings.out, '         ', rootKey[45:89]
            print >>settings.out, 'Chain Code:', chainCode[0:44]
            print >>settings.out, '           ', chainCode[45:89]
            
    elif settings.outType == 'electrum':
        if settings.hideLabels:
            print >>settings.out, genOutput[1]
        else:
            print >>settings.out, 'Electrum Seed:',genOutput[1]
    
    elif settings.outType == 'gpg':
        if not settings.hideLabels:
	    print >>settings.out, '4096 bit RSA key in PEM format import using: '
	    print >>settings.out, ('  [pem format key] | pem2openpgp "User <email@addr>"'
		' | gpg --allow-secret-key-import --import')
	print >>settings.out, genOutput
    
    elif settings.outType == 'bytes':
        print >>settings.out, genOutput[0]
    
    elif settings.outType == 'hex':
        print >>settings.out, genOutput[1]
                
    else:
        if settings.hideLabels:
            if settings.showPrivateKey:
                print >>settings.out, genOutput[1]
            if settings.showPublicKey:
                print >>settings.out, hexlify(genOutput[2])
            print >>settings.out, genOutput[3]
        else:
            if settings.showPrivateKey:
                print >>settings.out, 'Private Key:', genOutput[1]
            if settings.showPublicKey:
                print >>settings.out, 'Public Key:', hexlify(genOutput[2])
            print >>settings.out, 'Bitcoin Address:', genOutput[3]

def generateAndCheckOutput(settings, salt, passphrase):
    if settings.doubleCheck:
        genOutput1 = generateOutput(settings, passphrase, salt, 0, 2, True)
        
        if settings.verbose:
            print "Double checking keys."
        genOutput2 = generateOutput(settings, passphrase, salt, 1, 2, True)
        if genOutput1 == genOutput2:
            if settings.verbose:
                print "Keys passed double check."
        else:
            raise DoubleCheckError()
    else:
        genOutput1 = generateOutput(settings, passphrase, salt, 0, 1, True)    
    
    return genOutput1

def generateOutput(settings, passphrase, salt, step, totalSteps, outputProgress):
    
    def progressChanged(i, iterations):     
        if time() > progressChanged.lastTime + 0.5:
            progressChanged.lastTime = time()
            sys.stdout.write('{:f}% \r'.format((step*100.0/totalSteps) + (i*100.0)/(iterations*totalSteps) ))
            sys.stdout.flush()
    progressChanged.lastTime = time()
    
    if outputProgress:
        kdf = PBKDF2(passphrase, salt, settings.iterations, settings.hashFunction, HMAC, progressChanged)
    else:
        kdf = PBKDF2(passphrase, salt, settings.iterations, settings.hashFunction, HMAC, None)
    
    if settings.outType == 'armory':
        rootKeyBytes = kdf.read(32)
        chainCodeBytes = kdf.read(32)
        
        easy16 = 'asdfghjkwertuion'
        def toEasy16(data):
            return ''.join([easy16[h] for b in data for h in [ord(b)>>4, ord(b)&0xF]] )
        def toPaperLine(data):
            return toEasy16( data + sha256(sha256(data).digest()).digest()[:2] )
        
        rootKey = toPaperLine(rootKeyBytes[0:16]) + toPaperLine(rootKeyBytes[16:32])
        chainCode = toPaperLine(chainCodeBytes[0:16]) + toPaperLine(chainCodeBytes[16:32])
        
        rootKey = ' '.join([rootKey[i:i+4]  for i in range(0,72,4)])
        chainCode = ' '.join([chainCode[i:i+4]  for i in range(0,72,4)])
        
        return (rootKeyBytes, rootKey, chainCodeBytes, chainCode)
    
    elif settings.outType == 'electrum':
        seed = kdf.read(16)
        seedHex = hexlify(seed)
            
        return (seed, seedHex)

    elif settings.outType == 'gpg':
        # PBKDF2 returns a file-like object that gives us deterministic random bytes
	key = RSA.generate(4096, kdf.read)

	return key.exportKey(pkcs=1)
    
    elif settings.outType == 'bytes' or settings.outType == 'hex':
        kdfBytes = kdf.read(settings.bytes)
        kdfHex = hexlify(kdfBytes)
            
        return (kdfBytes, kdfHex)
        
    else:
        privateKey = kdf.read(32)
        privateKeyHex = hexlify(privateKey)
        secret = long(privateKeyHex, 16)
        publicKey = generatePublicKey(secret)
        bitcoinAddress = generateBitcoinAddress(publicKey, settings.isTestnet)
        
        return (privateKey, privateKeyHex, publicKey, bitcoinAddress)


class SHA512:
    def new(self, data=""):
        return sha512(data)

class SHA256:
    def new(self, data=""):
        return sha256(data)

class SHA1:
    def new(self, data=""):
        return sha1(data)

# key derivation functions with command line names for keys and 
keyDerivationFunctions = {'pbkdf2-hmac-sha-1':('PBKDF2-HMAC-SHA-1', SHA1()), 'pbkdf2-hmac-sha-256':('PBKDF2-HMAC-SHA-256', SHA256()), 'pbkdf2-hmac-sha-512':('PBKDF2-HMAC-SHA-512', SHA512())}


def loadArguments():
    parser = argparse.ArgumentParser(description='Derives keys, addresses, wallet seeds, and arbitrary bytes from a passphrase using PBKDF2. '
                                     'Running this program with no arguments uses the default high-strength settings.')
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--iterations', help='iterations', type=int, metavar='I', default=1048576)
    group.add_argument('-f', '--fast', help='uses the faster, lower strength settings', action="store_true")
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--armory', help='outputs armory root key and chain code', action="store_true")
    group.add_argument('--electrum', help='outputs electrum seed', action="store_true")
    group.add_argument('--gpg', help='outputs gpg key (4096 bit RSA)', action="store_true")
    group.add_argument('-b', '--bytes', help='outputs bytes generated by the kdf', type=int, metavar='B')
    group.add_argument('--hex', help='outputs bytes generated by the kdf as hex characters', type=int, metavar='H')
    group.add_argument('-tn', '--testnet', help='output testnet address', action="store_true")
    
    parser.add_argument('-o', '--out', help='outputs to specified file', type=argparse.FileType('wt'))
    
    parser.add_argument('-kdf', '--key-derivation-function', help='key derivation function used to transform passphrase to keys',
                        choices=keyDerivationFunctions.keys(), default='pbkdf2-hmac-sha-512')
    parser.add_argument('-v', '--verbose', help='output settings and progress details', action="store_true")
    parser.add_argument('-V', '--version', action="version", version="cckeygen 0.1.0")
    
    parser.add_argument('-sp', '--show-passphrase', help='displays passphrase characters', action="store_true")
    
    parser.add_argument('-hl', '--hide-labels', help='hides the labels on the output', action="store_true")
    parser.add_argument('-prv', '--show-private-key', help='displays private key', action="store_true")
    parser.add_argument('-pub', '--show-public-key', help='displays public key', action="store_true")
    
    parser.add_argument('-sdc', '--skip-double-check',
                        help='skips the second run of the key derivation function that check for errors',
                        action="store_true")
    parser.add_argument('-sc', '--skip-confirmation',
                        help='skips the salt and password confirmation',
                        action="store_true") 
    args = parser.parse_args()
    
    #print args
    
    return args


def processArguments(args):
    if args.fast:
        iterations = 4096
    else:
        iterations = args.iterations
        
    keyDerivationFunction = args.key_derivation_function
    
    
    class Settings(): pass
    settings = Settings()
    settings.iterations = iterations
    settings.hashFunction = keyDerivationFunctions[keyDerivationFunction][1] 
    settings.showPassphrase = args.show_passphrase
    settings.showPrivateKey = args.show_private_key
    settings.showPublicKey = args.show_public_key
    settings.doubleCheck = not args.skip_double_check
    settings.confirmPassphrase = not args.skip_confirmation
    settings.verbose = args.verbose
    settings.armory = args.armory
    settings.out = args.out
    settings.hideLabels = args.hide_labels
    settings.isTestnet = args.testnet
    settings.bytes = args.bytes if args.bytes else args.hex
    settings.outType = 'armory' if args.armory else 'electrum' if args.electrum else 'bytes' if args.bytes else 'hex' if args.hex else 'gpg' if args.gpg else 'address'
    
    if args.verbose:
        if iterations == 4096:
            print 'Iterations: 4096 = 2^12'
        elif iterations == 1048576:
            print 'Iterations: 1048576 = 2^20'
        else:
            print 'Iterations:', iterations
        print 'Key Derivation Function:', keyDerivationFunctions[keyDerivationFunction][0]
        print 'Show Private Key:', settings.showPrivateKey
        print 'Show Public Key:', settings.showPublicKey
        print 'Double Check:', settings.doubleCheck
        print 'Network:', 'Test' if args.testnet else 'Main'
    
    return settings


def generatePublicKey(secret):
    publicKeyPoint = Public_key(generator_secp256k1, generator_secp256k1 * secret).point
    return '\x04' + int_to_string(publicKeyPoint.x()) + int_to_string(publicKeyPoint.y())

def generateBitcoinAddress(publicKey, isTestnet):
    # hash public key with sha-256 then ripemd-160 and prefix with 0x00
    pubKeyHash1 = sha256(publicKey).digest()
    ripehash = hashlib.new('ripemd160')
    ripehash.update(pubKeyHash1)
    if isTestnet:
        netHash = '\x6F' + ripehash.digest()  # 0x6F for Testnet
    else:
        netHash = '\x00' + ripehash.digest()  # 0x00 for Main Network
        
    # generate checksum by applying sha-256 twice and taking the first 4 bytes
    chksumHash1 = sha256(netHash).digest()
    chksumHash2 = sha256(chksumHash1).digest()
    chksum = chksumHash2[:4]
    
    addr = netHash + chksum
    addr58 = b58encode(addr)
    
    return addr58

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)
def b58encode(v):
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * ord(c)
    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break
    return (__b58chars[0] * nPad) + result


if __name__ == '__main__':
    main()

