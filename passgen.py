#!/usr/bin/env python
'''
@author: dcc4e
@version: 0.1.0
Distributed under the MIT software license, see the accompanying
file LICENSE or http://www.opensource.org/licenses/mit-license.php.
'''

import csv
import random
from getpass import getpass
from hashlib import sha512
import bz2
import math
import argparse
from collections import namedtuple
import os


def main():
    args = loadArguments()
    settings = processArguments(args)
    
    words = loadWords(settings)
    entropy = getEntropy(settings)
    
    generatePassphrases(settings, words, entropy)
    

csrng = random.SystemRandom()
        

def generatePassphrases(settings, words, entropy):    
    counter = 0
    for j in xrange(settings.passphrases):
        randomIntegers = []
        while len(randomIntegers) < settings.wordCount:
            counter += 1
            randomIntegers.extend(getRandomIntegers(counter, entropy, len(words)))
        
        passphrase = [words[randomIntegers[i]][0] for i in xrange(settings.wordCount)]
                
        for word in passphrase:
            print word,    
        print

def getRandomIntegers(counter, entropy, maxInt):
    """
    returns a list of random integers between 0 (inclusive) and maxInt (exclusive) 
    """
    systemEntropy = bytearray(csrng.getrandbits(8) for i in range(64))
    counterString = str(counter)
    counterString = (128-len(counterString))*'0' + counterString
    hashInput = counterString+entropy+systemEntropy
    #print binascii.hexlify(hashInput)        
    randStr = sha512(sha512(hashInput).digest()).digest()
    
    randomIntegers = []
    bytesPerInt = int(math.ceil(math.log(maxInt, 256)))
    for i in xrange(0, 32, bytesPerInt):
        #build random int from random bytes
        randInt = ord(randStr[i])
        for j in xrange(1,bytesPerInt):
            randInt <<= 8
            randInt |= ord(randStr[i+j])
        #trim randInt down to least amount of bits necessary
        randInt %= 2**int(math.ceil(math.log(maxInt, 2)))
        #check if randInt is within the acceptable range
        if randInt < maxInt:
            randomIntegers.append(randInt)
    
    return randomIntegers

def getEntropy(settings):
    userEntropy = ''
    
    if not settings.skipUserEntropy:
        goodEntropy = False
        while not goodEntropy:
            userEntropy = getpass('Enter at least 100 random characters (mash the keyboard):')
            
            if len(userEntropy) > 0:
                compressedBytes = len(bz2.compress(userEntropy)) - len(bz2.compress('A')) #remove compression overhead
                goodEntropy = compressedBytes > 64
                if not goodEntropy:
                    print 'Insufficient amount of random characters. Please enter', int( math.ceil( 64.0/max(1, compressedBytes) ) ), 'times more random characters.'
    
    csrng = random.SystemRandom()
    systemEntropy = bytearray(csrng.getrandbits(8) for i in range(64))
    
    entropy = sha512(sha512(userEntropy + systemEntropy).digest()).digest()
    
    return entropy

def loadWords(settings):    
    with open(settings.listPath, 'rb') as csvFile:
        csvReader = csv.reader(csvFile)
        words = [row for row in csvReader]
    
    shortWords = [word for word in words if len(word[0]) <= settings.maxWordLength]
    commonWords = shortWords[:settings.listSize]
    
    if settings.verbose:
        print 'World List Size:', len(commonWords)
    
    return commonWords

def loadArguments():
    parser = argparse.ArgumentParser(description='This program generates random passphrases using the OS secure RNG and user entropy.')
    
    parser.add_argument('-l', '--list', help='the CSV list of words used', type=str, metavar='L')    
    parser.add_argument('-w', '--words', help='the amount of words in the passphrase', type=int, metavar='W', default=10)
    parser.add_argument('-wl', '--wordLength', help='the maximum amount of characters allowed per word', type=int, metavar='WL', default=5)
    parser.add_argument('-ls', '--listSize', help='the amount of words selected from in the source list, starting with the most common words', type=int, metavar='LS', default=4096)
    parser.add_argument('-p', '--passphrases', help='', type=int, metavar='P', default=16)
    parser.add_argument('-sue', '--skipUserEntropy', help='skips the additional entropy input from the user, will only use the OS secure random number generator', action="store_true")
    parser.add_argument('-V', '--version', action="version", version="passgen 0.1.0")
    parser.add_argument('-v', '--verbose', action="store_true")
    
    args = parser.parse_args()
    
    return args

def processArguments(args):
    listPath = args.list
    if listPath == None:
        listPath = os.path.join(os.path.dirname(__file__), 'included_words.csv')

    if args.verbose:  
        print 'Word Count:', args.words
        print 'Maximum Word Length:', args.wordLength
        print 'Preferred List Size:', args.listSize
        print 'Passphrase Count:', args.passphrases
        print 'Skip User Entropy:', args.skipUserEntropy
        print 'List:', listPath



    return namedtuple('settings', 'wordCount maxWordLength listSize passphrases skipUserEntropy verbose listPath')(args.words,
            args.wordLength, args.listSize, args.passphrases, args.skipUserEntropy, args.verbose, listPath)


if __name__ == '__main__':
    main()

