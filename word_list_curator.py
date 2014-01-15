#!/usr/bin/env python
'''
Created on Nov 28, 2013

@author: dcc4e
'''

import csv
import os
from random import shuffle

def main():
    print ('This utility will import words from included_words.csv, allow the user to remove words,'
        ' and will save the results in included_words.csv and removed_words.csv. '
        'To remove words just list the numbers next the word without spaces, ex: 368.')
    
    maxWordLength = 5
    listSize = 4096
    includedWords = loadWords('included_words.csv')
    removedWords = loadWords('removed_words.csv')
    
    print 'Included Word Count:', len(includedWords)
    print 'Removed Word Count:', len(removedWords)
    
    displayWords = []
    
    #select words based on size
    for i in xrange(len(includedWords)-1,-1,-1):
        if len(includedWords[i][0]) <= maxWordLength:
            displayWords.append(includedWords.pop(i))        
        
    #select words based on popularity
    displayWords = sorted(displayWords, key = lambda word: word[1], reverse = True)
    includedWords.extend(displayWords[listSize:])
    displayWords = displayWords[:listSize]
        
    print 'Displayed Word Count:', len(displayWords)
    
    shuffle(displayWords)
    
    displayLists = [displayWords[i:i+10] for i in xrange(0, len(displayWords), 10)]
    
    for j in xrange(0, len(displayLists)):
        displayList = displayLists[j]
        
        for i in xrange(0, len(displayList)):
            print str(i)+': '+displayList[i][0]
        
        inStr = raw_input('Words to remove (q to quit):').lower()
                
        if inStr == 'q':
            #add remaining lists
            for displayList in displayLists[j:]:
                includedWords.extend(displayList)
            break        
    
        selectedIndices = []
        if inStr.isdigit():
            selectedIndices = [int(inStr[i]) for i in xrange( 0, min(10, len(inStr)) )]
        
        for i in sorted(selectedIndices, reverse=True):
            removedWords.append( displayList.pop(i) )
                        
        includedWords.extend( displayList )
    
    print 'Included Word Count:', len(includedWords)
    saveWords(includedWords, 'included_words.csv')
    
    print 'Removed Word Count:', len(removedWords)
    saveWords(removedWords, 'removed_words.csv')
        

def loadWords(filename):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    
    if not os.path.isfile(filepath):
        return []
    
    words = []
    with open(filepath, 'rb') as csvFile:
        csvReader = csv.reader(csvFile)
        for row in csvReader:
            if len(row) == 2:
                words.append( [row[0], int(row[1])] )
    
    return words


def saveWords(words, filename):
    words = sorted(words, key = lambda word: word[1], reverse = True)
    
    filepath = os.path.join(os.path.dirname(__file__), filename)
    
    with open(filepath, 'wb') as csvFile:
        csvWriter = csv.writer(csvFile, quoting = csv.QUOTE_NONNUMERIC)
        for word in words:
            csvWriter.writerow(word)
    
    

if __name__ == '__main__':
    main()