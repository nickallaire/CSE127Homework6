from hashlib import md5
from collections import defaultdict
import itertools


#########################
#       Rule 1          #
#########################

# English word
def rule1(wordDict, hash, crackedPasswords, pid):
    print
    print 'Checking password rule 1...'

    rule1 = open('rule1passwords_saltedM.txt', 'w')

    for d in wordDict:
        # Unsalted
        # hashedWord = md5(pid + d).hexdigest()

        for h in hash:
            # Salted
            hashedWord = md5(pid + d + h[2]).hexdigest()

            hashedPassword = h[1]
            if hashedPassword == hashedWord:
                pair = [h[0], d]
                rule1.write(h[0] + str(':') + d + '\n')
                crackedPasswords.append(pair)

    rule1.close()

    return crackedPasswords


#########################
#       Rule 2          #
#########################

# A string up to 8 digits as password attack, can have 0's in front (e.g. 00001)
def rule2(wordDict, hash, crackedPasswords, pid):
    print
    print 'Checking password rule 2...'

    passwordLength = 8
    i = 1
    count = 0
    rule2 = open('rule2passwords_saltedM.txt', 'w')

    zeroLength = 0
    for numLength in range(0, passwordLength):
        print numLength
        for num in range(0, (10**(passwordLength - numLength))):
            numString = str(zeroLength*'0') + str(num)

            # Unsalted
            # hashedWord = md5(pid + numString).hexdigest()

            for h in hash:
                # Salted
                hashedWord = md5(pid + numString + h[2]).hexdigest()

                hashedPassword = h[1]

                if hashedPassword == hashedWord:
                    pair = [h[0], numString]
                    rule2.write(h[0] + str(':') + numString + '\n')
                    crackedPasswords.append(pair)
                    count += 1
                    print 'FOUND', count

        zeroLength += 1

        i += 1

    rule2.close()

    return crackedPasswords


#########################
#       Rule 3          #
#########################

# English word followed by some digits, English word is at least 5 characters, no more than 10 characters in length in total
def rule3(wordDict, hash, crackedPasswords, pid):
    print
    print 'Checking password rule 3...'

    count = 0
    ruleThreeWords = [d for d in wordDict if len(d) >= 5]
    rule3 = open('rule3passwords_saltedM.txt', 'w')

    i = 1
    for d in ruleThreeWords:
        print i
        wordLength = len(d)
        passwordLength = 10 - wordLength
        zeroLength = 0
        for numLength in range(0, passwordLength):
            for num in range(0, 10**(passwordLength - numLength)):
                numString = str(zeroLength*'0') + str(num)

                # Unsalted
                # hashedWord = md5(pid + d + numString).hexdigest()

                for h in hash:
                    hashedPassword = h[1]

                    # Salted
                    hashedWord = md5(pid + d + numString + h[2]).hexdigest()

                    if hashedPassword == hashedWord:
                        pair = [h[0], d + numString]
                        rule3.write(h[0] + str(':') + d + numString + '\n')
                        crackedPasswords.append(pair)
                        count += 1
                        print 'FOUND', count

            zeroLength += 1

        i += 1

    rule3.close()

    return crackedPasswords


#########################
#       Rule 4          #
#########################

# English word but change some letters to upper case and some letters to symbols
def rule4(wordDict, hash, crackedPasswords, pid, letterSubs):
    print
    print 'Checking password rule 4...'

    rule4 = open('rule4passwords_unsalted2M.txt', 'w')
    count = 0
    i = 1
    # ruleThreeWords = [d for d in wordDict if len(d) == 11]

    for word in wordDict:
        print i, word
        comb = map(''.join, itertools.product(*zip(word.upper(), word.lower())))
        for c in comb:

            if c != word:

                # Unsalted
                hashedWord = md5(pid + c).hexdigest()

                for h in hash:
                    hashedPassword = h[1]

                    # Salted
                    # hashedWord = md5(pid + c + h[2]).hexdigest()

                    if hashedPassword == hashedWord:
                        pair = [h[0], c]
                        rule4.write(h[0] + str(':') + c + '\n')
                        crackedPasswords.append(pair)
                        count += 1
                        print 'FOUND', count

            specialWord = ''
            for letter in c:
                if letter in letterSubs:
                    specialWord += letterSubs[letter]
                else:
                    specialWord += letter

            specialComb = map(''.join, itertools.product(*zip(c, specialWord)))
            dup = []
            for sp in specialComb:
                if sp not in comb and sp not in dup:
                    dup.append(sp)

                    # Unsalted
                    hashedWord = md5(pid + sp).hexdigest()

                    for h in hash:
                        hashedPassword = h[1]

                        # Salted
                        # hashedWord = md5(pid + sp + h[2]).hexdigest()

                        if hashedPassword == hashedWord:
                            pair = [h[0], c]
                            rule4.write(h[0] + str(':') + sp + '\n')
                            crackedPasswords.append(pair)
                            count += 1
                            print 'FOUND', count
                        # print specialWord

        i += 1

    rule4.close()

    return crackedPasswords


#########################
#       Rule 5          #
#########################

# Concatenate two English words together
def rule5(wordDict, hash, crackedPasswords, pid):
    print
    print 'Checking password rule 5...'

    i = 1
    rule5 = open('rule5passwords_saltedM.txt', 'w')

    for d in wordDict:
        for d1 in wordDict:
            word = d + d1

            # Unsalted
            # hashedWord = md5(pid + word).hexdigest()

            for h in hash:
                hashedPassword = h[1]

                # Salted
                hashedWord = md5(pid + word + h[2]).hexdigest()

                if hashedPassword == hashedWord:
                    pair = [h[0], word]
                    rule5.write(h[0] + str(':') + word + '\n')

                    crackedPasswords.append(pair)
                    print len(crackedPasswords)

        i += 1

    rule5.close()

    return crackedPasswords


def main():
    # Dictionary words
    file = open('words.txt', 'r')
    wordDict = [d.strip() for d in file]

    # Read hash1.txt
    file = open('missedHash1.txt', 'r')
    hash1 = [d.strip().split(':') for d in file]

    # Read hash2.txt
    file = open('missedHash2.txt', 'r')
    hash2 = [d.strip().split(':') for d in file]

    # Dictionary that contains letter substitutions
    letterSubs = defaultdict(list)
    letterSubs['a'] = '@'
    letterSubs['b'] = '8'
    letterSubs['c'] = '('
    letterSubs['f'] = '#'
    letterSubs['g'] = '9'
    letterSubs['i'] = '1'
    letterSubs['l'] = '1'
    letterSubs['o'] = '0'
    letterSubs['s'] = '$'

    crackedPasswords = []

    # Change PID
    pid = 'A10639753'

    # !!!!!!!!!DON'T FORGET TO CHANGE FILE NAME WHEN SWITCHING FROM hash1 TO hash2!!!!!!!!!!!!
    # hash1 = unsalted, hash2 = salted

    rule1(wordDict, hash2, crackedPasswords, pid)
    rule2(wordDict, hash2, crackedPasswords, pid)
    rule3(wordDict, hash2, crackedPasswords, pid)
    rule4(wordDict, hash1, crackedPasswords, pid, letterSubs)
    rule5(wordDict, hash2, crackedPasswords, pid)


if __name__ == "__main__": main()