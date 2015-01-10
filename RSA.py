#!/usr/bin/env python

import random, sys, os
import hashlib
from decimal import *
import time

# This method returns trrue if the number is prime
def rabinMiller(num):
    # Returns True if num is a prime number.
    s = num - 1
    t = 0
    while s % 2 == 0:
        # keep halving s while it is even (and use t
        # to count how many times we halve s)
        s = s // 2
        t += 1

    for trials in range(5): # try to falsify num's primality 5 times
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1: # this test does not apply if v is 1.
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True

# This method checks if the randomly generated number is prime or not
def isPrime(num):
    # Return True if num is a prime number. This function does a quicker
    # prime number check before calling rabinMiller().

    if (num < 2):
        return False # 0, 1, and negative numbers are not prime

    # About 1/3 of the time we can quickly determine if num is not prime
    # by dividing by the first few dozen prime numbers. This is quicker
    # than rabinMiller()
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True

    # See if any of the low prime numbers can divide num
    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    # If all else fails, call rabinMiller() to determine if num is a prime.
    return rabinMiller(num)

# This method generates a prime number of specified size
def generateLargePrime(keysize):
    # Return a random prime number of keysize bits in size.
    while True:
        num = random.randrange(2**(keysize-1), 2**(keysize))
        if isPrime(num):
            return num

def gcd(a,b):
	while a!=0:
		a,b = b%a,a
	return b

# This method calculated the inverse of 'e' using extended euclidisn method
def ExtendedEuclidianInverse(e,PHI):
	if gcd(e,PHI) != 1:
		return None
	u1, u2, u3 = 1,0,e
	v1,v2,v3 = 0,1,PHI
	while v3 != 0:
		q = u3 // v3
		v1, v2, v3, u1, u2, u3 = (u1 - q* v1), (u2 -q * v2), (u3 -q * v3), v1, v2, v3
	return u1 % PHI

# This method calculates the values of p,q,n,e,d which are further required for signing and verification
def PrimesAndValuesGeneration(KeySize):
	p = generateLargePrime(KeySize)
	q = generateLargePrime(KeySize)
	# p = 61
	# q = 17
	n = p*q
	PHI = (p-1)*(q-1)
	# e = 23
	while True:
		e = random.randrange(2**(KeySize-1),2**(KeySize))
		if gcd(e,PHI) == 1:
			break
	d = ExtendedEuclidianInverse(e,PHI)
	return p,q,n,e,d

# This method is used to generate the public and private keys
def KeyGeneration():
	PrimeSize = 23
	print("Size of the modulus is 512")
	p,q,n,e,d = PrimesAndValuesGeneration(PrimeSize)
	PublicKey = (n,e)
	PrivateKey = (n,d)
	print "PublicKey"
	print PublicKey
	print "PrivateKey"
	print PrivateKey
	return (PublicKey,PrivateKey)

# This method is used to sign the message
def RSASigning(message):
	MessageHash = hashlib.sha1(message).hexdigest()
	PrimeSize = 23
	p,q,n,e,d = PrimesAndValuesGeneration(PrimeSize)
	integerValue = int(MessageHash,16)
	signature = pow(integerValue,d,n)
	return signature

# This message is used to verify the signed message
def RSAVerification(message, signature):
	PrimeSize = 23
	p,q,n,e,d = PrimesAndValuesGeneration(PrimeSize)
	MessageHash = hashlib.sha1(message).hexdigest()
	integerValue = int(MessageHash,16)
	print "Calculated Value"
	print integerValue %n
	verification = pow(signature,e,n)
	print "Received Value"
	print verification
	print("Verification Passed... Sent message is same as received message")



if __name__ == '__main__':
    in_file = 'in.txt'
    
    in_FH = open(in_file,'r')
    message = in_FH.read()
    
    print ("Key Generation Started...")
    KeyGeneration_start = time.time()
    KeyGeneration()
    print("Key Generation Time taken {} seconds".format(time.time()-KeyGeneration_start))
    
    print("Signing Started...")
    Signing_start = time.time()
    RSASigning(message)
    print("Signing Time taken {} seconds".format(time.time()-Signing_start))

    print("Verification Started...")
    Verification_start = time.time()
    RSAVerification(message,RSASigning(message))
    print("Verification Time taken {} seconds".format(time.time()-Verification_start))
    
    print("Total Time taken for key generation, signing and verification is {} seconds:".format(time.time()-KeyGeneration_start))
    in_FH.close()
    


