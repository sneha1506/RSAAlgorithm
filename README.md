# RSAAlgorithm
Pyhton code for RSA algorithm

Usage:-

The file “RSA.py” code performs signing and verification of the bible text(stored as in.txt). I have used the RabbinMiller code to check if the randomly generated numbers ‘p’,’q’ are primes or not. After selecting the primes p and q the extended euclidian algorithm will find the inverse element which are inturn used to generate the public and private keys. 

After the key generation process, the hash of the message is computed using “sha1” later it is signed (computing the value h(m)^d modn).

Verification receives the message and the signature and verifies if the signature belongs to the message or not. It computes the hash of the received message and (sig(m)^e modn) and verifies if both values are equal or not.


Modules needed:-

The code RSA encryption needs PyCrypto module to install it you can use the following commands in your terminal or command prompt

	sudo install pip (Command to install pip)
	pip install PyCrypto (Command to install Pycrypto)

This code also uses the Rabbin miller primality test code which is present in the actual code itself.

How to run the file:-

Run the file using the command “python RSA.py” and it uses the in.txt file as the input file.

