# Assignment 6 - Public Key Cryptography

This C program contains code for a key generator which produces RSA public and private key pairs,
an encryptor which encrypts files using a public key, and a decryptor which decrypts encrypted
files using the corresponding private key.

## Formatting

Format the code with:

```
make format
```

## Building

Build the program with:

```
make all
```

## Running

To generate an RSA public/private key pair, run the program with:

```
$ ./keygen [-hv] [-b bits] -n pbfile -d pvfile
```

along with any of the following command-line options

```
OPTIONS
  -b : specifies the minimum bits needed for the public modulus n
  -i : specifies the number of Miller-Rabin iterations for testing primes (default: 50)
  -n pbfile : specifies the public key file (default: rsa.pub)
  -d pvfile : specifies the private key file (default: rsa.priv)
  -s : specifies the random seed for the random state initialization (default: the seconds since 
the UNIX epoch, given by time(NULL))
  -v : enables verbose output
  -h : displays program synopsis and usage
```

To encrypt data using RSA encryption, run the program with:

```
$ ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey
```

along with any of the following command-line options

```
OPTIONS
  -i : specifies the input file to encrypt (default: stdin)
  -o : specifies the output file to encrypt (default: stdout)
  -n : specifies the file containing the public key (default: rsa.pub)
  -v : enables verbose output
  -h : displays program synopsis and usage
```

To decrypt data using RSA decryption, run the program with:

```
$ ./decrypt [-hv] [-i infile] [-o outfile] -n privkey
```

along with any of the following command-line options

```
OPTIONS
  -i : specifies the input file to decrypt (default: stdin)
  -o : specifies the output file to decrypt (default: stdout)
  -n : specifies the file containing the private key (default: rsa.priv)
  -v : enables verbose output
  -h : displays program synopsis and usage
```

## Cleaning

Remove all files that are compiler generated with:

```
make clean
```

## Known Issues

None
