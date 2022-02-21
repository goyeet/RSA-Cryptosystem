#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <math.h>
#include <inttypes.h>

#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

// Creates parts of a new RSA public key: two large primes p and q,
// their product n, and the public exponent e.
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    bool done = false;
    uint64_t p_bits, q_bits;
    mpz_t totient, temp1, temp2, rand_num, d;
    mpz_inits(totient, temp1, temp2, rand_num, d, NULL);
    // number of p_bits is random number in the range [nbits/4,(3 * nbits)/4)
    p_bits = random() % (((3 * nbits) / 4) - (nbits / 4)) + nbits / 4;
    // The remaining bits go to q
    q_bits = nbits - p_bits;
    // creates large primes p and q
    make_prime(p, p_bits + 1, iters);
    make_prime(q, q_bits + 1, iters);
    // compute n (product of p and q)
    mpz_mul(n, p, q); // n <- p * q
    // compute totient
    mpz_sub_ui(temp1, p, 1); // temp1 <- p - 1
    mpz_sub_ui(temp2, q, 1); // temp2 <- q - 1
    mpz_mul(totient, temp1, temp2); // totient <- temp1 * temp2
    // find suitable public exponent e
    while (done == false) {
        mpz_urandomb(rand_num, state, nbits);
        gcd(d, rand_num, totient); // greatest common divisor of rand_num and totient
        if (mpz_cmp_ui(d, 1) == 0) { // rand_num and totient are coprime
            done = true;
        }
    }
    // rand_num will be the public exponent
    mpz_set(e, rand_num); // e <- rand_num
    mpz_clears(totient, temp1, temp2, rand_num, d, NULL);
}

// Writes a public RSA key to pbfile.
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%Zx\n%Zx\n%Zx\n", n, e, s); // writes n, e, and s to pbfile
    fprintf(pbfile, "%s\n", username); // writes username to pbfile
}

// Reads a public RSA key from pbfile.
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n%Zx\n%Zx\n", n, e, s); // reads n, e, and s from pbfile
    fscanf(pbfile, "%s\n", username); // reads username from pbfile
}

// Creates a new RSA private key d given primes p and q and public exponent e.
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t temp1, temp2, totient;
    mpz_inits(temp1, temp2, totient, NULL);
    mpz_sub_ui(temp1, p, 1); // temp1 <- p - 1
    mpz_sub_ui(temp2, q, 1); // temp2 <- q - 1
    mpz_mul(totient, temp1, temp2); // totient <- temp1 * temp2
    // compute the inverse of e mod totient
    mod_inverse(d, e, totient);
    mpz_clears(temp1, temp2, totient, NULL);
}

// Writes a private RSA key to pvfile.
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n%Zx\n", n, d); // writes n and d to pvfile
}

// Reads a private RSA key from pvfile.
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n%Zx\n", n, d); // reads n and d from pvfile
}

// Performs RSA encryption, computing ciphertext c by encrypting message m
// using public exponent e and modulus n.
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
}

// Encrypts the contents of infile, writing the encrypted contents to outfile.
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    size_t j = 1;
    uint64_t index = 1;
    uint64_t bytes = 0;
    uint64_t bytes_to_read = 0;
    mpz_t c, m;
    mpz_inits(c, m, NULL);
    // Calculate the block size k
    uint64_t k = floor((mpz_sizeinbase(n, 2) - 1) / 8); // floor of (log2(n)-1)/8
    // Measures total number of bytes in infile
    fseek(infile, 0, SEEK_END);
    bytes = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    // While there are still unprocessed bytes in infile:
    while (j > 0) {
        // Dynamically allocate an array that can hold k bytes.
        uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));
        if (!block) {
            free(block);
            block = NULL;
        }
        // Set the zeroth byte of the block to 0xFF.
        block[0] = 0xFF;
        // Read at most k − 1 bytes in from infile, j is the number of bytes actually read.
        if (bytes >= bytes - (k - 1)) { // k - 1 bytes can be read
            bytes_to_read = k - 1;
        } else { // k - 1 bytes cannot be read
            bytes_to_read = bytes - index;
        }
        if (bytes_to_read == 0) { // no more bytes to be read
            free(block);
            block = NULL;
            break;
        }
        j = fread(block + 1, sizeof(uint8_t), bytes_to_read, infile);
        index += j;
        // Convert the read bytes, including the prepended 0xFF into an mpz_t m
        mpz_import(m, j + 1, 1, 1, 1, 0, block);
        // Encrypt m with rsa_encrypt()
        rsa_encrypt(c, m, e, n);
        // Write ciphertext to outfile as a hexstring followed by a trailing newline
        gmp_fprintf(outfile, "%Zx\n", c);
        free(block);
        block = NULL;
    }
    mpz_clears(c, m, NULL);
}

// Performs RSA decryption, computing message m by decrypting ciphertext c
// using private key d and public modulus n.
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}

// Decrypts the contents of infile, writing the decrypted contents to outfile.
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    size_t j = 0;
    int64_t bytes_written = 1;
    mpz_t c, m;
    mpz_inits(c, m, NULL);
    // Calculate the block size k
    uint64_t k = floor((mpz_sizeinbase(n, 2) - 1) / 8); // floor of (log2(n)-1)/8
    // While there are still unprocessed bytes in infile:
    while (true) {
        // Dynamically allocate an array that can hold k bytes.
        uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));
        if (!block) {
            free(block);
            block = NULL;
        }
        if (feof(infile)) {
            free(block);
            block = NULL;
            break;
        }
        // Scan in a hexstring, saving the hexstring as a mpz_t c.
        gmp_fscanf(infile, "%Zx\n", c);
        // Compute message m by decrypting ciphertext c
        rsa_decrypt(m, c, d, n);
        // Convert c back into bytes, storing them in the allocated block.
        // j is the number of bytes actually converted.
        mpz_export(block, &j, 1, 1, 1, 0, m);
        // Write out j − 1 bytes starting from index 1 of the block to outfile.
        bytes_written = fwrite(block + 1, sizeof(uint8_t), j - 1, outfile);
        free(block);
        block = NULL;
    }
    mpz_clears(c, m, NULL);
}

// Performs RSA signing, producing signature s by signing message m
// using private key d and public modulus n.
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
}

// Performs RSA verification, returning true if signature s is verified and false otherwise.
// Verification is the inverse of signing.
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n);
    if (mpz_cmp(t, m) == 0) { // if t == m
        mpz_clear(t);
        return true; // signature is verified
    } else {
        mpz_clear(t);
        return false; // signature is not verified
    }
}
