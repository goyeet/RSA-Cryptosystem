#include "randstate.h"
#include "numtheory.h"
#include "rsa.h"

#include <stdio.h>
#include <stdint.h>
#include <gmp.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define OPTIONS "i:o:n:vh" // Valid inputs

// prints help page
static void help() {
    fprintf(stderr, "SYNOPSIS\n");
    fprintf(stderr, "   Encrypts data using RSA encryption.\n");
    fprintf(stderr, "   Encrypted data is decrypted by the decrypt program.\n\n");
    fprintf(stderr, "USAGE\n");
    fprintf(stderr, "   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey\n\n");
    fprintf(stderr, "OPTIONS\n");
    fprintf(stderr, "   -h              Display program help and usage.\n");
    fprintf(stderr, "   -v              Display verbose program output.\n");
    fprintf(stderr, "   -i infile       Input file of data to encrypt (default: stdin).\n");
    fprintf(stderr, "   -o outfile      Output file for encrypted data (default: stdout).\n");
    fprintf(stderr, "   -n pbfile       Public key file (default: rsa.pub).\n");
}

// driver code of the program
int main(int argc, char **argv) {
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *pbfile;
    bool verbose = false;
    bool use_default_file = true;
    int32_t opt = 0;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h': help(); return 1;
        case 'v': verbose = true; break;
        case 'i':
            if ((infile = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "Failed to open infile\n");
                return 1;
            }
            break;
        case 'o':
            if ((outfile = fopen(optarg, "w")) == NULL) {
                fprintf(stderr, "Failed to open outfile\n");
                return 1;
            }
            break;
        case 'n':
            if ((pbfile = fopen(optarg, "r")) == NULL) {
                printf("Failed to open pbfile\n");
                return 1;
            }
            use_default_file = false;
            break;
        default: help(); return 1;
        }
    }

    // Open the public key file.
    if (use_default_file) {
        pbfile = fopen("rsa.pub", "r");
    }

    // Read the public key from the opened public key file.
    mpz_t n, e, s, username;
    mpz_inits(n, e, s, username, NULL);
    char *user = getenv("USER");
    rsa_read_pub(n, e, s, user, pbfile);

    // If verbose output is enabled
    if (verbose) {
        printf("user = %s\n", user);
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
    }

    // Convert the username that was read in to an mpz_t.
    mpz_set_str(username, user, 62);

    // Verify the signature.
    if (!rsa_verify(username, s, e, n)) {
        fprintf(stderr, "Error: Cannot be verified\n");
        mpz_clears(n, e, s, username, NULL);
        fclose(infile);
        fclose(outfile);
        fclose(pbfile);
        return 1;
    }

    // Encrypt the file
    rsa_encrypt_file(infile, outfile, n, e);

    // clear stuff used
    fclose(infile);
    fclose(outfile);
    fclose(pbfile);
    mpz_clears(n, e, s, username, NULL);

    return 0;
}
