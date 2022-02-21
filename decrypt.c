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
    fprintf(stderr, "   Decrypts data using RSA decryption.\n");
    fprintf(stderr, "   Encrypted data is encrypted by the encrypt program.\n\n");
    fprintf(stderr, "USAGE\n");
    fprintf(stderr, "   ./decrypt [-hv] [-i infile] [-o outfile] -n privkey\n\n");
    fprintf(stderr, "OPTIONS\n");
    fprintf(stderr, "   -h              Display program help and usage.\n");
    fprintf(stderr, "   -v              Display verbose program output.\n");
    fprintf(stderr, "   -i infile       Input file of data to decrypt (default: stdin).\n");
    fprintf(stderr, "   -o outfile      Output file for decrypted data (default: stdout).\n");
    fprintf(stderr, "   -n pvfile       Private key file (default: rsa.priv).\n");
}

// driver code of the program
int main(int argc, char **argv) {
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *pvfile;
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
            if ((pvfile = fopen(optarg, "r")) == NULL) {
                printf("Failed to open pvfile\n");
                return 1;
            }
            use_default_file = false;
            break;
        default: help(); return 1;
        }
    }

    // Open the private key file.
    if (use_default_file) {
        pvfile = fopen("rsa.priv", "r");
    }

    // Read the private key from the opened private key file.
    mpz_t n, d;
    mpz_inits(n, d, NULL);
    rsa_read_priv(n, d, pvfile);

    // If verbose output is enabled
    if (verbose) {
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    // Decrypt the file
    rsa_decrypt_file(infile, outfile, n, d);

    // clear stuff used
    fclose(infile);
    fclose(outfile);
    fclose(pvfile);
    mpz_clears(n, d, NULL);

    return 0;
}
