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

#define OPTIONS "hvb:i:n:d:s:" // Valid inputs

// prints help page
static void help() {
    fprintf(stderr, "SYNOPSIS\n");
    fprintf(stderr, "   Generates an RSA public/private key pair.\n\n");
    fprintf(stderr, "USAGE\n");
    fprintf(stderr, "   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n\n");
    fprintf(stderr, "OPTIONS\n");
    fprintf(stderr, "   -h              Display program help and usage.\n");
    fprintf(stderr, "   -v              Display verbose program output.\n");
    fprintf(stderr, "   -b bits         Minimum bits needed for public key n (default: 256).\n");
    fprintf(
        stderr, "   -i confidence   Miller-Rabin iterations for testing primes (default: 50).\n");
    fprintf(stderr, "   -n pbfile       Public key file (default: rsa.pub).\n");
    fprintf(stderr, "   -d pvfile       Private key file (default: rsa.priv).\n");
    fprintf(stderr, "   -s seed         Random seed for testing.\n");
}

// driver code of the program
int main(int argc, char **argv) {
    FILE *pbfile;
    FILE *pvfile;
    bool verbose = false;
    bool use_default_files = true;
    uint32_t seed = time(NULL); // default seed is time(NULL)
    uint64_t nbits = 256; // default min bits needed for public key is 256
    uint64_t iters = 50; // default Miller-Rabin iterations is 50
    int64_t opt = 0;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h': help(); return 0;
        case 'v': verbose = true; break;
        case 'b': nbits = strtoul(optarg, NULL, 10); break;
        case 'i': iters = strtoul(optarg, NULL, 10); break;
        case 'n':
            pbfile = fopen(optarg, "w+");
            if (pbfile == NULL) {
                fprintf(stderr, "Failed to open pbfile\n");
                return 1;
            }
            use_default_files = false;
            break;
        case 'd':
            pvfile = fopen(optarg, "w+");
            if (pvfile == NULL) {
                fprintf(stderr, "Failed to open pvfile\n");
                return 1;
            }
            use_default_files = false;
            break;
        case 's': seed = strtoul(optarg, NULL, 10); break;
        default: help(); return 1;
        }
    }

    // Open the public and private key files.
    if (use_default_files == true) {
        pbfile = fopen("rsa.pub", "w+");
        if (pbfile == NULL) {
            fprintf(stderr, "Failed to open pbfile\n");
            return 1;
        }
        pvfile = fopen("rsa.priv", "w+");
        if (pvfile == NULL) {
            fprintf(stderr, "Failed to open pvfile\n");
            return 1;
        }
    }

    // Make sure that the private key file permissions are set to 0600,
    // indicating read and write permissions for the user, and no permissions for anyone else.
    int fd = fileno(pvfile);
    fchmod(fd, 0600);

    // Initialize the random state.
    randstate_init(seed);

    // Make the public and private keys.
    mpz_t p, q, n, e, d, username, s;
    mpz_inits(p, q, n, e, d, username, s, NULL);
    rsa_make_pub(p, q, n, e, nbits, iters);
    rsa_make_priv(d, e, p, q);

    // Get the current user’s name as a string.
    char *user = getenv("USER");

    // Convert the username into an mpz_t, specifying the base as 62.
    mpz_set_str(username, user, 62);

    // Compute the signature s of the username.
    rsa_sign(s, username, d, n);

    // Write the computed public and private key to their respective files.
    rsa_write_pub(n, e, s, user, pbfile);
    rsa_write_priv(n, d, pvfile);

    // If verbose output is enabled:
    if (verbose) {
        printf("user = %s\n", user);
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("p (%d bits) = %Zd\n", mpz_sizeinbase(p, 2), p);
        gmp_printf("q (%d bits) = %Zd\n", mpz_sizeinbase(q, 2), q);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    // clear stuff used
    fclose(pbfile);
    fclose(pvfile);
    randstate_clear();
    mpz_clears(p, q, n, e, d, username, s, NULL);

    return 0;
}
