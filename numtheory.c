#include <stdio.h>
#include <stdint.h>
#include <gmp.h>
#include <stdbool.h>

#include "randstate.h"
#include "numtheory.h"

// Computes the greatest common divisor of a and b, storing the value of the computed divisor in d.
void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t temp, a_val, b_val;
    mpz_inits(temp, a_val, b_val, NULL);
    mpz_set(a_val, a);
    mpz_set(b_val, b);
    while (mpz_cmp_ui(b_val, 0) != 0) { // while b != 0
        mpz_set(temp, b_val); // t <- b
        mpz_mod(b_val, a_val, b_val); // b <- a mod b
        mpz_set(a_val, temp); // a <- t
    }
    mpz_set(d, a_val); // d <- a
    mpz_clears(temp, a_val, b_val, NULL);
}

// Computes the inverse i of a modulo n. If a modular inverse cannot be found, i is set to 0.
void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r, rp, t, tp, q, temp;
    mpz_inits(r, rp, t, tp, q, temp, NULL);
    mpz_set(r, n); // r <- n
    mpz_set(rp, a); // rp <- a
    mpz_set_ui(t, 0); // t <- 0
    mpz_set_ui(tp, 1); // t' <- 1
    while (mpz_cmp_ui(rp, 0) != 0) { // while r' != 0
        mpz_fdiv_q(q, r, rp); // q <- floor of r/r'
        mpz_set(temp, r); // temp <- r
        mpz_set(r, rp); // r <- r'
        mpz_submul(temp, q, rp); // temp <- (r - q * r')
        mpz_set(rp, temp); // r' <- (r - q * r')
        mpz_set(temp, t); // temp <- t
        mpz_set(t, tp); // t <- t'
        mpz_submul(temp, q, tp); // temp <- (t - q * t')
        mpz_set(tp, temp); // t' <- (t - q * t')
    }
    if (mpz_cmp_ui(r, 1) > 0) { // if r > 1
        mpz_set_ui(t, 0); // t <- 0
    }
    if (mpz_cmp_ui(t, 0) < 0) { // if t < 0
        mpz_add(t, t, n); // t <- t + n
    }
    mpz_set(i, t); // i <- t
    mpz_clears(r, rp, t, tp, q, temp, NULL);
}

// Performs fast modular exponentiation, computing base raised to the exponent power modulo modulus
// and stores the computed result in out.
void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t v, p, d, remainder, product, expression, temp;
    mpz_inits(v, p, d, remainder, product, expression, temp, NULL);
    mpz_set_ui(v, 1); // v <- 1
    mpz_set(p, base); // p <- a
    mpz_set(d, exponent); // d <- exponent
    while (mpz_cmp_ui(d, 0) > 0) { // while d > 0
        mpz_mod_ui(remainder, d, 2); // checking remainder of d/2
        if (mpz_cmp_ui(remainder, 1) == 0) { // if remainder is 1 (d is odd)
            mpz_mul(product, v, p); // product <- v * p
            mpz_mod(expression, product, modulus); // expression <- product % modulus
            mpz_set(v, expression); // v <- expression
        }
        mpz_mul(product, p, p); // product <- p * p
        mpz_mod(expression, product, modulus); // expression <- product % modulus
        mpz_set(p, expression); // p <- expression
        mpz_fdiv_q_ui(d, d, 2); // d <- floor of d/2
    }
    mpz_set(out, v); // out <- v
    mpz_clears(v, p, d, remainder, product, expression, temp, NULL);
}

// Conducts the Miller-Rabin primality test to indicate whether or not n is prime using
// iters number of Miller-Rabin iterations.
bool is_prime(mpz_t n, uint64_t iters) {
    mpz_t s, r, a, y, j, t, remainder, temp, temp2;
    mpz_inits(s, r, a, y, j, t, remainder, temp, temp2, NULL);
    // Corner cases (1 and 4 are false, 2 and 3 are true)
    if ((mpz_cmp_ui(n, 1) <= 0) || (mpz_cmp_ui(n, 4) == 0)) { // if n <= 1 or n == 4
        mpz_clears(s, r, a, y, j, t, remainder, temp, temp2, NULL);
        return false;
    }
    if ((mpz_cmp_ui(n, 2) == 0) || (mpz_cmp_ui(n, 3) == 0)) { // if n == 2 or n == 3
        return true;
    }
    // loop to make sure r is odd
    mpz_set_ui(s, 0); // s <- 0
    mpz_sub_ui(r, n, 1); // r <- n - 1
    mpz_mod_ui(remainder, r, 2); // checking remainder of r/2
    while (mpz_cmp_ui(remainder, 0) == 0) { // while r is even
        mpz_add_ui(s, s, 1); // s <- s + 1
        mpz_divexact_ui(r, r, 2); // r = r/2
        mpz_mod_ui(remainder, r, 2); // checking remainder of r/2
    }
    mpz_set_ui(t, 2); // t <- 2 for pow_mod on line 110
    for (uint64_t i = 1; i < iters; i++) {
        mpz_sub_ui(temp, n, 3); // temp <- n - 3
        mpz_urandomm(a, state, temp); // choose a random number a between 0 and n - 4
        mpz_add_ui(a, a, 2); // a += 2 to make the random number between 2 and n - 2
        pow_mod(y, a, r, n); // y <- pow_mod(a, r, n)
        mpz_sub_ui(temp, n, 1); // temp <- n - 1
        mpz_sub_ui(temp2, s, 1); // temp2 <- s - 1
        if ((mpz_cmp_ui(y, 1) != 0) && (mpz_cmp(y, temp) != 0)) { // if y != 1 and y != n - 1
            mpz_set_ui(j, 1); // j <- 1
            while ((mpz_cmp(j, temp2) <= 0) && (mpz_cmp(y, temp) != 0)) { // while j<=s-1 and y!=n-1
                pow_mod(y, y, t, n); // y <- pow_mod(y, 2, n)
                if ((mpz_cmp_ui(y, 1)) == 0) { // if y == 1
                    mpz_clears(s, r, a, y, j, t, remainder, temp, temp2, NULL);
                    return false;
                }
                mpz_add_ui(j, j, 1); // j <- j + 1
            }
            if (mpz_cmp(y, temp) != 0) { // if y != n - 1
                mpz_clears(s, r, a, y, j, t, remainder, temp, temp2, NULL);
                return false;
            }
        }
    }
    mpz_clears(s, r, a, y, j, t, remainder, temp, temp2, NULL);
    return true; // n is probably prime
}

// Generates a new prime number stored in p at least bits number of bits long.
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_urandomb(p, state, bits);
    while ((mpz_sizeinbase(p, 2) < bits - 1) || !is_prime(p, iters)) {
        mpz_urandomb(p, state, bits);
    }
}
