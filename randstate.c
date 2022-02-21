#include "randstate.h"

#include <stdint.h>
#include <gmp.h>

gmp_randstate_t state;

// initializes state with a Mersenne Twister algorithm, using seed as the random seed
void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
}

// clears and frees all memory used by the initialized global random state
void randstate_clear(void) {
    gmp_randclear(state);
}
