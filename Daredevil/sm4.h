#ifndef SM4_H
#define SM4_H

#include "utils.h"

template <class TypeGuess> int construct_guess_SM4 (TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);

#endif