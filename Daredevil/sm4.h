#ifndef SM4_H
#define SM4_H

// 白盒SM4专用版本
template <class TypeGuess> int construct_guess_SM4_whitebox (TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);

// 白盒SM4 T函数输出攻击
template <class TypeGuess> int construct_guess_SM4_whitebox_Toutput (TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);

// 白盒SM4编码输出攻击
template <class TypeGuess> int construct_guess_SM4_whitebox_encoded (TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);

#endif