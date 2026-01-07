/* ===================================================================== */
/* This file is part of Daredevil                                        */
/* Daredevil is a side-channel analysis tool                             */
/* Copyright (C) 2016                                                    */
/* Original author:   Paul Bottinelli <paulbottinelli@hotmail.com>       */
/* Contributors:      Joppe Bos <joppe_bos@hotmail.com>                  */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* any later version.                                                    */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/* ===================================================================== */
#include "utils.h"
#include "sm4.h"

/* Given the messages (m), use the bytenum-th byte to construct
 * the guesses for round R with the specified sbox.
 */
template <class TypeGuess>
int construct_guess_SM4(TypeGuess ***guess, Matrix *m, uint32_t n_m,
                       uint32_t bytenum, uint32_t R, uint16_t * sbox,
                       uint32_t n_keys, int8_t bit) {
    TypeGuess **mem = NULL;
    uint32_t i, j, nrows = 0;
    
    // 验证输入
    if (R != 0) {
        fprintf(stderr, "[ERROR]: Only round 0 supported for SM4.\n");
        return -1;
    }
    
    // SM4需要至少12字节输入（X1, X2, X3各32位）
    for (i = 0; i < n_m; i++) {
        if (m[i].n_columns < 12) {  // 至少需要12字节
            fprintf(stderr, "[ERROR]: SM4 requires at least 12 bytes per trace.\n");
            return -1;
        }
        nrows += m[i].n_rows;
    }
    
    // 加载数据
    if (import_matrices(&mem, m, n_m, 0) < 0) {
        fprintf(stderr, "[ERROR]: Importing matrix.\n");
        return -1;
    }
    
    // 分配猜测矩阵
    if (*guess == NULL) {
        if (allocate_matrix<TypeGuess>(guess, n_keys, nrows) < 0) {
            fprintf(stderr, "[ERROR]: Allocating memory.\n");
            free_matrix(&mem, nrows);
            return -1;
        }
    }
    
    // **SM4特定的中间值计算**
    for (i = 0; i < nrows; i++) {
        // 假设数据布局：[X1(4B) | X2(4B) | X3(4B)]
        uint32_t X1 = 0, X2 = 0, X3 = 0;
        
        // 大端序读取32位字
        for (int k = 0; k < 4; k++) {
            X1 = (X1 << 8) | mem[i][k];
            X2 = (X2 << 8) | mem[i][4 + k];
            X3 = (X3 << 8) | mem[i][8 + k];
        }
        
        // 计算T = X1 ⊕ X2 ⊕ X3
        uint32_t T = X1 ^ X2 ^ X3;
        
        // 提取要攻击的字节（大端序）
        uint8_t byte_pos = bytenum % 4;
        uint8_t T_byte = (T >> (24 - 8 * byte_pos)) & 0xFF;
        
        for (j = 0; j < n_keys; j++) {
            uint8_t sbox_in = T_byte ^ j;  // 轮密钥字节假设
            
            if (bit == -1) {
                (*guess)[j][i] = HW((TypeGuess)sbox[sbox_in]);
            } else if (bit >= 0 && bit < 8) {
                (*guess)[j][i] = (TypeGuess)((sbox[sbox_in] >> bit) & 1);
            }
        }
    }
    
    free_matrix(&mem, nrows);
    return 0;
}

template int construct_guess_SM4 (uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);
template int construct_guess_SM4 ( int8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);