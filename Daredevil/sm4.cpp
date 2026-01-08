#include "utils.h"
#include "sm4.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// 宏定义：SM4算法核心参数（避免魔法数字）
#define SM4_BLOCK_BYTES     16      // SM4分组长度（128位=16字节）
#define SM4_WORD_BYTES      4       // SM4单个字长度（32位=4字节）
#define SM4_MAX_BYTE_NUM    3       // bytenum合法范围：0~3
#define SM4_KEY_GUESS_NUM   256     // 单字节密钥猜测空间（0~255）

/**
 * @brief 计算8位整数的汉明重量（二进制中1的个数）
 * @param v 8位输入值
 * @return 汉明重量（0~8）
 */
static uint8_t HW(uint8_t v)
{
    uint8_t c = 0;
    for (; v != 0; c++) {
        v &= v - 1; // 清除最低位的1
    }
    return c;
}

/**
 * @brief 构造SM4白盒攻击的猜测矩阵（适配肖-来白盒SM4攻击逻辑）
 * @tparam TypeGuess 猜测矩阵的数据类型（uint8_t/int8_t）
 * @param guess 输出：猜测矩阵（n_keys行 × nrows列）
 * @param m 输入：消息矩阵数组（包含SM4分组数据）
 * @param n_m 输入：消息矩阵的数量
 * @param bytenum 输入：攻击的字节索引（0~3，对应32位字的第bytenum字节）
 * @param R 输入：攻击的轮数（当前仅支持轮0）
 * @param sbox 输入：SM4 S盒（含白盒混淆的S盒表）
 * @param n_keys 输入：密钥猜测空间大小（必须为256）
 * @param bit 输入：计算模式（-1=汉明重量；0~7=指定比特位）
 * @param is_little_endian 输入：是否小端序存储（默认大端，符合SM4国标）
 * @return 0=成功；-1=失败
 */
template <class TypeGuess>
int construct_guess_SM4(TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum,
                        uint32_t R, uint16_t *sbox, uint32_t n_keys, int8_t bit, 
                        bool is_little_endian) {
    TypeGuess **mem = NULL;
    uint32_t i, j, nrows = 0;

    // 1. 入参合法性校验
    // 1.1 轮数校验（当前仅支持轮0）
    if (R != 0) {
        fprintf(stderr, "[ERROR]: construct_guess_SM4: Only round 0 is supported (input R=%u).\n", R);
        return -1;
    }

    // 1.2 字节索引校验
    if (bytenum > SM4_MAX_BYTE_NUM) {
        fprintf(stderr, "[ERROR]: construct_guess_SM4: bytenum (%u) out of range (0~%d).\n", 
                bytenum, SM4_MAX_BYTE_NUM);
        return -1;
    }

    // 1.3 密钥猜测空间校验
    if (n_keys != SM4_KEY_GUESS_NUM) {
        fprintf(stderr, "[ERROR]: construct_guess_SM4: n_keys (%u) must be %d (1-byte key space).\n", 
                n_keys, SM4_KEY_GUESS_NUM);
        return -1;
    }

    // 1.4 比特位模式校验
    if (bit != -1 && (bit < 0 || bit >= 8)) {
        fprintf(stderr, "[ERROR]: construct_guess_SM4: bit (%d) out of range (-1 or 0~7).\n", bit);
        return -1;
    }

    // 2. 统计总行数并校验消息矩阵列数
    for (i = 0; i < n_m; i++) {
        // 每个消息矩阵需至少包含完整的SM4分组（16字节）
        if (m[i].n_columns < SM4_BLOCK_BYTES) {
            fprintf(stderr, "[ERROR]: construct_guess_SM4: Matrix %u n_columns (%d) < %d.\n", 
                    i, m[i].n_columns, SM4_BLOCK_BYTES);
            return -1;
        }
        nrows += m[i].n_rows;
    }

    // 3. 导入消息矩阵到内存
    if (import_matrices(&mem, m, n_m, 0) < 0) {
        fprintf(stderr, "[ERROR]: construct_guess_SM4: Failed to import matrices.\n");
        return -1;
    }

    // 4. 分配猜测矩阵内存（若未初始化）
    if (*guess == NULL) {
        if (allocate_matrix<TypeGuess>(guess, n_keys, nrows) < 0) {
            fprintf(stderr, "[ERROR]: construct_guess_SM4: Failed to allocate guess matrix.\n");
            free_matrix(&mem, nrows); // 释放已分配的内存，避免泄漏
            return -1;
        }
    }

    // 5. 核心逻辑：构造猜测矩阵
    // SM4轮0攻击点：T(X₁⊕X₂⊕X₃⊕rk₀) = L(τ(X₁⊕X₂⊕X₃⊕rk₀))
    // 其中 τ(x) = (Sbox(a₀), Sbox(a₁), Sbox(a₂), Sbox(a₃))，攻击τ的单个字节
    for (i = 0; i < nrows; i++) {
        // 5.1 计算目标字节的偏移量（适配大小端）
        uint32_t x1_offset = 1 * SM4_WORD_BYTES + bytenum; // X₁的起始偏移：4字节
        uint32_t x2_offset = 2 * SM4_WORD_BYTES + bytenum; // X₂的起始偏移：8字节
        uint32_t x3_offset = 3 * SM4_WORD_BYTES + bytenum; // X₃的起始偏移：12字节
        
        if (is_little_endian) {
            // 小端序：32位字的字节存储顺序为 [3,2,1,0]（如X₁的字节7,6,5,4）
            x1_offset = 1 * SM4_WORD_BYTES + (SM4_WORD_BYTES - 1 - bytenum);
            x2_offset = 2 * SM4_WORD_BYTES + (SM4_WORD_BYTES - 1 - bytenum);
            x3_offset = 3 * SM4_WORD_BYTES + (SM4_WORD_BYTES - 1 - bytenum);
        }

        // 5.2 提取X₁、X₂、X₃的目标字节
        uint8_t x1_byte = (uint8_t)mem[i][x1_offset];
        uint8_t x2_byte = (uint8_t)mem[i][x2_offset];
        uint8_t x3_byte = (uint8_t)mem[i][x3_offset];

        // 5.3 计算 X₁⊕X₂⊕X₃（T函数输入的前半部分）
        uint8_t xor_result = x1_byte ^ x2_byte ^ x3_byte;

        // 5.4 遍历所有密钥猜测值，构造猜测矩阵
        for (j = 0; j < n_keys; j++) {
            // 肖-来白盒SM4：S_ij(x) = Sbox(x ⊕ k_j)（k_j为轮密钥的单个字节）
            uint8_t sbox_input = xor_result ^ (uint8_t)j;
            uint8_t sbox_output = (uint8_t)sbox[sbox_input]; // S盒输出（8位）

            // 根据bit参数计算猜测值
            if (bit == -1) {
                // 模式1：计算汉明重量
                (*guess)[j][i] = (TypeGuess)HW(sbox_output);
            } else {
                // 模式2：提取指定比特位（0=最低位，7=最高位）
                (*guess)[j][i] = (TypeGuess)((sbox_output >> bit) & 0x01);
            }
        }
    }

    // 6. 释放临时内存，避免泄漏
    free_matrix(&mem, nrows);
    return 0;
}

// 模板实例化（仅保留必要类型，移除冗余）
template int construct_guess_SM4(uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum,
                                 uint32_t R, uint16_t *sbox, uint32_t n_keys, int8_t bit,
                                 bool is_little_endian);

template int construct_guess_SM4(int8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum,
                                 uint32_t R, uint16_t *sbox, uint32_t n_keys, int8_t bit,
                                 bool is_little_endian);

// 兼容原有接口（默认大端序）
template <class TypeGuess>
int construct_guess_SM4(TypeGuess ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum,
                        uint32_t R, uint16_t *sbox, uint32_t n_keys, int8_t bit) {
    return construct_guess_SM4(guess, m, n_m, bytenum, R, sbox, n_keys, bit, false);
}

// 原有接口的模板实例化（保证向下兼容）
template int construct_guess_SM4(uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum,
                                 uint32_t R, uint16_t *sbox, uint32_t n_keys, int8_t bit);

template int construct_guess_SM4(int8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum,
                                 uint32_t R, uint16_t *sbox, uint32_t n_keys, int8_t bit);