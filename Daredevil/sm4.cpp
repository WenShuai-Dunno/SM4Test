#include "utils.h"
#include "sm4.h"

/* 白盒SM4攻击专门版本
 * 假设条件：
 * 1. L变换已被合并到密钥运算的查找表中
 * 2. 每个密钥字节的查找表已经包含了S盒和部分L变换操作
 * 3. 攻击目标是白盒查找表的输出中间值
 */

// 辅助函数：计算汉明重量
uint8_t HW(uint16_t v)
{
  uint8_t c;
  for (c = 0; v; c++) v &= v - 1;
  return c;
}

/* 白盒SM4第一轮攻击 - 针对查找表输出
 * 在白盒实现中，通常会有多个查找表，每个表对应一个密钥字节
 * 攻击点：查找表的输出（已经包含了S盒和部分L变换）
 */
template <class TypeGuess>
int construct_guess_SM4_whitebox(TypeGuess ***guess, Matrix *m, uint32_t n_m,
                                uint32_t bytenum, uint32_t R, uint16_t * sbox,
                                uint32_t n_keys, int8_t bit) {
    TypeGuess **mem = NULL;
    uint32_t i, j, nrows = 0;
    
    // 验证输入
    if (R != 0) {
        fprintf(stderr, "[ERROR]: Only round 0 supported for SM4 whitebox.\n");
        return -1;
    }
    
    // 白盒SM4通常需要完整的16字节输入（X0, X1, X2, X3）
    // 但攻击特定字节时，可能需要额外的上下文信息
    for (i = 0; i < n_m; i++) {
        if (m[i].n_columns < 12) {  // 至少需要12字节（X1, X2, X3）
            fprintf(stderr, "[ERROR]: Whitebox SM4 requires at least 12 bytes per trace.\n");
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
    
    /* 白盒SM4攻击逻辑
     * 在白盒实现中，查找表通常是：T_byte = Table[X1_byte ⊕ X2_byte ⊕ X3_byte]
     * 其中Table已经包含了S盒、L变换的部分和轮密钥
     * 我们攻击的是Table的输出
     */
    for (i = 0; i < nrows; i++) {
        // 读取输入数据
        // 假设数据布局：[X1(4B) | X2(4B) | X3(4B)] 或者 [X0|X1|X2|X3]
        uint32_t X1 = 0, X2 = 0, X3 = 0;
        
        // 大端序读取32位字
        // 假设前12字节是X1, X2, X3（某些白盒实现可能不需要X0）
        for (int k = 0; k < 4; k++) {
            X1 = (X1 << 8) | mem[i][k];
            X2 = (X2 << 8) | mem[i][4 + k];
            X3 = (X3 << 8) | mem[i][8 + k];
        }
        
        // 提取要攻击的字节位置
        uint8_t byte_pos = bytenum % 4;
        
        // 获取X1, X2, X3的对应字节
        uint8_t X1_byte = (X1 >> (24 - 8 * byte_pos)) & 0xFF;
        uint8_t X2_byte = (X2 >> (24 - 8 * byte_pos)) & 0xFF;
        uint8_t X3_byte = (X3 >> (24 - 8 * byte_pos)) & 0xFF;
        
        // 计算X1 ⊕ X2 ⊕ X3（固定部分）
        uint8_t fixed_part = X1_byte ^ X2_byte ^ X3_byte;
        
        // 对每个密钥猜测进行计算
        for (j = 0; j < n_keys; j++) {
            // 在白盒SM4中，查找表通常已经编码了密钥
            // 我们假设查找表索引是 (fixed_part ^ key_guess)
            uint8_t table_index = fixed_part ^ j;
            
            // 查找表输出（已经包含了S盒和部分L变换）
            uint8_t table_output = sbox[table_index];
            
            // 选择攻击模型
            if (bit == -1) {
                // 汉明重量模型
                (*guess)[j][i] = HW((TypeGuess)table_output);
            } else if (bit >= 0 && bit < 8) {
                // 位模型
                (*guess)[j][i] = (TypeGuess)((table_output >> bit) & 1);
            } else {
                // 默认使用汉明重量
                (*guess)[j][i] = HW((TypeGuess)table_output);
            }
        }
    }
    
    free_matrix(&mem, nrows);
    return 0;
}

/* 白盒SM4攻击 - 针对合并L变换的查找表输出
 * 这个版本假设查找表已经包含了完整的T函数（S盒+L变换）
 * 攻击点：T函数的32位输出中的特定字节
 */
template <class TypeGuess>
int construct_guess_SM4_whitebox_Toutput(TypeGuess ***guess, Matrix *m, uint32_t n_m,
                                        uint32_t bytenum, uint32_t R, uint16_t * sbox,
                                        uint32_t n_keys, int8_t bit) {
    TypeGuess **mem = NULL;
    uint32_t i, j, nrows = 0;
    
    if (R != 0) {
        fprintf(stderr, "[ERROR]: Only round 0 supported for SM4 whitebox T-output.\n");
        return -1;
    }
    
    // 需要完整的16字节输入来计算T函数
    for (i = 0; i < n_m; i++) {
        if (m[i].n_columns < 16) {
            fprintf(stderr, "[ERROR]: Whitebox SM4 T-output requires 16 bytes per trace.\n");
            return -1;
        }
        nrows += m[i].n_rows;
    }
    
    if (import_matrices(&mem, m, n_m, 0) < 0) {
        fprintf(stderr, "[ERROR]: Importing matrix.\n");
        return -1;
    }
    
    if (*guess == NULL) {
        if (allocate_matrix<TypeGuess>(guess, n_keys, nrows) < 0) {
            fprintf(stderr, "[ERROR]: Allocating memory.\n");
            free_matrix(&mem, nrows);
            return -1;
        }
    }
    
    /* 白盒SM4 T函数输出攻击
     * 假设查找表已经实现了：T_output = L(Sbox(X1 ⊕ X2 ⊕ X3 ⊕ rk0))
     * 我们需要猜测rk0的32位值，但可以分字节攻击
     */
    for (i = 0; i < nrows; i++) {
        // 读取完整的输入数据
        uint32_t X0 = 0, X1 = 0, X2 = 0, X3 = 0;
        
        for (int k = 0; k < 4; k++) {
            X0 = (X0 << 8) | mem[i][k];
            X1 = (X1 << 8) | mem[i][4 + k];
            X2 = (X2 << 8) | mem[i][8 + k];
            X3 = (X3 << 8) | mem[i][12 + k];
        }
        
        // 提取要攻击的字节位置
        uint8_t byte_pos = bytenum % 4;
        
        // 获取X1, X2, X3的对应字节
        uint8_t X1_byte = (X1 >> (24 - 8 * byte_pos)) & 0xFF;
        uint8_t X2_byte = (X2 >> (24 - 8 * byte_pos)) & 0xFF;
        uint8_t X3_byte = (X3 >> (24 - 8 * byte_pos)) & 0xFF;
        
        // 计算固定部分
        uint8_t fixed_part = X1_byte ^ X2_byte ^ X3_byte;
        
        for (j = 0; j < n_keys; j++) {
            // 猜测轮密钥字节
            uint8_t key_byte_guess = j;
            
            // 对于T函数输出攻击，我们需要考虑L变换的影响
            // 但在白盒中，L变换可能已经被合并到查找表中
            // 我们假设查找表输出已经是T函数的完整字节输出
            
            // 查找表索引：输入字节 ⊕ 密钥字节
            uint8_t table_index = fixed_part ^ key_byte_guess;
            
            // 查找表输出（假设已经是T函数输出的对应字节）
            uint8_t T_output_byte = sbox[table_index];
            
            if (bit == -1) {
                (*guess)[j][i] = HW((TypeGuess)T_output_byte);
            } else if (bit >= 0 && bit < 8) {
                (*guess)[j][i] = (TypeGuess)((T_output_byte >> bit) & 1);
            }
        }
    }
    
    free_matrix(&mem, nrows);
    return 0;
}

/* 白盒SM4攻击 - 针对编码的查找表
 * 这个版本处理白盒实现中常见的编码情况
 * 查找表输出可能经过了仿射变换等编码
 */
template <class TypeGuess>
int construct_guess_SM4_whitebox_encoded(TypeGuess ***guess, Matrix *m, uint32_t n_m,
                                        uint32_t bytenum, uint32_t R, uint16_t * sbox,
                                        uint32_t n_keys, int8_t bit) {
    TypeGuess **mem = NULL;
    uint32_t i, j, nrows = 0;
    
    if (R != 0) {
        fprintf(stderr, "[ERROR]: Only round 0 supported for encoded SM4 whitebox.\n");
        return -1;
    }
    
    // 通常需要完整的输入
    for (i = 0; i < n_m; i++) {
        if (m[i].n_columns < 12) {
            fprintf(stderr, "[ERROR]: Encoded SM4 whitebox requires at least 12 bytes.\n");
            return -1;
        }
        nrows += m[i].n_rows;
    }
    
    if (import_matrices(&mem, m, n_m, 0) < 0) {
        fprintf(stderr, "[ERROR]: Importing matrix.\n");
        return -1;
    }
    
    if (*guess == NULL) {
        if (allocate_matrix<TypeGuess>(guess, n_keys, nrows) < 0) {
            fprintf(stderr, "[ERROR]: Allocating memory.\n");
            free_matrix(&mem, nrows);
            return -1;
        }
    }
    
    /* 编码白盒SM4攻击
     * 假设查找表输出经过了编码：Encoded_output = E(Sbox(input ⊕ key))
     * 其中E是编码函数（如仿射变换）
     * 我们需要攻击编码后的输出
     */
    for (i = 0; i < nrows; i++) {
        // 读取输入
        uint32_t X1 = 0, X2 = 0, X3 = 0;
        
        for (int k = 0; k < 4; k++) {
            X1 = (X1 << 8) | mem[i][k];
            X2 = (X2 << 8) | mem[i][4 + k];
            X3 = (X3 << 8) | mem[i][8 + k];
        }
        
        uint8_t byte_pos = bytenum % 4;
        uint8_t X1_byte = (X1 >> (24 - 8 * byte_pos)) & 0xFF;
        uint8_t X2_byte = (X2 >> (24 - 8 * byte_pos)) & 0xFF;
        uint8_t X3_byte = (X3 >> (24 - 8 * byte_pos)) & 0xFF;
        
        uint8_t fixed_part = X1_byte ^ X2_byte ^ X3_byte;
        
        for (j = 0; j < n_keys; j++) {
            // 查找表索引
            uint8_t table_index = fixed_part ^ j;
            
            // 查找表输出（已经编码）
            uint8_t encoded_output = sbox[table_index];
            
            if (bit == -1) {
                // 攻击编码输出的汉明重量
                (*guess)[j][i] = HW((TypeGuess)encoded_output);
            } else if (bit >= 0 && bit < 8) {
                // 攻击编码输出的特定位
                (*guess)[j][i] = (TypeGuess)((encoded_output >> bit) & 1);
            }
        }
    }
    
    free_matrix(&mem, nrows);
    return 0;
}

// 模板实例化
template int construct_guess_SM4_whitebox (uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);
template int construct_guess_SM4_whitebox ( int8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);

template int construct_guess_SM4_whitebox_Toutput (uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);
template int construct_guess_SM4_whitebox_Toutput ( int8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);

template int construct_guess_SM4_whitebox_encoded (uint8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);
template int construct_guess_SM4_whitebox_encoded ( int8_t ***guess, Matrix *m, uint32_t n_m, uint32_t bytenum, uint32_t R, uint16_t * sbox, uint32_t n_keys, int8_t bit);