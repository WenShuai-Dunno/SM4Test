#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "WBoxSm4Crypt.h"

// 复用Deadpool代码的块大小定义
const int BLOCK_SIZE = 16;

/**
 * @brief 从ASCII十六进制字符串中解析出前16字节二进制数据（兼容任意长度输入）
 * @param hex_str  输入的ASCII十六进制字符串（如64字节）
 * @param hex_len  输入字符串长度
 * @param bin_buf  输出的二进制数组（固定16字节）
 * @return int     0:成功 -1:输入为空/过短
 */
int hex_str_to_bin_16bytes(const char* hex_str, int hex_len, unsigned char* bin_buf) {
    if (hex_str == NULL || hex_len < 2 * BLOCK_SIZE) { // 至少需要32个ASCII字符才能解析16字节
        return -1;
    }

    // 仅解析前32个ASCII字符（对应16字节二进制），忽略剩余字符
    for (int i = 0; i < BLOCK_SIZE; i++) {
        char hex_byte[3] = {0};
        strncpy(hex_byte, &hex_str[2*i], 2); // 逐2个字符解析1个字节
        bin_buf[i] = (unsigned char)strtoul(hex_byte, NULL, 16);
    }
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char input[BLOCK_SIZE];
    unsigned char out[BLOCK_SIZE]; // 与Deadpool代码一致的16字节输出缓存
    char* encData = NULL;
    int encLen = 0;
    int i, ret;

    // 复用Deadpool代码的入参校验逻辑
    if (argc != 17)
    {
        printf("Usage:\n %s <16 bytes in hex, separated by spaces>\n", argv[0]);
        return 1;
    }

    // 完全复用原AES代码的输入解析逻辑
    for (i = 0; i < BLOCK_SIZE; i++)
    {
        input[i] = strtoul(argv[i + 1], NULL, 16);
    }

    // 调用SM4白盒加密接口
    ret = wBoxSm4Encrypt((const char*)input, BLOCK_SIZE, &encData, &encLen);
    if (ret != 0)
    {
        printf("Encryption failed! Error code: %d\n", ret);
        if (ret == -1) printf("Reason: Memory allocation failed\n");
        else if (ret == -2) printf("Reason: Invalid input data\n");
        free(encData);
        return -1;
    }

    // 兼容64字节ASCII串，仅解析前32字符为16字节二进制（对齐原AES输出）
    ret = hex_str_to_bin_16bytes(encData, encLen, out);
    if (ret != 0) {
        printf("Convert encrypted data failed! Error code: %d\n", ret);
        printf("Reason: Enc data len=%d (need at least 32)\n", encLen);
        free(encData);
        return -1;
    }

    // 复用Deadpool代码的打印逻辑（格式、长度100%对齐）
    printf("INPUT:     ");
    for (i = 0; i < BLOCK_SIZE; i++)
    {
        printf("%02x ", input[i]);
    }
    printf("\nOUTPUT:    ");
    for (i = 0; i < BLOCK_SIZE; i++)
    {
        printf("%02x ", out[i]);
    }
    printf("\n");

    // 释放内存，避免泄漏
    if (encData != NULL)
    {
        free(encData);
        encData = NULL;
    }

    return 0;
}