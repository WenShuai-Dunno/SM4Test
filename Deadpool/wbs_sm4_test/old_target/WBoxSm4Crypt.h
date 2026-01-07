#include <string.h>
#include <stdlib.h>

/**
 * @brief 获取sm4白盒版本号
 * @param version      版本号指针
 */
void getWBoxSm4Version(char** version);

/**
 * @brief sm4白盒加密
 * @param pData        明文
 * @param dataLen      明文长度
 * @param encData      密文指针[使用后,非空需要释放]
 * @param encLen       密文长度指针
 * @return int         加密状态码 0:正常 -1:申请内存失败  -2:传入数据错误
 */
int wBoxSm4Encrypt(const char* pData, int dataLen, char** encData, int *encLen);

