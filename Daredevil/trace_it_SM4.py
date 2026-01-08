#!/usr/bin/env python

import sys
sys.path.insert(0, '../../')
from deadpool_dca import *

def processinput(iblock, blocksize):
    p='%0*x' % (2*blocksize, iblock)
    return (None, [p[j*2:(j+1)*2] for j in range(len(p)/2)])

def processoutput(output, blocksize):
    return int(''.join([x for x in output.split('\n') if x.find('OUTPUT')==0][0][10:].split(' ')), 16)

T=TracerGrind('../target/wb_sm4_challenge', processinput, processoutput, ARCH.amd64, 16,  addr_range='0x04000000-0x04030000')
# Tracing only the first round:
#T=TracerGrind('../target/wb_sm4_challenge', processinput, processoutput, ARCH.amd64, 16,  addr_range='0x108000-0x10c000')
T.run(500)
bin2daredevil(configs={'attack_sbox':   {'algorithm':'SM4', 'position':'LUT/SM4_WHITEBOX_SBOX'}})
# 配置2：T函数输出攻击
# bin2daredevil(configs={
#     'attack_sbox': {
#         'algorithm': 'SM4',
#         'position': 'LUT/SM4_WHITEBOX_T_OUTPUT'
#     }
# })

# 配置3：编码白盒攻击
# bin2daredevil(configs={
#     'attack_sbox': {
#         'algorithm': 'SM4',
#         'position': 'LUT/SM4_WHITEBOX_LUT'
#     }
# })

# 配置4：多位置攻击（如果需要攻击多个S盒位置）
# bin2daredevil(configs={
#     'attack_sbox': {
#         'algorithm': 'SM4',
#         'position': 'LUT/SM4_WHITEBOX_SBOX',
#         'bytenum': 'all'  # 攻击所有字节
#     },
#     'attack_t_output': {
#         'algorithm': 'SM4',
#         'position': 'LUT/SM4_WHITEBOX_T_OUTPUT',
#         'bytenum': 'all'
#     }
# })
