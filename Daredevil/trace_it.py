#!/usr/bin/env python

import sys
sys.path.insert(0, '../../')
from deadpool_dca import *

def processinput(iblock, blocksize):
    # SM4分组大小是128位 = 16字节（与AES相同）
    p='%0*x' % (2*blocksize, iblock)
    return (None, [p[j*2:(j+1)*2] for j in range(len(p)/2)])

def processoutput(output, blocksize):
    return int(''.join([x for x in output.split('\n') if x.find('OUTPUT')==0][0][10:].split(' ')), 16)

T=TracerGrind('../target/wb_sm4_challenge', processinput, processoutput, ARCH.amd64, 16, addr_range='0x108000-0x130000')

# 如果只想追踪第一轮，可以缩小范围
# T=TracerGrind('../target/wb_sm4_challenge', processinput, processoutput, ARCH.amd64, 16, addr_range='0x108000-0x10c000')

T.run(200)

# 修改为SM4配置：
# 白盒SM4的关键攻击点是Part 2的查找表（8->32位查找表，包含密钥）
bin2daredevil(configs={
    'attack_sm4_sbox': {
        'algorithm':'SM4', 
        'position':'LUT/SM4_AFTER_SBOX',
        'round':0,
        'bytenum':0  # 可以攻击4个S-box中的任意一个（0-3）
    }
})