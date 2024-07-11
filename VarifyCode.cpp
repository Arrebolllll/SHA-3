#include <stdio.h>
#include <stdint.h>
#include <string.h>

// 左旋转宏定义
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

// Keccak的轮常数
const uint64_t keccakf_rndc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

// Keccak的旋转偏移常数
const uint8_t keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36,
    45, 55, 2, 14, 27, 41, 56, 8,
    25, 43, 62, 18, 39, 61, 20, 44
};

// Keccak的置换常数
const uint8_t keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16,
    8, 21, 24, 4, 15, 23, 19, 13,
    12, 2, 20, 14, 22, 9, 6, 1
};

// Keccakf函数，进行24轮的状态变换
void keccakf(uint64_t st[25])
{
    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < 24; r++) {
        // θ步
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // ρ和π步
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // χ步
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // ι步
        st[0] ^= keccakf_rndc[r];
    }
}

// SHA-3哈希函数
void sha3(const uint8_t* in, int inlen, uint8_t* md, int mdlen)
{
    uint64_t st[25] = { 0 }; // 初始化状态数组为0
    uint8_t temp[200]; // 临时数组用于填充
    int i;

    // 处理输入数据块
    while (inlen >= 200) {
        for (i = 0; i < 200 / 8; i++)
            st[i] ^= ((uint64_t*)in)[i];
        keccakf(st);
        in += 200;
        inlen -= 200;
    }

    // 剩余的输入数据填充
    for (i = 0; i < inlen; i++)
        temp[i] = in[i];
    temp[inlen] = 1; // 添加单一比特1
    inlen++;

    for (i = inlen; i < 200 - 1; i++)
        temp[i] = 0;
    temp[200 - 1] |= 0x80; // 添加单一比特0和一个1
    for (i = 0; i < 200 / 8; i++)
        st[i] ^= ((uint64_t*)temp)[i];
    keccakf(st);

    // 提取输出哈希值
    for (i = 0; i < mdlen; i++)
        md[i] = st[i / 8] >> 8 * (i % 8);
}

// SHA-3 224位哈希函数
void sha3_224(const uint8_t* in, int inlen, uint8_t* md)
{
    sha3(in, inlen, md, 28);
}

// SHA-3 256位哈希函数
void sha3_256(const uint8_t* in, int inlen, uint8_t* md)
{
    sha3(in, inlen, md, 32);
}

// SHA-3 384位哈希函数
void sha3_384(const uint8_t* in, int inlen, uint8_t* md)
{
    sha3(in, inlen, md, 48);
}

// SHA-3 512位哈希函数
void sha3_512(const uint8_t* in, int inlen, uint8_t* md)
{
    sha3(in, inlen, md, 64);
}

// 打印哈希值
void print_hash(const uint8_t* hash, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// 测试SHA-3 256位哈希函数
void test_sha3_256() {
    const uint8_t input[] = "abc";
    const uint8_t expected_output[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6a, 0x1d, 0xa9, 0x08, 0xbd,
        0xd1, 0x39, 0x9a, 0x0a, 0xbb, 0x43, 0x99, 0x24
    };
    uint8_t output[32];

    sha3_256(input, strlen((const char*)input), output);

    printf("SHA3-256(\"abc\") = ");
    print_hash(output, 32);

    if (memcmp(output, expected_output, 32) == 0) {
        printf("Test passed.\n");
    }
    else {
        printf("Test failed.\n");
    }
}

int main() {
    test_sha3_256();
    return 0;
}
