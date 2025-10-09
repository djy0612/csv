#ifndef CSV_ATTEST_H
#define CSV_ATTEST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 常量定义 - 与官方代码保持一致
#define GUEST_ATTESTATION_NONCE_SIZE 16
#define GUEST_ATTESTATION_DATA_SIZE 64
#define HASH_LEN 32
#define USER_DATA_SIZE 64
#define HASH_BLOCK_LEN 32
#define SN_LEN 64
#define VM_ID_SIZE 16
#define VM_VERSION_SIZE 16
#define ECC_LEN 32
#define ECC_POINT_SIZE 72
#define SIZE_INT32 4
#define ATTESTATION_REPORT_SIGNED_SIZE 180

// 证书相关常量
#define KEY_USAGE_TYPE_HRK 0
#define KEY_USAGE_TYPE_HSK 0x13
#define KEY_USAGE_TYPE_OCA 0x1001
#define KEY_USAGE_TYPE_PEK 0x1002
#define KEY_USAGE_TYPE_CEK 0x1004
#define KEY_USAGE_TYPE_INVALID 0x1000

#define CURVE_ID_TYPE_P256 0x1
#define CURVE_ID_TYPE_P384 0x2
#define CURVE_ID_TYPE_SM2_256 0x3

// IOCTL相关定义
#define CSV_GUEST_IOC_TYPE 'D'
#define GET_ATTESTATION_REPORT _IOWR(CSV_GUEST_IOC_TYPE, 1, struct csv_guest_mem)

// Hypercall定义
#define KVM_HC_VM_ATTESTATION 100

// 证书下载地址
#define HRK_CERT_SITE "https://cert.hygon.cn/hrk"
#define KDS_CERT_SITE "https://cert.hygon.cn/hsk_cek?snumber="

// 文件名定义
#define HRK_FILENAME "./hrk.cert"
#define HSK_FILENAME "./hsk.cert"
#define CEK_FILENAME "./cek.cert"
#define HSK_CEK_FILENAME "hsk_cek.cert"
#define ATTESTATION_REPORT_FILE "./report.cert"
#define ATTESTATION_NONCE_FILE "./nonce.bin"

// 页面相关常量
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGEMAP_LEN 8

// 错误码定义
#define CSV_SUCCESS 0
#define CSV_ERROR_INVALID_PARAM -1
#define CSV_ERROR_MEMORY_ALLOC -2
#define CSV_ERROR_IOCTL_FAILED -3
#define CSV_ERROR_HYPERCALL_FAILED -4
#define CSV_ERROR_VERIFICATION_FAILED -5
#define CSV_ERROR_CERT_CHAIN_FAILED -6

// 数据结构定义 - 与官方代码保持一致
typedef struct _hash_block_u {
    unsigned char block[HASH_LEN];
} hash_block_u;

typedef struct _hash_block {
    uint8_t block[HASH_BLOCK_LEN];
} __attribute__ ((packed)) hash_block_t;

typedef struct _chip_key_id {
    uint8_t id[16];
} __attribute__ ((packed)) chip_key_id_t;

typedef struct _userid_u {
    unsigned short len;
    unsigned char uid[256 - sizeof(unsigned short)];
} __attribute__ ((packed)) userid_u;

typedef struct _ecc_pubkey {
    uint32_t curve_id;
    uint32_t Qx[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t Qy[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t user_id[256 / SIZE_INT32];
} __attribute__ ((packed)) ecc_pubkey_t;

typedef struct _ecc_signature {
    uint32_t sig_r[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t sig_s[ECC_POINT_SIZE / SIZE_INT32];
} __attribute__ ((packed)) ecc_signature_t;

// HRK证书结构体 - 与官方代码保持一致
struct _hygon_root_cert {
    uint32_t      version;
    chip_key_id_t key_id;
    chip_key_id_t certifying_id;
    uint32_t      key_usage;
    uint32_t      reserved1[24 / SIZE_INT32];
    union {
        uint32_t     pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + 256) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved2[108 / SIZE_INT32];
    union {
        uint32_t        signature[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig;
    };
    uint32_t reserved3[112 / SIZE_INT32];
} __attribute__((packed));

// CSV证书结构体 - 与官方代码保持一致
struct _hygon_csv_cert {
    uint32_t version;
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  reserved1;
    uint8_t  reserved2;
    uint32_t pubkey_usage;
    uint32_t pubkey_algo;
    union {
        uint32_t     pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + 256) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved3[624 / SIZE_INT32];
    uint32_t sig1_usage;
    uint32_t sig1_algo;
    union {
        uint32_t        sig1[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig1;
    };
    uint32_t reserved4[368 / SIZE_INT32];
    uint32_t sig2_usage;
    uint32_t sig2_algo;
    union {
        uint32_t        sig2[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig2;
    };
    uint32_t reserved5[368 / SIZE_INT32];
} __attribute__((packed));

// 类型别名 - 与官方代码保持一致
typedef struct _hygon_root_cert chip_root_cert_t;
typedef struct _hygon_csv_cert csv_cert_t;
typedef struct csv_attestation_report csv_attestation_report_t;
typedef uint32_t curve_id_t;

// 证明报告结构体 - 与官方代码完全一致
struct csv_attestation_report {
    hash_block_t user_pubkey_digest;      // 用户公钥摘要（哈希）
    uint8_t     vm_id[VM_ID_SIZE];        // 虚拟机ID
    uint8_t     vm_version[VM_VERSION_SIZE]; // 虚拟机版本
    uint8_t     user_data[USER_DATA_SIZE];   // 用户自定义数据
    uint8_t     mnonce[GUEST_ATTESTATION_NONCE_SIZE]; // 随机数（nonce）
    hash_block_t measure;                 // 虚拟机度量值（hash）
    uint32_t    policy;                   // 策略信息
    uint32_t    sig_usage;                // 签名用途
    uint32_t    sig_algo;                 // 签名算法
    uint32_t    anonce;                   // 另一个随机数
    union {
        uint32_t sig1[ECC_POINT_SIZE*2/SIZE_INT32];
        ecc_signature_t ecc_sig1;         // 签名1（ECC签名）
    };
    csv_cert_t  pek_cert;                 // PEK证书（平台加密密钥证书）
    uint8_t     sn[SN_LEN];               // 序列号
    uint8_t     reserved2[32];            // 保留字段
    hash_block_u mac;                     // MAC 校验值
};

// 用户数据结构体 - 与官方代码保持一致
struct csv_attestation_user_data {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
};

// IOCTL参数结构体 - 与官方代码保持一致
struct csv_guest_mem {
    unsigned long va;
    int size;
};

// 辅助数据结构体
struct ecc_point_q {
    uint32_t     curve_id;
    unsigned char Qx[ECC_LEN];
    unsigned char Qy[ECC_LEN];
};

struct ecdsa_sign {
    unsigned char r[ECC_LEN];
    unsigned char s[ECC_LEN];
};

// 函数声明
int csv_get_attestation_report_ioctl(unsigned char* report_buf, unsigned int buf_len,
                                   unsigned char* nonce, unsigned int nonce_len);

int csv_verify_attestation_report(unsigned char* report_buf, unsigned int buf_len, int verify_chain);

void csv_gen_random_bytes(void *buf, uint32_t len);

int csv_get_attestation_report(unsigned char* report_buf, unsigned int buf_len);

int csv_verify_session_mac(csv_attestation_report_t *report);

int csv_get_status(uint32_t *status);

int csv_save_pubkey_to_pem_file(ecc_pubkey_t *pubkey, const char *pemfile);

// 证书链验证相关函数
int validate_cert_chain(csv_attestation_report_t *report);
int verify_hrk_cert_signature(chip_root_cert_t *hrk);
int verify_hsk_cert_signature(chip_root_cert_t *hrk, chip_root_cert_t *hsk);
int verify_cek_signature(chip_root_cert_t *hsk, csv_cert_t *cek);
int verify_pek_cert_with_cek_signature(csv_cert_t *cek, csv_cert_t *pek);
int csv_attestation_report_verify(csv_attestation_report_t *report);
int csv_cert_verify(const char *data, uint32_t datalen, ecc_signature_t *signature, ecc_pubkey_t *pubkey);

// 证书加载相关函数
int load_hrk_file(char *filename, void *buff, size_t len);
int load_hsk_cek_file(char *chip_id, void *hsk, size_t hsk_len, void *cek, size_t cek_len);
int load_data_from_file(const char *path, void *buff, size_t len);
int get_hrk_cert(char *cert_file);
int get_hsk_cek_cert(char *cert_file, char *chip_id);

// 辅助函数
void invert_endian(unsigned char* buf, int len);
int gmssl_sm2_verify(struct ecc_point_q Q, unsigned char *userid, unsigned int userid_len, 
                     const unsigned char *msg, unsigned int msg_len, struct ecdsa_sign *sig_in);

#ifdef __cplusplus
}
#endif

#endif // CSV_ATTEST_H
