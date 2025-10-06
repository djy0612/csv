#ifndef CSV_ATTEST_H
#define CSV_ATTEST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 常量定义
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

// 错误码定义
#define CSV_SUCCESS 0
#define CSV_ERROR_INVALID_PARAM -1
#define CSV_ERROR_MEMORY_ALLOC -2
#define CSV_ERROR_IOCTL_FAILED -3
#define CSV_ERROR_HYPERCALL_FAILED -4
#define CSV_ERROR_VERIFICATION_FAILED -5
#define CSV_ERROR_CERT_CHAIN_FAILED -6

// 数据结构定义
typedef struct {
    unsigned char block[HASH_LEN];
} hash_block_u;

typedef struct {
    uint8_t block[HASH_BLOCK_LEN];
} hash_block_t;

typedef struct {
    uint8_t id[16];
} chip_key_id_t;

typedef struct {
    unsigned short len;
    unsigned char uid[256 - sizeof(unsigned short)];
} __attribute__ ((packed)) userid_u;

typedef struct {
    uint32_t curve_id;
    uint32_t Qx[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t Qy[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t user_id[256 / SIZE_INT32];
} __attribute__ ((packed)) ecc_pubkey_t;

typedef struct {
    uint32_t sig_r[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t sig_s[ECC_POINT_SIZE / SIZE_INT32];
} __attribute__ ((packed)) ecc_signature_t;

typedef struct {
    uint32_t version;
    chip_key_id_t key_id;
    chip_key_id_t certifying_id;
    uint32_t key_usage;
    uint32_t reserved1[24 / SIZE_INT32];
    union {
        uint32_t pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + 256) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved2[108 / SIZE_INT32];
    union {
        uint32_t signature[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig;
    };
    uint32_t reserved3[112 / SIZE_INT32];
} __attribute__((packed)) hygon_root_cert_t;

typedef struct {
    uint32_t version;
    uint8_t api_major;
    uint8_t api_minor;
    uint8_t reserved1;
    uint8_t reserved2;
    uint32_t pubkey_usage;
    uint32_t pubkey_algo;
    union {
        uint32_t pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + 256) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved3[624 / SIZE_INT32];
    uint32_t sig1_usage;
    uint32_t sig1_algo;
    union {
        uint32_t sig1[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig1;
    };
    uint32_t reserved4[368 / SIZE_INT32];
    uint32_t sig2_usage;
    uint32_t sig2_algo;
    union {
        uint32_t sig2[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig2;
    };
    uint32_t reserved5[368 / SIZE_INT32];
} __attribute__((packed)) hygon_csv_cert_t;

typedef hygon_root_cert_t chip_root_cert_t;
typedef hygon_csv_cert_t csv_cert_t;

typedef struct {
    hash_block_t user_pubkey_digest;
    uint8_t vm_id[VM_ID_SIZE];
    uint8_t vm_version[VM_VERSION_SIZE];
    uint8_t user_data[USER_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_t measure;
    uint32_t policy;
    uint32_t sig_usage;
    uint32_t sig_algo;
    uint32_t anonce;
    union {
        uint32_t sig1[ECC_POINT_SIZE*2/SIZE_INT32];
        ecc_signature_t ecc_sig1;
    };
    csv_cert_t pek_cert;
    uint8_t sn[SN_LEN];
    uint8_t reserved2[32];
    hash_block_u mac;
} csv_attestation_report_t;

typedef struct {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
} csv_attestation_user_data_t;

typedef struct {
    unsigned long va;
    int size;
} csv_guest_mem_t;

// 辅助数据结构
typedef struct {
    uint32_t curve_id;
    unsigned char Qx[ECC_LEN];
    unsigned char Qy[ECC_LEN];
} ecc_point_q;

typedef struct {
    unsigned char r[ECC_LEN];
    unsigned char s[ECC_LEN];
} ecdsa_sign;

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
