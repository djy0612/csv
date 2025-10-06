#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <time.h>
#include <immintrin.h>
#include <errno.h>
#include <libgen.h>

#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/sm3.h"
#include "openssl/obj_mac.h"
#include "openssl/pem.h"

// 从 csv_status.h 复制的关键定义
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGEMAP_LEN 8

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

#define CSV_GUEST_IOC_TYPE 'D'
#define GET_ATTESTATION_REPORT _IOWR(CSV_GUEST_IOC_TYPE, 1, struct csv_guest_mem)

#define KVM_HC_VM_ATTESTATION 100

// 证书相关定义
#define KEY_USAGE_TYPE_HRK 0
#define KEY_USAGE_TYPE_HSK 0x13
#define KEY_USAGE_TYPE_OCA 0x1001
#define KEY_USAGE_TYPE_PEK 0x1002
#define KEY_USAGE_TYPE_CEK 0x1004
#define KEY_USAGE_TYPE_INVALID 0x1000

#define CURVE_ID_TYPE_P256 0x1
#define CURVE_ID_TYPE_P384 0x2
#define CURVE_ID_TYPE_SM2_256 0x3

#define ATTESTATION_REPORT_SIGNED_SIZE 180

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

// 日志宏
#ifdef LOG_ON
#define logcat printf
#else
#define logcat(format, ...)
#endif

// 数据结构定义
typedef struct _hash_block_u {
    unsigned char block[HASH_LEN];
} hash_block_u;

typedef struct _userid_u {
    unsigned short len;
    unsigned char uid[256 - sizeof(unsigned short)];
} __attribute__ ((packed)) userid_u;

typedef struct _hash_block {
    uint8_t block[HASH_BLOCK_LEN];
} __attribute__ ((packed)) hash_block_t;

typedef struct _chip_key_id {
    uint8_t id[16];
} __attribute__ ((packed)) chip_key_id_t;

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

typedef struct _hygon_root_cert {
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
} __attribute__((packed));

typedef struct _hygon_csv_cert {
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
} __attribute__((packed));

typedef struct _hygon_root_cert CHIP_ROOT_CERT_t;
typedef struct _hygon_csv_cert CSV_CERT_t;

struct csv_attestation_report {
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
    CSV_CERT_t pek_cert;
    uint8_t sn[SN_LEN];
    uint8_t reserved2[32];
    hash_block_u mac;
};

struct csv_attestation_user_data {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
};

struct csv_guest_mem {
    unsigned long va;
    int size;
};

// 全局变量
static uint8_t g_user_data[USER_DATA_SIZE];
static uint8_t g_measure[HASH_BLOCK_LEN];
static uint8_t g_chip_id[SN_LEN];
static uint8_t g_mnonce[GUEST_ATTESTATION_NONCE_SIZE] = {0};
static uint8_t r_mnonce[GUEST_ATTESTATION_NONCE_SIZE] = {0};
static CSV_CERT_t g_pek_cert;
static char *external_oca_file = NULL;

// 辅助函数
void csv_gen_random_bytes(void *buf, uint32_t len)
{
    uint32_t i;
    uint8_t *buf_byte = (uint8_t *)buf;

    srand(time(NULL));

    for (i = 0; i < len; i++) {
        buf_byte[i] = rand() & 0xFF;
    }
}

void csv_data_dump(const char* name, uint8_t *data, uint32_t len)
{
    logcat("%s:\n", name);
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        logcat("%02hhx", c);
    }
    logcat("\n");
}

uint64_t va_to_pa(uint64_t va)
{
    FILE *pagemap;
    uint64_t offset, pfn;
    
    pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) {
        logcat("open pagemap fail\n");
        return 0;
    }
    
    offset = va / PAGE_SIZE * PAGEMAP_LEN;
    if(fseek(pagemap, offset, SEEK_SET) != 0) {
        logcat("seek pagemap fail\n");
        fclose(pagemap);
        return 0;
    }
    
    if (fread(&pfn, 1, PAGEMAP_LEN - 1, pagemap) != PAGEMAP_LEN - 1) {
        logcat("read pagemap fail\n");
        fclose(pagemap);
        return 0;
    }
    
    pfn &= 0x7FFFFFFFFFFFFF;
    fclose(pagemap);
    
    return pfn << PAGE_SHIFT;
}

long hypercall(unsigned int nr, unsigned long p1, unsigned int len)
{
    long ret = 0;

    asm volatile("vmmcall"
        : "=a"(ret)
        : "a"(nr), "b"(p1), "c"(len)
        : "memory");
    return ret;
}

int get_attestation_report(struct csv_attestation_report *report)
{
    struct csv_attestation_user_data *user_data;
    uint64_t user_data_pa;
    long ret;
    
    if (!report) {
        logcat("NULL pointer for report\n");
        return -1;
    }

    user_data = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (user_data == MAP_FAILED) {
        logcat("mmap failed\n");
        return -1;
    }
    
    logcat("mmap %p\n", user_data);
    
    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    csv_gen_random_bytes(user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    memcpy(g_mnonce, user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);

    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);
    
    csv_data_dump("data", user_data->data, GUEST_ATTESTATION_DATA_SIZE);
    csv_data_dump("mnonce", user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    csv_data_dump("hash", (unsigned char *)&user_data->hash, sizeof(hash_block_u));
    logcat("data: %s\n", user_data->data);

    user_data_pa = va_to_pa((uint64_t)user_data);
    logcat("user_data_pa: %lx\n", user_data_pa);
    
    ret = hypercall(KVM_HC_VM_ATTESTATION, user_data_pa, PAGE_SIZE);
    if (ret) {
        logcat("hypercall fail: %ld\n", ret);
        munmap(user_data, PAGE_SIZE);
        return -1;
    }
    
    memcpy(report, user_data, sizeof(*report));
    munmap(user_data, PAGE_SIZE);

    return 0;
}

int verify_session_mac(struct csv_attestation_report *report)
{
    hash_block_u hmac = {0};
    
    sm3_hmac((const unsigned char*)(&report->pek_cert),
             sizeof(report->pek_cert) + SN_LEN + sizeof(report->reserved2),
             g_mnonce, GUEST_ATTESTATION_NONCE_SIZE, (unsigned char*)(hmac.block));
    
    if(memcmp(hmac.block, report->mac.block, sizeof(report->mac.block)) == 0){
        logcat("attestation report MAC verify success\n");
        return 0;
    } else {
        logcat("attestation report MAC verify failed\n");
        return -1;
    }
}

int get_attestation_report_ioctl(struct csv_attestation_report *report,
                                 unsigned char* nonce, unsigned int nonce_len)
{
    struct csv_attestation_user_data *user_data;
    int user_data_len = PAGE_SIZE;
    long ret;
    int fd = 0;
    struct csv_guest_mem mem = {0};
    
    if (!report || !nonce) {
        logcat("NULL pointer for report\n");
        return -1;
    }

    if (nonce_len != GUEST_ATTESTATION_NONCE_SIZE) {
        logcat("invalid nonce length\n");
        return -1;
    }

    user_data = (struct csv_attestation_user_data *)malloc(user_data_len);
    if (user_data == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }
    memset((void *)user_data, 0x0, user_data_len);

    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    memcpy(user_data->mnonce, nonce, GUEST_ATTESTATION_NONCE_SIZE);
    memcpy(g_mnonce, nonce, GUEST_ATTESTATION_NONCE_SIZE);

    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);

    logcat("attestation request - \n");
    csv_data_dump("data", user_data->data, GUEST_ATTESTATION_DATA_SIZE);
    logcat("data in ascii ( %s )\n", user_data->data);
    csv_data_dump("mnonce", user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    csv_data_dump("hash", (unsigned char *)&user_data->hash, sizeof(hash_block_u));
    logcat("\n\n");
    
    fd = open("/dev/csv-guest", O_RDWR);
    if(fd < 0) {
        logcat("open /dev/csv-guest failed\n");
        free(user_data);
        return -1;
    }
    
    mem.va = (uint64_t)user_data;
    mem.size = user_data_len;
    
    ret = ioctl(fd, GET_ATTESTATION_REPORT, &mem);
    if(ret < 0) {
        logcat("ioctl GET_ATTESTATION_REPORT fail: %ld\n", ret);
        goto error;
    }
    
    memcpy(report, user_data, sizeof(*report));

    ret = 0;
error:
    close(fd);
    free(user_data);
    return ret;
}

// 字节序转换函数
void invert_endian(unsigned char* buf, int len)
{
    int i;
    for(i = 0; i < len/2; i++) {
        unsigned int tmp = buf[i];
        buf[i] = buf[len - i - 1];
        buf[len - i - 1] = tmp;
    }
}

// SM2 签名验证函数
int gmssl_sm2_verify(struct ecc_point_q Q, unsigned char *userid,
                     unsigned int userid_len, const unsigned char *msg, 
                     unsigned int msg_len, struct ecdsa_sign *sig_in)
{
    int ret;
    EC_KEY *eckey;
    unsigned char dgst[ECC_LEN];
    long unsigned int dgstlen;

    if (!msg || !userid || !sig_in) {
        logcat("gmssl_sm2_verify: invalid input parameter\n");
        return -1;
    }

    invert_endian(sig_in->r, ECC_LEN);
    invert_endian(sig_in->s, ECC_LEN);

    BIGNUM *bn_qx = BN_bin2bn(Q.Qx, 32, NULL);
    BIGNUM *bn_qy = BN_bin2bn(Q.Qy, 32, NULL);

    eckey = EC_KEY_new();
    EC_GROUP *group256 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_group(eckey, group256);
    EC_POINT *ecpt_pubkey = EC_POINT_new(group256);
    EC_POINT_set_affine_coordinates_GFp(group256, ecpt_pubkey, bn_qx, bn_qy, NULL);
    EC_KEY_set_public_key(eckey, ecpt_pubkey);

    if (eckey == NULL) {
        logcat("EC_KEY_new_by_curve_name failed\n");
        EC_POINT_free(ecpt_pubkey);
        EC_GROUP_free(group256);
        return -1;
    }

    dgstlen = sizeof(dgst);
    SM2_compute_message_digest(EVP_sm3(), EVP_sm3(), msg, msg_len, 
                               (const char *)userid, userid_len, dgst, &dgstlen, eckey);

    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM *sig_r = BN_new();
    BIGNUM *sig_s = BN_new();
    BN_bin2bn(sig_in->r, 32, sig_r);
    BN_bin2bn(sig_in->s, 32, sig_s);
    ECDSA_SIG_set0(s, sig_r, sig_s);

    ret = SM2_do_verify(dgst, dgstlen, s, eckey);

    EC_POINT_free(ecpt_pubkey);
    ECDSA_SIG_free(s);
    EC_GROUP_free(group256);
    EC_KEY_free(eckey);

    if (1 != ret) {
        logcat("SM2_do_verify failed, ret=%d\n", ret);
        return -1;
    }

    return 0;
}

// 通用证书验证函数
int csv_cert_verify(const char *data, uint32_t datalen, ecc_signature_t *signature, ecc_pubkey_t *pubkey)
{
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;

    Q.curve_id = pubkey->curve_id;
    memcpy(Q.Qx, pubkey->Qx, ECC_LEN);
    memcpy(Q.Qy, pubkey->Qy, ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, ((userid_u*)pubkey->user_id)->uid, 
                           ((userid_u*)pubkey->user_id)->len, 
                           (const unsigned char *)data, datalen, &sig_in);
}

// 验证 HRK 证书签名
int verify_hrk_cert_signature(CHIP_ROOT_CERT_t *hrk)
{
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;
    uint32_t need_copy_len = 0;
    uint8_t hrk_userid[256] = {0};
    userid_u* sm2_userid = (userid_u*)hrk_userid;

    ecc_pubkey_t *pubkey = &hrk->ecc_pubkey;
    ecc_signature_t *signature = &hrk->ecc_sig;

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx, pubkey->Qx, ECC_LEN);
    memcpy(Q.Qy, pubkey->Qy, ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len = ((userid_u*)pubkey->user_id)->len;
    need_copy_len = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, 
                           (const uint8_t *)hrk, 64 + 512, &sig_in);
}

// 验证 HSK 证书签名
int verify_hsk_cert_signature(CHIP_ROOT_CERT_t *hrk, CHIP_ROOT_CERT_t *hsk)
{
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;
    uint32_t need_copy_len = 0;
    uint8_t hrk_userid[256] = {0};
    userid_u* sm2_userid = (userid_u*)hrk_userid;

    ecc_pubkey_t *pubkey = (ecc_pubkey_t*)hrk->pubkey;
    ecc_signature_t *signature = &hsk->ecc_sig;

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx, pubkey->Qx, ECC_LEN);
    memcpy(Q.Qy, pubkey->Qy, ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len = ((userid_u*)pubkey->user_id)->len;
    need_copy_len = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, 
                           (const uint8_t *)hsk, 64 + 512, &sig_in);
}

// 验证 CEK 证书签名
int verify_cek_signature(CHIP_ROOT_CERT_t *hsk, CSV_CERT_t *cek)
{
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;
    uint32_t need_copy_len = 0;
    uint8_t hrk_userid[256] = {0};
    userid_u* sm2_userid = (userid_u*)hrk_userid;

    ecc_pubkey_t *pubkey = (ecc_pubkey_t*)hsk->pubkey;
    ecc_signature_t *signature;

    if(KEY_USAGE_TYPE_INVALID == cek->sig1_usage) {
        signature = &cek->ecc_sig2;
    } else {
        signature = &cek->ecc_sig1;
    }

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx, pubkey->Qx, ECC_LEN);
    memcpy(Q.Qy, pubkey->Qy, ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len = ((userid_u*)pubkey->user_id)->len;
    need_copy_len = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, 
                           (const uint8_t *)cek, 16 + 1028, &sig_in);
}

// 验证 PEK 证书签名
int verify_pek_cert_with_cek_signature(CSV_CERT_t *cek, CSV_CERT_t *pek)
{
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;
    uint32_t need_copy_len = 0;
    uint8_t userid[256] = {0};
    userid_u* sm2_userid = (userid_u*)userid;

    ecc_pubkey_t *pubkey = &cek->ecc_pubkey;
    ecc_signature_t *signature = &pek->ecc_sig1;

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx, pubkey->Qx, ECC_LEN);
    memcpy(Q.Qy, pubkey->Qy, ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len = ((userid_u*)pubkey->user_id)->len;
    need_copy_len = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, 
                           (const uint8_t *)pek, 16 + 1028, &sig_in);
}

// 验证证明报告签名
int csv_attestation_report_verify(struct csv_attestation_report *report)
{
    CSV_CERT_t *pek_cert;
    int ret = 0;

    logcat("verify: do verify\n");
    pek_cert = &g_pek_cert;
    ret = csv_cert_verify((const char *)report, ATTESTATION_REPORT_SIGNED_SIZE, 
                         &report->ecc_sig1, &pek_cert->ecc_pubkey);
    logcat("verify %s\n", ret ? "fail" : "success");

    return ret;
}

// 文件读取函数
int load_data_from_file(const char *path, void *buff, size_t len)
{
    if (!path || !*path) {
        logcat("no file\n");
        return -ENOENT;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        logcat("open file %s fail %s\n", path, strerror(errno));
        return fd;
    }

    int rlen = 0, n;
    while (rlen < len) {
        n = read(fd, buff + rlen, len);
        if (n == -1) {
            logcat("read file error\n");
            close(fd);
            return n;
        }
        if (!n) {
            break;
        }
        rlen += n;
    }

    close(fd);
    return 0;
}

// 检查离线证书文件
static int check_offline_cert(char *filename)
{
    char path[PATH_MAX] = {0};
    char *dir = NULL;
    FILE *pfile = NULL;

    if (filename == NULL)
        return -1;

    if (readlink("/proc/self/exe", path, sizeof(path)-1) == -1) {
        logcat("fail to find file %s\n", filename);
        return -1;
    }

    dir = dirname(path);
    if (strlen(dir) + strlen(filename) + 2 > PATH_MAX) {
        return -1;
    }
    strcat(path, "/");
    strcat(path, filename);

    pfile = fopen(path, "r");
    if (pfile == NULL) {
        return -1;
    }
    if (fseek(pfile, 0, SEEK_END) != 0 || ftell(pfile) == 0) {
        fclose(pfile);
        return -1;
    }

    fclose(pfile);
    return 0;
}

// 获取 HRK 证书
int get_hrk_cert(char *cert_file)
{
    int cmd_ret = -1;
    char command_buff[256];

    sprintf(command_buff, "curl -s -f -o %s "HRK_CERT_SITE, cert_file);
    logcat("%s", command_buff);
    logcat("\n");
    cmd_ret = system(command_buff);
    if (cmd_ret != 0) {
        cmd_ret = check_offline_cert(basename(cert_file));
    }

    return (int)cmd_ret;
}

// 加载 HRK 文件
int load_hrk_file(char *filename, void *buff, size_t len)
{
    int ret;

    ret = get_hrk_cert(filename);
    if(ret != 0) {
        logcat("Error: Download hrk failed\n");
        return ret;
    }
    logcat("Get hrk file successful\n\n");
    ret = load_data_from_file(filename, buff, len);
    return ret;
}

// 获取 HSK 和 CEK 证书
int get_hsk_cek_cert(char *cert_file, char *chip_id)
{
    int cmd_ret = -1;
    char command_buff[256];

    sprintf(command_buff, "curl -s -f -o %s "KDS_CERT_SITE"%s", cert_file, chip_id);
    logcat("%s", command_buff);
    logcat("\n");
    cmd_ret = system(command_buff);
    if (cmd_ret != 0) {
        cmd_ret = check_offline_cert(basename(cert_file));
    }

    return (int)cmd_ret;
}

// 加载 HSK 和 CEK 文件
int load_hsk_cek_file(char *chip_id, void *hsk, size_t hsk_len, void *cek, size_t cek_len)
{
    int ret;
    struct {
        CHIP_ROOT_CERT_t hsk;
        CSV_CERT_t cek;
    } __attribute__((aligned(1))) HCK_file;

    ret = get_hsk_cek_cert(HSK_CEK_FILENAME, chip_id);
    if(ret != 0) {
        logcat("Error: Download hsk-cek failed\n");
        return ret;
    }
    logcat("Get hsk-cek file successful\n\n");

    ret = load_data_from_file(HSK_CEK_FILENAME, &HCK_file, sizeof(HCK_file));
    if(ret) {
        logcat("Error: load HSK CEK file failed\n");
        return ret;
    }

    memcpy(hsk, &HCK_file.hsk, hsk_len);
    memcpy(cek, &HCK_file.cek, cek_len);
    return 0;
}

// 完整的证书链验证
int validate_cert_chain(struct csv_attestation_report *report)
{
    CSV_CERT_t cek;
    CHIP_ROOT_CERT_t hsk;
    CHIP_ROOT_CERT_t hrk;
    CSV_CERT_t oca;
    int success = 0;
    int ret;

    // 证书加载与有效性预检查
    do {
        ret = load_hrk_file(HRK_FILENAME, &hrk, sizeof(CHIP_ROOT_CERT_t));
        if(ret) {
            logcat("hrk.cert doesn't exist or size isn't correct\n");
            break;
        }
        if(hrk.key_usage != KEY_USAGE_TYPE_HRK) {
            logcat("hrk.cert key_usage field isn't correct\n");
            break;
        }

        ret = load_hsk_cek_file((char *)g_chip_id, &hsk, sizeof(CHIP_ROOT_CERT_t), &cek, sizeof(CSV_CERT_t));
        if(ret) {
            logcat("Error: load hsk-cek cert failed\n");
            break;
        }

        if (external_oca_file) {
            if (load_data_from_file(external_oca_file, &oca, sizeof(oca))) {
                logcat("Error: load oca cert failed\n");
                break;
            }
        }

        if (hsk.key_usage != KEY_USAGE_TYPE_HSK) {
            logcat("hsk.cert key_usage field isn't correct\n");
            break;
        }

        if (cek.pubkey_usage != KEY_USAGE_TYPE_CEK) {
            logcat("cek.cert pub_key_usage field doesn't correct\n");
            break;
        }

        if (cek.sig1_usage != KEY_USAGE_TYPE_HSK) {
            logcat("cek.cert sig_1_usage field isn't correct\n");
            break;
        }

        if (cek.sig2_usage != KEY_USAGE_TYPE_INVALID) {
            logcat("cek.cert sig_2_usage field isn't correct\n");
            break;
        }

        if (external_oca_file && oca.pubkey_usage != KEY_USAGE_TYPE_OCA) {
            logcat("oca cert pub_key_usage field doesn't correct\n");
            break;
        }

        success = 1;
    } while(0);

    if(!success) {
        logcat("Error: load error cert file\n");
        return -1;
    }

    success = 0;
    // 密码学签名验证
    do {
        ret = verify_hrk_cert_signature(&hrk);
        if(ret) {
            logcat("hrk pubkey verify hrk cert failed\n");
            break;
        }
        logcat("hrk pubkey verify hrk cert successful\n");

        ret = verify_hsk_cert_signature(&hrk, &hsk);
        if(ret) {
            logcat("hrk pubkey verify hsk cert failed\n");
            break;
        }
        logcat("hrk pubkey verify hsk cert successful\n");

        ret = verify_cek_signature(&hsk, &cek);
        if(ret) {
            logcat("hsk pubkey verify cek cert failed\n");
            break;
        }
        logcat("hsk pubkey verify cek cert successful\n");

        ret = verify_pek_cert_with_cek_signature(&cek, &g_pek_cert);
        if(ret) {
            logcat("cek pubkey and verify pek cert failed\n");
            break;
        }
        logcat("cek pubkey verify pek cert successful\n");

        if (external_oca_file) {
            // OCA 验证逻辑可以在这里添加
            logcat("OCA verification not implemented yet\n");
        }

        success = 1;
    } while(0);

    if(success) {
        logcat("validate cert chain successful\n\n");
        return 0;
    }

    return -1;
}

// 完整的验证函数
int csv_verify_attestation_report(unsigned char* report_buf, unsigned int buf_len, int verify_chain)
{
    struct csv_attestation_report report;
    int ret = 0;
    int i = 0;
    int j = 0;
    
    if (buf_len < sizeof(report)){
        logcat("The allocated length is too short to meet the generated report!\n");
        logcat("The length should not be less than %ld \n", sizeof(report));
        return -1;
    }

    if (report_buf == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    logcat("verify attestation report\n");
    memcpy(&report, report_buf, sizeof(report));

    // 解密报告核心数据
    j = sizeof(report.user_data) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)g_user_data)[i] = ((uint32_t *)report.user_data)[i] ^ report.anonce;

    j = sizeof(report.mnonce) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
         ((uint32_t *)g_mnonce)[i] = ((uint32_t *)report.mnonce)[i] ^ report.anonce;

    j = sizeof(report.measure) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)g_measure)[i] = ((uint32_t *)report.measure.block)[i] ^ report.anonce;

    j = ((uint8_t *)report.sn - (uint8_t *)&report.pek_cert) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)&g_pek_cert)[i] = ((uint32_t *)&report.pek_cert)[i] ^ report.anonce;

    j = ((uint8_t *)&report.reserved2 - (uint8_t *)report.sn) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)g_chip_id)[i] = ((uint32_t *)report.sn)[i] ^ report.anonce;

    // 基础验证
    ret = verify_session_mac(&report);
    if (ret) {
        logcat("MAC verification failed\n");
        return ret;
    }

    // 完整的证书链验证
    if (verify_chain) {
        logcat("\nValidate cert chain:\n");
        ret = validate_cert_chain(&report);
        if (ret) {
            logcat("validate cert chain failed\n\n");
            return -1;
        }
    }

    // 最终报告签名验证
    logcat("verify report\n");
    ret = csv_attestation_report_verify(&report);

    return ret;
}

// 主要的 API 函数
int csv_get_attestation_report_ioctl(unsigned char* report_buf, unsigned int buf_len,
                                   unsigned char* nonce, unsigned int nonce_len)
{
    int ret;
    struct csv_attestation_report report;

    if (buf_len < sizeof(report)){
        logcat("The allocated length is too short to meet the generated report!\n");
        logcat("The length should not be less than %ld \n", sizeof(report));
        return -1;
    }

    if (report_buf == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    if (nonce == NULL) {
        logcat("invalid nonce \n");
        return -1;
    }

    if (nonce_len != GUEST_ATTESTATION_NONCE_SIZE) {
        logcat("invalid nonce length\n");
        return -1;
    }

    logcat("Requesting attestation report ... \n");

    ret = get_attestation_report_ioctl(&report, nonce, nonce_len);
    if (ret) {
        logcat("get attestation report fail\n");
        return -1;
    }

    logcat("Received attestation report \n");
    ret = verify_session_mac(&report);
    if (ret) {
        logcat("PEK cert and ChipId have been tampered with\n");
        return ret;
    } else {
        logcat("check PEK cert and ChipId successfully\n");
    }

    memset(report.reserved2, 0, sizeof(report.reserved2));
    memcpy(report_buf, &report, sizeof(report));

    return 0;
}