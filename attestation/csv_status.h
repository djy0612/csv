#ifndef __CSV_STATUS_H__
#define __CSV_STATUS_H__

#include <stdint.h>
#include <linux/ioctl.h>

#define HRK_FILENAME "./hrk.cert"
#define HSK_FILENAME "./hsk.cert"
#define CEK_FILENAME "./cek.cert"
#define HSK_CEK_FILENAME "hsk_cek.cert"
// Hygon根证书(HRK)的固定下载地址
#define HRK_CERT_SITE "https://cert.hygon.cn/hrk"
// 密钥分发服务(KDS)的地址,提供芯片的序列号获取HSK和CEK证书
#define KDS_CERT_SITE "https://cert.hygon.cn/hsk_cek?snumber="


#define ATTESTATION_REPORT_FILE "./report.cert"
#define ATTESTATION_NONCE_FILE "./nonce.bin"
// 定义了各种数据字段的精确字节长度
#define HASH_LEN                      32
#define CERT_ECC_MAX_SIG_SIZE        72
#define GUEST_ATTESTATION_NONCE_SIZE 16
#define GUEST_ATTESTATION_DATA_SIZE  64
#define VM_ID_SIZE                   16
#define VM_VERSION_SIZE              16
#define SN_LEN                       64
#define USER_DATA_SIZE               64
#define HASH_BLOCK_LEN               32
// 条件日志宏,如果在编译时定义了 LOG_ON 宏（例如，通过编译命令 gcc -DLOG_ON ...），那么代码中所有的 logcat(...) 都会被替换成 printf(...)，从而打印出详细的日志。
#ifdef LOG_ON
    #define logcat printf
#else
    #define logcat(format, ...)
#endif
// 声明了该证书中的公钥应该被用于什么目的
typedef enum _key_usage {
    KEY_USAGE_TYPE_HRK     = 0,
    KEY_USAGE_TYPE_HSK     = 0x13,
    KEY_USAGE_TYPE_INVALID = 0x1000,
    KEY_USAGE_TYPE_MIN     = 0x1001,
    KEY_USAGE_TYPE_OCA     = 0x1001,
    KEY_USAGE_TYPE_PEK     = 0x1002,
    KEY_USAGE_TYPE_PDH     = 0x1003,
    KEY_USAGE_TYPE_CEK     = 0x1004,
    KEY_USAGE_TYPE_MAX     = 0x1004,
} key_usage_t;

typedef struct _hash_block_u {
    unsigned char block[HASH_LEN];
} hash_block_u;

/**
 * struct csv_issue_cmd - CSV ioctl parameters
 *
 * @cmd: CSV commands to execute
 * @opaque: pointer to the command structure
 * @error: CSV FW return code on failure
 */
struct csv_issue_cmd {
    uint32_t cmd;					/* In */
    uint64_t data;					/* In */
    uint32_t error;					/* Out */
}  __attribute__((packed));

#define CSV_IOC_TYPE		'S'
#define CSV_ISSUE_CMD	_IOWR(CSV_IOC_TYPE, 0x0, struct csv_issue_cmd)

// 定义了csv_issue_cmd.cmd字段可以使用的具体命令值
enum {
    CSV_USER_CMD_FACTORY_RESET = 0,
    CSV_USER_CMD_PDH_CERT_EXPORT = 5,
    CSV_USER_CMD_GET_ID = 7,
    CSV_USER_CMD_GET_ID2 = 8,
    CSV_USER_CMD_ATTESTATION = 38,
    CSV_USER_CMD_MAX,
};

/* verify */
#define  CERT_ECC_MAX_KEY_SIZE          72
#define  CERT_ECC_MAX_SIG_SIZE          72
#define  CERT_ECC_KEY_RESERVED_SIZE     880
#define  CERT_SM2_KEY_RESERVED_SIZE     624
#define  CERT_SM2_ROOT_KEY_RESERVED_SIZE     620
#define  CERT_ECC_SIG_RESERVED_SIZE     368
// 定义了椭圆曲线的类型ID
typedef enum _curve_id {
    CURVE_ID_TYPE_INVALID = 0,
    CURVE_ID_TYPE_MIN     = 0X1,
    CURVE_ID_TYPE_P256    = 0x1,
    CURVE_ID_TYPE_P384    = 0x2,
    CURVE_ID_TYPE_SM2_256 = 0x3,
    CURVE_ID_TYPE_MAX     = 0X3
} curve_id_t;

#define CSV_CERT_RSVD3_SIZE      624
#define CSV_CERT_RSVD4_SIZE      368
#define CSV_CERT_RSVD5_SIZE      368
#define HYGON_USER_ID_SIZE       256
#define SIZE_INT32               4
#define SIZE_24                  24
#define SIZE_108                 108
#define SIZE_112                 112
#define ECC_POINT_SIZE           72
#define CHIP_KEY_ID_LEN          16
#define SM2_UID_SIZE_U           256
#define ECC_LEN                  32  // p-256
#define ECC_KEY_BITS             256

#define ATTESTATION_REPORT_SIGNED_SIZE 180
// 定义了向Hypervisor发起证明请求的vmmcall（或hypercall）的功能号
#define KVM_HC_VM_ATTESTATION	       100	/* Specific to Hygon platform */
// 封装SM2算法所需的userid，包含长度和数据
typedef struct _userid_u {
    unsigned short   len;
    unsigned char    uid[SM2_UID_SIZE_U - sizeof(unsigned short)];
} __attribute__ ((packed)) userid_u;


/**
 * hash block data structure
 * used to store the hash result value
 */
typedef struct _hash_block {
    uint8_t block[HASH_BLOCK_LEN];
} __attribute__ ((packed)) hash_block_t;
//  16字节的芯片/密钥唯一标识符
typedef struct _chip_key_id {
    uint8_t id[CHIP_KEY_ID_LEN];
} __attribute__ ((packed)) chip_key_id_t;

typedef struct _ecc_pubkey {
    uint32_t curve_id;
    uint32_t Qx[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t Qy[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t user_id[HYGON_USER_ID_SIZE / SIZE_INT32];
} __attribute__ ((packed)) ecc_pubkey_t;

typedef struct _ecc_signature {
    uint32_t sig_r[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t sig_s[ECC_POINT_SIZE / SIZE_INT32];
} __attribute__ ((packed)) ecc_signature_t;

// 定义 HRK 证书的格式
struct _hygon_root_cert {
    uint32_t      version;
    chip_key_id_t key_id;
    chip_key_id_t certifying_id;
    uint32_t      key_usage;
    uint32_t      reserved1[SIZE_24 / SIZE_INT32];
    union {
        uint32_t     pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + HYGON_USER_ID_SIZE) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved2[SIZE_108 / SIZE_INT32];
    union {
        uint32_t        signature[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig;
    };
    uint32_t reserved3[SIZE_112 / SIZE_INT32];
} __attribute__((packed));

// 定义通用的证书格式
struct _hygon_csv_cert {
    uint32_t version;
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  reserved1;
    uint8_t  reserved2;
    uint32_t pubkey_usage;
    uint32_t pubkey_algo;
    union {
        uint32_t     pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + HYGON_USER_ID_SIZE) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved3[CSV_CERT_RSVD3_SIZE / SIZE_INT32];
    uint32_t sig1_usage;
    uint32_t sig1_algo;
    union {
        uint32_t        sig1[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig1;
    };
    uint32_t reserved4[CSV_CERT_RSVD4_SIZE / SIZE_INT32];
    uint32_t sig2_usage;
    uint32_t sig2_algo;
    union {
        uint32_t        sig2[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig2;
    };
    uint32_t reserved5[CSV_CERT_RSVD5_SIZE / SIZE_INT32];
} __attribute__((packed));

typedef struct _hygon_root_cert CHIP_ROOT_CERT_t;
typedef struct _hygon_csv_cert  CSV_CERT_t;

typedef struct _csv_cert_chain {
    CSV_CERT_t pek_cert;
    CSV_CERT_t oca_cert;
    CSV_CERT_t cek_cert;
} CSV_CERT_CHAIN_t;

// 证明报告结构
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
    CSV_CERT_t  pek_cert;                 // PEK证书（平台加密密钥证书）
    uint8_t     sn[SN_LEN];               // 序列号
    uint8_t     reserved2[32];            // 保留字段
    hash_block_u mac;                     // MAC 校验值
};

/**
 * struct csv_user_data_pdh_cert_export - PDH_CERT_EXPORT command parameters
 *
 * @pdh_address: PDH certificate address
 * @pdh_length: length of PDH certificate
 * @cert_chain_address: PDH certificate chain
 * @cert_chain_length: length of PDH certificate chain
 */
//  这个结构体定义了通过ioctl命令 PDH_CERT_EXPORT 导出“PDH证书”时所需的参数
struct csv_user_data_pdh_cert_export {
    uint64_t pdh_cert_address;				/* In */
    uint32_t pdh_cert_length;				/* In/Out */
    uint64_t cert_chain_address;			/* In */
    uint32_t cert_chain_length;			    /* In/Out */
}  __attribute__((packed));


struct ecc_point_q {
    curve_id_t     curve_id;
    unsigned char    Qx[ECC_LEN];
    unsigned char    Qy[ECC_LEN];
};

struct ecdsa_sign {
    unsigned char    r[ECC_LEN];
    unsigned char    s[ECC_LEN];
};

/**
 * virtual machine status command buffer.
 *
 * @vm_type                - virtual machine type: 0=nocsv; 1=csv
 * @verify_chain           - verify certificate chain: 0=no; 1=yes
 * @reserved               - reserved. Set to zero.
 */
// 这是csv_get_status函数的最终输出，用一种高度压缩和简洁的方式报告虚拟机的可信状态
typedef struct vm_status_t {
    uint32_t vm_type: 1,
        verify_chain: 1,
        reserved: 30;
} vm_status;

/**
 * @brief  get random in csv virtual machine
 *
 * @param  [in]  len: the length of random data stored
 * @param  [out] buf: information of random number with a length of len
 *
 * @returns success: 0, failure: -1 and so on
*/
int TCM_GetRandom(uint8_t *buf, uint32_t len);

/**
 * @brief  get virtual machine status
 *
 * @param  [out] status: information of virtual machine status
 *
 * @returns success: 0, failure: -1 and so on
*/
int csv_get_status(uint32_t *status);

/*make the files in the csv_sdk dir reuse the functions in csv_status.c*/
extern uint8_t g_mnonce[GUEST_ATTESTATION_NONCE_SIZE];
extern uint8_t r_mnonce[GUEST_ATTESTATION_NONCE_SIZE];
extern char *external_oca_file;
// 定义了在发起证明请求时，需要准备并传递给Hypervisor的输入数据包的格式
struct csv_attestation_user_data {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
};
struct csv_guest_mem{
    unsigned long va;
    int size;
};

int vmmcall_get_attestation_report(unsigned char* report_buf, unsigned int buf_len);
int verify_session_mac(struct csv_attestation_report *report);
void csv_data_dump(const char* name, uint8_t *data, uint32_t len);
int get_attestation_report_ioctl(struct csv_attestation_report *report, unsigned char* nonce, unsigned int nonce_len);
void gen_random_bytes(void *buf, uint32_t len);
int get_attestation_report(struct csv_attestation_report *report);
int  save_csv_pubkey_to_pem_file(ecc_pubkey_t *pubkey, char *pemfile);

#endif /* __CSV_STATUS_H__ */
