// 包含生成的绑定
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// 重新导出关键类型和函数
pub use crate::{
    csv_attestation_report_t as CsvAttestationReport,
    csv_attestation_user_data_t as CsvAttestationUserData,
    csv_guest_mem_t as CsvGuestMem,
    hash_block_u as HashBlockU,
    hash_block_t as HashBlock,
    chip_key_id_t as ChipKeyId,
    userid_u as UserIdU,
    ecc_pubkey_t as EccPubkey,
    ecc_signature_t as EccSignature,
    hygon_root_cert_t as HygonRootCert,
    hygon_csv_cert_t as HygonCsvCert,
    chip_root_cert_t as ChipRootCert,
    csv_cert_t as CsvCert,
};

// 重新导出函数
pub use crate::{
    csv_get_attestation_report_ioctl,
    csv_verify_attestation_report,
    csv_gen_random_bytes,
    csv_get_attestation_report,
    csv_verify_session_mac,
    csv_get_status,
    csv_save_pubkey_to_pem_file,
    // 证书链验证相关函数
    validate_cert_chain,
    verify_hrk_cert_signature,
    verify_hsk_cert_signature,
    verify_cek_signature,
    verify_pek_cert_with_cek_signature,
    csv_attestation_report_verify,
    csv_cert_verify,
    // 证书加载相关函数
    load_hrk_file,
    load_hsk_cek_file,
    load_data_from_file,
    get_hrk_cert,
    get_hsk_cek_cert,
    // 辅助函数
    invert_endian,
    gmssl_sm2_verify,
};

// 常量定义
pub const GUEST_ATTESTATION_NONCE_SIZE: usize = 16;
pub const GUEST_ATTESTATION_DATA_SIZE: usize = 64;
pub const HASH_LEN: usize = 32;
pub const USER_DATA_SIZE: usize = 64;
pub const HASH_BLOCK_LEN: usize = 32;
pub const SN_LEN: usize = 64;
pub const VM_ID_SIZE: usize = 16;
pub const VM_VERSION_SIZE: usize = 16;
pub const ECC_LEN: usize = 32;
pub const ECC_POINT_SIZE: usize = 72;
pub const SIZE_INT32: usize = 4;
pub const ATTESTATION_REPORT_SIGNED_SIZE: usize = 180;

// 错误码定义
pub const CSV_SUCCESS: i32 = 0;
pub const CSV_ERROR_INVALID_PARAM: i32 = -1;
pub const CSV_ERROR_MEMORY_ALLOC: i32 = -2;
pub const CSV_ERROR_IOCTL_FAILED: i32 = -3;
pub const CSV_ERROR_HYPERCALL_FAILED: i32 = -4;
pub const CSV_ERROR_VERIFICATION_FAILED: i32 = -5;
pub const CSV_ERROR_CERT_CHAIN_FAILED: i32 = -6;

// 密钥用途常量
pub const KEY_USAGE_TYPE_HRK: u32 = 0;
pub const KEY_USAGE_TYPE_HSK: u32 = 0x13;
pub const KEY_USAGE_TYPE_OCA: u32 = 0x1001;
pub const KEY_USAGE_TYPE_PEK: u32 = 0x1002;
pub const KEY_USAGE_TYPE_CEK: u32 = 0x1004;
pub const KEY_USAGE_TYPE_INVALID: u32 = 0x1000;

// 曲线类型常量
pub const CURVE_ID_TYPE_P256: u32 = 0x1;
pub const CURVE_ID_TYPE_P384: u32 = 0x2;
pub const CURVE_ID_TYPE_SM2_256: u32 = 0x3;

// 辅助函数
pub fn get_error_string(error_code: i32) -> &'static str {
    match error_code {
        CSV_SUCCESS => "Success",
        CSV_ERROR_INVALID_PARAM => "Invalid parameter",
        CSV_ERROR_MEMORY_ALLOC => "Memory allocation failed",
        CSV_ERROR_IOCTL_FAILED => "IOCTL operation failed",
        CSV_ERROR_HYPERCALL_FAILED => "Hypercall failed",
        CSV_ERROR_VERIFICATION_FAILED => "Verification failed",
        CSV_ERROR_CERT_CHAIN_FAILED => "Certificate chain verification failed",
        _ => "Unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_attestation_report_size() {
        assert_eq!(std::mem::size_of::<CsvAttestationReport>(), 1800);
    }

    #[test]
    fn test_csv_attestation_user_data_size() {
        assert_eq!(std::mem::size_of::<CsvAttestationUserData>(), 112);
    }

    #[test]
    fn test_constants() {
        assert_eq!(GUEST_ATTESTATION_NONCE_SIZE, 16);
        assert_eq!(GUEST_ATTESTATION_DATA_SIZE, 64);
        assert_eq!(HASH_LEN, 32);
        assert_eq!(USER_DATA_SIZE, 64);
        assert_eq!(SN_LEN, 64);
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(get_error_string(CSV_SUCCESS), "Success");
        assert_eq!(get_error_string(CSV_ERROR_INVALID_PARAM), "Invalid parameter");
        assert_eq!(get_error_string(CSV_ERROR_MEMORY_ALLOC), "Memory allocation failed");
    }
}