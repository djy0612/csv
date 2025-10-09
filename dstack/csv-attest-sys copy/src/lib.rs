// 包含生成的绑定
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// 重新导出关键类型和函数
pub use crate::{
    csv_attestation_report as CsvAttestationReport,
    csv_attestation_user_data as CsvAttestationUserData,
    csv_guest_mem as CsvGuestMem,
    hash_block_u as HashBlockU,
    hash_block_t as HashBlock,
    chip_key_id_t as ChipKeyId,
    userid_u as UserIdU,
    ecc_pubkey_t as EccPubkey,
    ecc_signature_t as EccSignature,
    _hygon_root_cert as HygonRootCert,
    _hygon_csv_cert as HygonCsvCert,
    chip_root_cert_t as ChipRootCert,
    csv_cert_t as CsvCert,
};

// 函数现在从 bindgen 生成的绑定中直接可用
// 无需手动重新导出

// 常量定义 - 现在从 bindgen 生成的绑定中获取
// 这些常量在 bindings.rs 中定义，无需重复定义

// 辅助函数
pub fn get_error_string(error_code: i32) -> &'static str {
    match error_code {
        0 => "Success", // CSV_SUCCESS is u32 = 0, so we match 0 directly
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
        assert_eq!(get_error_string(0), "Success"); // CSV_SUCCESS is u32 = 0
        assert_eq!(get_error_string(CSV_ERROR_INVALID_PARAM), "Invalid parameter");
        assert_eq!(get_error_string(CSV_ERROR_MEMORY_ALLOC), "Memory allocation failed");
    }
}