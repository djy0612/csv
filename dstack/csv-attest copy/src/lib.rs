use csv_attest_sys::*;
use std::ffi::{CString, CStr};
use std::ptr;
use std::slice;

/// CSV 证明报告错误类型
#[derive(Debug, thiserror::Error)]
pub enum CsvAttestationError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Memory allocation failed")]
    MemoryAllocation,
    
    #[error("IOCTL operation failed: {0}")]
    IoctlFailed(i32),
    
    #[error("Hypercall failed: {0}")]
    HypercallFailed(i32),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Certificate chain verification failed: {0}")]
    CertChainFailed(String),
    
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    
    #[error("Unknown error: {0}")]
    Unknown(i32),
}

impl From<i32> for CsvAttestationError {
    fn from(error_code: i32) -> Self {
        match error_code {
            0 => unreachable!(), // CSV_SUCCESS
            CSV_ERROR_INVALID_PARAM => CsvAttestationError::InvalidParameter("Invalid parameter".to_string()),
            CSV_ERROR_MEMORY_ALLOC => CsvAttestationError::MemoryAllocation,
            CSV_ERROR_IOCTL_FAILED => CsvAttestationError::IoctlFailed(error_code),
            CSV_ERROR_HYPERCALL_FAILED => CsvAttestationError::HypercallFailed(error_code),
            CSV_ERROR_VERIFICATION_FAILED => CsvAttestationError::VerificationFailed("Verification failed".to_string()),
            CSV_ERROR_CERT_CHAIN_FAILED => CsvAttestationError::CertChainFailed("Certificate chain verification failed".to_string()),
            _ => CsvAttestationError::Unknown(error_code),
        }
    }
}

/// CSV 证明报告结果
pub type CsvAttestationResult<T> = Result<T, CsvAttestationError>;

/// CSV 证明报告结构体
#[derive(Debug, Clone)]
pub struct CsvAttestationReport {
    pub user_pubkey_digest: [u8; 32],
    pub vm_id: [u8; 16],
    pub vm_version: [u8; 16],
    pub user_data: [u8; 64],
    pub mnonce: [u8; 16],
    pub measure: [u8; 32],
    pub policy: u32,
    pub sig_usage: u32,
    pub sig_algo: u32,
    pub anonce: u32,
    pub sig1: [u32; 36],
    pub pek_cert: Vec<u8>, // PEK 证书数据
    pub sn: [u8; 64],
    pub mac: [u8; 32],
}

impl CsvAttestationReport {
    /// 从原始字节数据创建证明报告
    pub fn from_bytes(data: &[u8]) -> CsvAttestationResult<Self> {
        if data.len() < std::mem::size_of::<CsvAttestationReport>() {
            return Err(CsvAttestationError::InvalidParameter(
                format!("Data too short: {} bytes", data.len())
            ));
        }

        let raw_report = unsafe {
            ptr::read(data.as_ptr() as *const CsvAttestationReport)
        };

        Ok(Self {
            user_pubkey_digest: raw_report.user_pubkey_digest.block,
            vm_id: raw_report.vm_id,
            vm_version: raw_report.vm_version,
            user_data: raw_report.user_data,
            mnonce: raw_report.mnonce,
            measure: raw_report.measure.block,
            policy: raw_report.policy,
            sig_usage: raw_report.sig_usage,
            sig_algo: raw_report.sig_algo,
            anonce: raw_report.anonce,
            sig1: raw_report.sig1,
            pek_cert: raw_report.pek_cert.to_vec(),
            sn: raw_report.sn,
            mac: raw_report.mac.block,
        })
    }

    /// 获取用户数据（解密后）
    pub fn get_user_data(&self) -> Vec<u8> {
        let mut decrypted = vec![0u8; 64];
        for i in 0..16 {
            let val = u32::from_le_bytes([
                self.user_data[i * 4],
                self.user_data[i * 4 + 1],
                self.user_data[i * 4 + 2],
                self.user_data[i * 4 + 3],
            ]);
            let decrypted_val = val ^ self.anonce;
            let bytes = decrypted_val.to_le_bytes();
            decrypted[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        decrypted
    }

    /// 获取随机数（解密后）
    pub fn get_mnonce(&self) -> Vec<u8> {
        let mut decrypted = vec![0u8; 16];
        for i in 0..4 {
            let val = u32::from_le_bytes([
                self.mnonce[i * 4],
                self.mnonce[i * 4 + 1],
                self.mnonce[i * 4 + 2],
                self.mnonce[i * 4 + 3],
            ]);
            let decrypted_val = val ^ self.anonce;
            let bytes = decrypted_val.to_le_bytes();
            decrypted[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        decrypted
    }

    /// 获取度量值（解密后）
    pub fn get_measure(&self) -> Vec<u8> {
        let mut decrypted = vec![0u8; 32];
        for i in 0..8 {
            let val = u32::from_le_bytes([
                self.measure[i * 4],
                self.measure[i * 4 + 1],
                self.measure[i * 4 + 2],
                self.measure[i * 4 + 3],
            ]);
            let decrypted_val = val ^ self.anonce;
            let bytes = decrypted_val.to_le_bytes();
            decrypted[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        decrypted
    }

    /// 获取芯片序列号（解密后）
    pub fn get_chip_id(&self) -> Vec<u8> {
        let mut decrypted = vec![0u8; 64];
        for i in 0..16 {
            let val = u32::from_le_bytes([
                self.sn[i * 4],
                self.sn[i * 4 + 1],
                self.sn[i * 4 + 2],
                self.sn[i * 4 + 3],
            ]);
            let decrypted_val = val ^ self.anonce;
            let bytes = decrypted_val.to_le_bytes();
            decrypted[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        decrypted
    }
}

/// CSV 证明客户端
pub struct CsvAttestationClient {
    nonce: [u8; GUEST_ATTESTATION_NONCE_SIZE],
}

impl CsvAttestationClient {
    /// 创建新的 CSV 证明客户端
    pub fn new() -> Self {
        Self {
            nonce: [0u8; GUEST_ATTESTATION_NONCE_SIZE],
        }
    }

    /// 生成随机数
    pub fn generate_nonce(&mut self) -> CsvAttestationResult<()> {
        unsafe {
            csv_gen_random_bytes(self.nonce.as_mut_ptr(), GUEST_ATTESTATION_NONCE_SIZE as u32);
        }
        Ok(())
    }

    /// 设置自定义随机数
    pub fn set_nonce(&mut self, nonce: &[u8]) -> CsvAttestationResult<()> {
        if nonce.len() != GUEST_ATTESTATION_NONCE_SIZE {
            return Err(CsvAttestationError::InvalidParameter(
                format!("Invalid nonce length: {} bytes", nonce.len())
            ));
        }
        self.nonce.copy_from_slice(nonce);
        Ok(())
    }

    /// 获取证明报告（通过 ioctl）
    pub fn get_attestation_report_ioctl(&self) -> CsvAttestationResult<CsvAttestationReport> {
        let mut report_buf = vec![0u8; std::mem::size_of::<CsvAttestationReport>()];
        
        let ret = unsafe {
            csv_get_attestation_report_ioctl(
                report_buf.as_mut_ptr(),
                report_buf.len() as u32,
                self.nonce.as_ptr(),
                GUEST_ATTESTATION_NONCE_SIZE as u32,
            )
        };

        if ret == 0 {
            CsvAttestationReport::from_bytes(&report_buf)
        } else {
            Err(ret.into())
        }
    }

    /// 获取证明报告（通过 vmmcall）
    pub fn get_attestation_report_vmmcall(&self) -> CsvAttestationResult<CsvAttestationReport> {
        let mut report_buf = vec![0u8; std::mem::size_of::<CsvAttestationReport>()];
        
        let ret = unsafe {
            csv_get_attestation_report(
                report_buf.as_mut_ptr(),
                report_buf.len() as u32,
            )
        };

        if ret == 0 {
            CsvAttestationReport::from_bytes(&report_buf)
        } else {
            Err(ret.into())
        }
    }

    /// 验证证明报告（支持完整证书链验证）
    pub fn verify_attestation_report(&self, report: &CsvAttestationReport, verify_chain: bool) -> CsvAttestationResult<()> {
        let report_bytes = self.report_to_bytes(report)?;
        
        let ret = unsafe {
            csv_verify_attestation_report(
                report_bytes.as_ptr(),
                report_bytes.len() as u32,
                if verify_chain { 1 } else { 0 },
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(ret.into())
        }
    }

    /// 验证证书链（HRK → HSK → CEK → PEK）
    pub fn verify_certificate_chain(&self, report: &CsvAttestationReport) -> CsvAttestationResult<()> {
        let report_bytes = self.report_to_bytes(report)?;
        
        let ret = unsafe {
            validate_cert_chain(report_bytes.as_ptr() as *const csv_attest_sys::csv_attestation_report)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(CsvAttestationError::CertChainFailed(format!("Certificate chain verification failed: {}", ret)))
        }
    }

    /// 验证 HRK 证书
    pub fn verify_hrk_certificate(&self, hrk_cert: &csv_attest_sys::chip_root_cert_t) -> CsvAttestationResult<()> {
        let ret = unsafe {
            verify_hrk_cert_signature(hrk_cert as *const csv_attest_sys::chip_root_cert_t)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(CsvAttestationError::CertChainFailed(format!("HRK certificate verification failed: {}", ret)))
        }
    }

    /// 验证 HSK 证书
    pub fn verify_hsk_certificate(&self, hrk_cert: &csv_attest_sys::chip_root_cert_t, hsk_cert: &csv_attest_sys::chip_root_cert_t) -> CsvAttestationResult<()> {
        let ret = unsafe {
            verify_hsk_cert_signature(
                hrk_cert as *const csv_attest_sys::chip_root_cert_t,
                hsk_cert as *const csv_attest_sys::chip_root_cert_t
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(CsvAttestationError::CertChainFailed(format!("HSK certificate verification failed: {}", ret)))
        }
    }

    /// 验证 CEK 证书
    pub fn verify_cek_certificate(&self, hsk_cert: &csv_attest_sys::chip_root_cert_t, cek_cert: &csv_attest_sys::csv_cert_t) -> CsvAttestationResult<()> {
        let ret = unsafe {
            verify_cek_signature(
                hsk_cert as *const csv_attest_sys::chip_root_cert_t,
                cek_cert as *const csv_attest_sys::csv_cert_t
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(CsvAttestationError::CertChainFailed(format!("CEK certificate verification failed: {}", ret)))
        }
    }

    /// 验证 PEK 证书
    pub fn verify_pek_certificate(&self, cek_cert: &csv_attest_sys::csv_cert_t, pek_cert: &csv_attest_sys::csv_cert_t) -> CsvAttestationResult<()> {
        let ret = unsafe {
            verify_pek_cert_with_cek_signature(
                cek_cert as *const csv_attest_sys::csv_cert_t,
                pek_cert as *const csv_attest_sys::csv_cert_t
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(CsvAttestationError::CertChainFailed(format!("PEK certificate verification failed: {}", ret)))
        }
    }

    /// 验证证明报告签名
    pub fn verify_report_signature(&self, report: &CsvAttestationReport) -> CsvAttestationResult<()> {
        let report_bytes = self.report_to_bytes(report)?;
        
        let ret = unsafe {
            csv_attestation_report_verify(report_bytes.as_ptr() as *mut csv_attest_sys::csv_attestation_report)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(CsvAttestationError::VerificationFailed(format!("Report signature verification failed: {}", ret)))
        }
    }

    /// 加载 HRK 证书文件
    pub fn load_hrk_certificate(&self, filename: &str) -> CsvAttestationResult<Vec<u8>> {
        let c_filename = CString::new(filename)
            .map_err(|_| CsvAttestationError::InvalidParameter("Invalid filename".to_string()))?;
        
        let mut buffer = vec![0u8; std::mem::size_of::<csv_attest_sys::chip_root_cert_t>()];
        
        let ret = unsafe {
            load_hrk_file(
                c_filename.as_ptr() as *mut i8,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer.len(),
            )
        };

        if ret == 0 {
            Ok(buffer)
        } else {
            Err(CsvAttestationError::CertChainFailed(format!("Failed to load HRK certificate: {}", ret)))
        }
    }

    /// 加载 HSK 和 CEK 证书文件
    pub fn load_hsk_cek_certificates(&self, chip_id: &str) -> CsvAttestationResult<(Vec<u8>, Vec<u8>)> {
        let c_chip_id = CString::new(chip_id)
            .map_err(|_| CsvAttestationError::InvalidParameter("Invalid chip ID".to_string()))?;
        
        let mut hsk_buffer = vec![0u8; std::mem::size_of::<csv_attest_sys::chip_root_cert_t>()];
        let mut cek_buffer = vec![0u8; std::mem::size_of::<csv_attest_sys::csv_cert_t>()];
        
        let ret = unsafe {
            load_hsk_cek_file(
                c_chip_id.as_ptr() as *mut i8,
                hsk_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                hsk_buffer.len(),
                cek_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                cek_buffer.len(),
            )
        };

        if ret == 0 {
            Ok((hsk_buffer, cek_buffer))
        } else {
            Err(CsvAttestationError::CertChainFailed(format!("Failed to load HSK/CEK certificates: {}", ret)))
        }
    }

    /// 获取虚拟机状态
    pub fn get_vm_status(&self) -> CsvAttestationResult<u32> {
        let mut status = 0u32;
        
        let ret = unsafe {
            csv_get_status(&mut status)
        };

        if ret == 0 {
            Ok(status)
        } else {
            Err(ret.into())
        }
    }

    /// 保存公钥到 PEM 文件
    pub fn save_pubkey_to_pem_file(&self, pubkey: &EccPubkey, filename: &str) -> CsvAttestationResult<()> {
        let c_filename = CString::new(filename)
            .map_err(|_| CsvAttestationError::InvalidParameter("Invalid filename".to_string()))?;
        
        let ret = unsafe {
            csv_save_pubkey_to_pem_file(
                pubkey as *mut EccPubkey,
                c_filename.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(ret.into())
        }
    }

    /// 将证明报告转换为字节数组
    fn report_to_bytes(&self, report: &CsvAttestationReport) -> CsvAttestationResult<Vec<u8>> {
        let mut bytes = vec![0u8; std::mem::size_of::<CsvAttestationReport>()];
        
        // 复制各个字段
        bytes[0..32].copy_from_slice(&report.user_pubkey_digest);
        bytes[32..48].copy_from_slice(&report.vm_id);
        bytes[48..64].copy_from_slice(&report.vm_version);
        bytes[64..128].copy_from_slice(&report.user_data);
        bytes[128..144].copy_from_slice(&report.mnonce);
        bytes[144..176].copy_from_slice(&report.measure);
        
        // 复制 u32 字段
        let policy_bytes = report.policy.to_le_bytes();
        bytes[176..180].copy_from_slice(&policy_bytes);
        
        let sig_usage_bytes = report.sig_usage.to_le_bytes();
        bytes[180..184].copy_from_slice(&sig_usage_bytes);
        
        let sig_algo_bytes = report.sig_algo.to_le_bytes();
        bytes[184..188].copy_from_slice(&sig_algo_bytes);
        
        let anonce_bytes = report.anonce.to_le_bytes();
        bytes[188..192].copy_from_slice(&anonce_bytes);
        
        // 复制签名
        for (i, sig_val) in report.sig1.iter().enumerate() {
            let sig_bytes = sig_val.to_le_bytes();
            bytes[192 + i * 4..192 + (i + 1) * 4].copy_from_slice(&sig_bytes);
        }
        
        // 复制 PEK 证书
        if report.pek_cert.len() <= 1024 {
            bytes[336..336 + report.pek_cert.len()].copy_from_slice(&report.pek_cert);
        }
        
        // 复制序列号
        bytes[1376..1440].copy_from_slice(&report.sn);
        
        // 复制 MAC
        bytes[1440..1472].copy_from_slice(&report.mac);
        
        Ok(bytes)
    }
}

impl Default for CsvAttestationClient {
    fn default() -> Self {
        Self::new()
    }
}

/// 便捷函数：生成随机字节
pub fn generate_random_bytes(len: usize) -> CsvAttestationResult<Vec<u8>> {
    let mut buf = vec![0u8; len];
    unsafe {
        csv_gen_random_bytes(buf.as_mut_ptr(), len as u32);
    }
    Ok(buf)
}

/// 便捷函数：验证证明报告
pub fn verify_attestation_report(report_data: &[u8], verify_chain: bool) -> CsvAttestationResult<()> {
    let ret = unsafe {
        csv_verify_attestation_report(
            report_data.as_ptr(),
            report_data.len() as u32,
            if verify_chain { 1 } else { 0 },
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(ret.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_attestation_client_creation() {
        let client = CsvAttestationClient::new();
        assert_eq!(client.nonce.len(), GUEST_ATTESTATION_NONCE_SIZE);
    }

    #[test]
    fn test_nonce_generation() {
        let mut client = CsvAttestationClient::new();
        assert!(client.generate_nonce().is_ok());
    }

    #[test]
    fn test_custom_nonce() {
        let mut client = CsvAttestationClient::new();
        let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(client.set_nonce(&nonce).is_ok());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let mut client = CsvAttestationClient::new();
        let invalid_nonce = vec![1, 2, 3];
        assert!(client.set_nonce(&invalid_nonce).is_err());
    }

    #[test]
    fn test_random_bytes_generation() {
        let result = generate_random_bytes(16);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 16);
    }
}