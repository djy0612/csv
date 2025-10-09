use csv_attest::{CsvAttestationClient, CsvAttestationError};
use std::env;

fn main() -> Result<(), CsvAttestationError> {
    println!("CSV Attestation Demo");
    println!("===================");

    // 创建 CSV 证明客户端
    let mut client = CsvAttestationClient::new();
    
    // 生成随机数
    println!("Generating nonce...");
    client.generate_nonce()?;
    println!("Nonce generated successfully");

    // 尝试通过 ioctl 获取证明报告
    println!("\nTrying to get attestation report via ioctl...");
    match client.get_attestation_report_ioctl() {
        Ok(report) => {
            println!("✓ Attestation report obtained successfully via ioctl");
            print_report_info(&report);
            
            // 验证报告
            println!("\nVerifying attestation report...");
            match client.verify_attestation_report(&report, false) {
                Ok(_) => println!("✓ Report verification successful"),
                Err(e) => println!("✗ Report verification failed: {}", e),
            }

            // 验证证书链
            println!("\nVerifying certificate chain...");
            match client.verify_certificate_chain(&report) {
                Ok(_) => println!("✓ Certificate chain verification successful"),
                Err(e) => println!("✗ Certificate chain verification failed: {}", e),
            }

            // 验证报告签名
            println!("\nVerifying report signature...");
            match client.verify_report_signature(&report) {
                Ok(_) => println!("✓ Report signature verification successful"),
                Err(e) => println!("✗ Report signature verification failed: {}", e),
            }

            // 尝试加载证书文件
            println!("\nLoading certificate files...");
            match client.load_hrk_certificate("./hrk.cert") {
                Ok(hrk_data) => println!("✓ HRK certificate loaded: {} bytes", hrk_data.len()),
                Err(e) => println!("✗ Failed to load HRK certificate: {}", e),
            }

            let chip_id_str = String::from_utf8_lossy(&chip_id);
            match client.load_hsk_cek_certificates(&chip_id_str) {
                Ok((hsk_data, cek_data)) => {
                    println!("✓ HSK certificate loaded: {} bytes", hsk_data.len());
                    println!("✓ CEK certificate loaded: {} bytes", cek_data.len());
                },
                Err(e) => println!("✗ Failed to load HSK/CEK certificates: {}", e),
            }
        }
        Err(e) => {
            println!("✗ Failed to get attestation report via ioctl: {}", e);
            
            // 尝试通过 vmmcall 获取证明报告
            println!("\nTrying to get attestation report via vmmcall...");
            match client.get_attestation_report_vmmcall() {
                Ok(report) => {
                    println!("✓ Attestation report obtained successfully via vmmcall");
                    print_report_info(&report);
                    
                    // 验证报告
                    println!("\nVerifying attestation report...");
                    match client.verify_attestation_report(&report, false) {
                        Ok(_) => println!("✓ Report verification successful"),
                        Err(e) => println!("✗ Report verification failed: {}", e),
                    }
                }
                Err(e) => {
                    println!("✗ Failed to get attestation report via vmmcall: {}", e);
                    println!("This might be because:");
                    println!("  - CSV kernel module is not loaded");
                    println!("  - Not running in a CSV environment");
                    println!("  - Missing /dev/csv-guest device");
                }
            }
        }
    }

    // 获取虚拟机状态
    println!("\nGetting VM status...");
    match client.get_vm_status() {
        Ok(status) => {
            println!("✓ VM status: 0x{:x}", status);
            if status & 0x1 != 0 {
                println!("  - VM type: CSV");
            } else {
                println!("  - VM type: Non-CSV");
            }
            if status & 0x2 != 0 {
                println!("  - Certificate chain verification: Supported");
            } else {
                println!("  - Certificate chain verification: Not supported");
            }
        }
        Err(e) => {
            println!("✗ Failed to get VM status: {}", e);
        }
    }

    Ok(())
}

fn print_report_info(report: &csv_attest::CsvAttestationReport) {
    println!("\nAttestation Report Information:");
    println!("================================");
    
    // 打印基本信息
    println!("Policy: 0x{:x}", report.policy);
    println!("Signature Usage: 0x{:x}", report.sig_usage);
    println!("Signature Algorithm: 0x{:x}", report.sig_algo);
    println!("ANonce: 0x{:x}", report.anonce);
    
    // 打印 VM ID
    println!("VM ID: {}", hex_string(&report.vm_id));
    
    // 打印 VM Version
    println!("VM Version: {}", hex_string(&report.vm_version));
    
    // 打印用户数据（解密后）
    let user_data = report.get_user_data();
    println!("User Data (decrypted): {}", hex_string(&user_data));
    
    // 打印随机数（解密后）
    let mnonce = report.get_mnonce();
    println!("MNonce (decrypted): {}", hex_string(&mnonce));
    
    // 打印度量值（解密后）
    let measure = report.get_measure();
    println!("Measure (decrypted): {}", hex_string(&measure));
    
    // 打印芯片序列号（解密后）
    let chip_id = report.get_chip_id();
    println!("Chip ID (decrypted): {}", hex_string(&chip_id));
    
    // 打印 MAC
    println!("MAC: {}", hex_string(&report.mac));
    
    // 打印 PEK 证书信息
    println!("PEK Certificate Size: {} bytes", report.pek_cert.len());
    if report.pek_cert.len() > 0 {
        println!("PEK Certificate (first 32 bytes): {}", 
                 hex_string(&report.pek_cert[..32.min(report.pek_cert.len())]));
    }
}

fn hex_string(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
