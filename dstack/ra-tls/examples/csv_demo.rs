//! CSV 证明演示程序

use anyhow::Result;
use ra_tls::attestation::{Attestation, QuoteContentType};
use ra_tls::cert::{generate_ra_cert, CertPair};
use csv_attest::CsvAttestationClient;
use std::env;
use std::time::Instant;

fn main() -> Result<()> {
    println!("CSV RA-TLS 证明演示程序");
    println!("========================");
    
    // 检查命令行参数
    let args: Vec<String> = env::args().collect();
    let test_mode = args.get(1).map(|s| s.as_str()).unwrap_or("basic");
    
    match test_mode {
        "basic" => run_basic_demo()?,
        "cert" => run_certificate_demo()?,
        "verify" => run_verification_demo()?,
        "performance" => run_performance_demo()?,
        "all" => run_all_demos()?,
        _ => {
            println!("用法: {} [basic|cert|verify|performance|all]", args[0]);
            println!("  basic      - 基础证明功能演示");
            println!("  cert       - 证书生成演示");
            println!("  verify     - 证明验证演示");
            println!("  performance - 性能测试演示");
            println!("  all        - 运行所有演示");
        }
    }
    
    Ok(())
}

/// 基础证明功能演示
fn run_basic_demo() -> Result<()> {
    println!("\n--- 基础证明功能演示 ---");
    
    // 1. 创建 CSV 证明客户端
    println!("1. 创建 CSV 证明客户端...");
    let mut client = CsvAttestationClient::new();
    client.generate_nonce()?;
    println!("✓ CSV 证明客户端创建成功");
    
    // 2. 尝试获取证明报告
    println!("2. 获取证明报告...");
    let start = Instant::now();
    let report_result = client.get_attestation_report_ioctl()
        .or_else(|_| client.get_attestation_report_vmmcall());
    let duration = start.elapsed();
    
    match report_result {
        Ok(report) => {
            println!("✓ 证明报告获取成功 (耗时: {:?})", duration);
            println!("  VM ID: {}", hex::encode(report.vm_id));
            println!("  VM Version: {}", hex::encode(report.vm_version));
            println!("  Policy: 0x{:x}", report.policy);
            println!("  Anonce: 0x{:x}", report.anonce);
        }
        Err(e) => {
            println!("⚠ 证明报告获取失败（非 CSV 环境）: {}", e);
            println!("  耗时: {:?}", duration);
        }
    }
    
    // 3. 测试报告数据生成
    println!("3. 测试报告数据生成...");
    let test_data = b"test application data";
    let report_data = QuoteContentType::AppData.to_report_data(test_data);
    println!("✓ 报告数据生成成功");
    println!("  输入数据: {}", String::from_utf8_lossy(test_data));
    println!("  报告数据: {}", hex::encode(report_data));
    
    Ok(())
}

/// 证书生成演示
fn run_certificate_demo() -> Result<()> {
    println!("\n--- 证书生成演示 ---");
    
    // 1. 生成 CA 证书
    println!("1. 生成 CA 证书...");
    let (ca_cert_pem, ca_key_pem) = generate_test_ca_cert()?;
    println!("✓ CA 证书生成成功");
    
    // 2. 生成 RA-TLS 证书
    println!("2. 生成 RA-TLS 证书...");
    let start = Instant::now();
    let cert_result = generate_ra_cert(ca_cert_pem, ca_key_pem);
    let duration = start.elapsed();
    
    match cert_result {
        Ok(cert_pair) => {
            println!("✓ RA-TLS 证书生成成功 (耗时: {:?})", duration);
            println!("  证书长度: {} 字节", cert_pair.cert_pem.len());
            println!("  密钥长度: {} 字节", cert_pair.key_pem.len());
            
            // 显示证书信息
            if let Ok(cert_info) = extract_cert_info(&cert_pair.cert_pem) {
                println!("  证书主题: {}", cert_info.subject);
                println!("  证书有效期: {}", cert_info.validity);
            }
        }
        Err(e) => {
            println!("⚠ RA-TLS 证书生成失败（非 CSV 环境）: {}", e);
            println!("  耗时: {:?}", duration);
        }
    }
    
    Ok(())
}

/// 证明验证演示
fn run_verification_demo() -> Result<()> {
    println!("\n--- 证明验证演示 ---");
    
    // 1. 创建本地证明
    println!("1. 创建本地证明...");
    let attestation_result = Attestation::local();
    
    match attestation_result {
        Ok(attestation) => {
            println!("✓ 本地证明创建成功");
            
            // 2. 验证证明
            println!("2. 验证证明...");
            let test_report_data = [42u8; 64];
            let start = Instant::now();
            
            let verification_result = tokio::runtime::Runtime::new()?
                .block_on(attestation.verify(&test_report_data, None));
            let duration = start.elapsed();
            
            match verification_result {
                Ok(verified_att) => {
                    println!("✓ 证明验证成功 (耗时: {:?})", duration);
                    println!("  验证状态: {}", verified_att.report.status);
                    println!("  建议数量: {}", verified_att.report.advisory_ids.len());
                    
                    // 3. 解码应用信息
                    println!("3. 解码应用信息...");
                    if let Ok(app_info) = verified_att.decode_app_info(false) {
                        println!("✓ 应用信息解码成功");
                        println!("  设备ID: {}", hex::encode(&app_info.device_id));
                        println!("  系统测量值: {}", hex::encode(&app_info.system_measurement));
                    }
                }
                Err(e) => {
                    println!("⚠ 证明验证失败: {}", e);
                    println!("  耗时: {:?}", duration);
                }
            }
        }
        Err(e) => {
            println!("⚠ 本地证明创建失败（非 CSV 环境）: {}", e);
        }
    }
    
    Ok(())
}

/// 性能测试演示
fn run_performance_demo() -> Result<()> {
    println!("\n--- 性能测试演示 ---");
    
    // 1. 报告数据生成性能
    println!("1. 报告数据生成性能测试...");
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = QuoteContentType::AppData.to_report_data(b"performance test data");
    }
    
    let duration = start.elapsed();
    let avg_time = duration / iterations;
    
    println!("✓ {} 次报告数据生成完成", iterations);
    println!("  总耗时: {:?}", duration);
    println!("  平均耗时: {:?}", avg_time);
    println!("  每秒处理: {:.0} 次", 1_000_000_000.0 / avg_time.as_nanos() as f64);
    
    // 2. 事件日志重放性能
    println!("2. 事件日志重放性能测试...");
    let mock_events = create_mock_events(100)?;
    let iterations = 1000;
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = ra_tls::attestation::replay_event_logs(&mock_events, None)?;
    }
    let duration = start.elapsed();
    let avg_time = duration / iterations;
    
    println!("✓ {} 次事件日志重放完成", iterations);
    println!("  总耗时: {:?}", duration);
    println!("  平均耗时: {:?}", avg_time);
    println!("  每秒处理: {:.0} 次", 1_000_000_000.0 / avg_time.as_nanos() as f64);
    
    Ok(())
}

/// 运行所有演示
fn run_all_demos() -> Result<()> {
    println!("运行所有演示程序...\n");
    
    run_basic_demo()?;
    run_certificate_demo()?;
    run_verification_demo()?;
    run_performance_demo()?;
    
    println!("\n✓ 所有演示程序运行完成！");
    Ok(())
}

// 辅助函数

/// 生成测试 CA 证书
fn generate_test_ca_cert() -> Result<(String, String)> {
    use rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256};
    
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec!["localhost".to_string()];
    params.key_pair = Some(key_pair);
    
    let cert = Certificate::from_params(params)?;
    let cert_pem = cert.pem();
    let key_pem = cert.serialize_private_key_pem();
    
    Ok((cert_pem, key_pem))
}

/// 提取证书信息
fn extract_cert_info(cert_pem: &str) -> Result<CertInfo> {
    use x509_parser::pem::parse_x509_pem;
    
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())?;
    let cert = pem.parse_x509()?;
    
    let subject = cert.subject().to_string();
    let validity = format!("{} - {}", 
        cert.validity().not_before,
        cert.validity().not_after
    );
    
    Ok(CertInfo { subject, validity })
}

/// 创建模拟事件
fn create_mock_events(count: usize) -> Result<Vec<cc_eventlog::TdxEventLog>> {
    use cc_eventlog::TdxEventLog as EventLog;
    
    let mut events = Vec::new();
    for i in 0..count {
        events.push(EventLog {
            imr: (i % 4) as u32,
            event_type: (i + 1) as u32,
            digest: [i as u8; 48],
            event: format!("performance-test-event-{}", i),
            event_payload: vec![i as u8; 16],
        });
    }
    
    Ok(events)
}

/// 证书信息结构
#[derive(Debug)]
struct CertInfo {
    subject: String,
    validity: String,
}
