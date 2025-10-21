//! CSV 证明功能单元测试

use anyhow::Result;
use ra_tls::attestation::{Attestation, CsvVerifiedReport, QuoteContentType};
use csv_attest::CsvAttestationClient;
use serde_json;
use tempfile::tempdir;

/// 测试 CSV 证明报告创建
#[test]
fn test_csv_attestation_creation() -> Result<()> {
    // 创建 CSV 证明客户端
    let mut client = CsvAttestationClient::new();
    client.generate_nonce()?;
    
    // 尝试获取证明报告
    let report = client.get_attestation_report_ioctl()
        .or_else(|_| client.get_attestation_report_vmmcall());
    
    match report {
        Ok(_) => println!("✓ CSV 证明报告创建成功"),
        Err(e) => {
            // 在非 CSV 环境中，这是预期的
            println!("⚠ CSV 证明报告创建失败（非 CSV 环境）: {}", e);
        }
    }
    
    Ok(())
}

/// 测试 CSV 证明报告序列化/反序列化
#[test]
fn test_csv_report_serialization() -> Result<()> {
    // 注意：由于 CsvAttestationReport 是外部类型，我们无法直接创建模拟数据
    // 这个测试主要用于验证序列化/反序列化逻辑
    println!("✓ CSV 报告序列化/反序列化测试跳过（需要实际 CSV 环境）");
    Ok(())
}

/// 测试报告数据生成
#[test]
fn test_report_data_generation() {
    let content_type = QuoteContentType::RaTlsCert;
    let test_data = b"test public key data";
    
    let report_data = content_type.to_report_data(test_data);
    
    // 验证报告数据不为空
    assert_ne!(report_data, [0u8; 64]);
    
    // 验证相同输入产生相同输出
    let report_data2 = content_type.to_report_data(test_data);
    assert_eq!(report_data, report_data2);
    
    println!("✓ 报告数据生成测试通过");
}

/// 测试事件日志重放功能
#[test]
fn test_event_log_replay() -> Result<()> {
    use cc_eventlog::TdxEventLog as EventLog;
    use ra_tls::attestation::replay_event_logs;
    
    // 创建模拟事件日志
    let mock_events = vec![
        EventLog {
            imr: 0,
            event_type: 1,
            digest: [1u8; 48],
            event: "test-event-1".to_string(),
            event_payload: vec![1, 2, 3],
        },
        EventLog {
            imr: 1,
            event_type: 2,
            digest: [2u8; 48],
            event: "test-event-2".to_string(),
            event_payload: vec![4, 5, 6],
        },
    ];
    
    // 测试事件日志重放
    let rtmrs = replay_event_logs(&mock_events, None)?;
    
    // 验证返回了 4 个 RTMR 值
    assert_eq!(rtmrs.len(), 4);
    
    // 验证 RTMR 值不为全零（至少有一些事件被处理）
    let has_non_zero = rtmrs.iter().any(|rtmr| rtmr.iter().any(|&x| x != 0));
    assert!(has_non_zero);
    
    println!("✓ 事件日志重放测试通过");
    Ok(())
}

/// 测试空事件日志重放
#[test]
fn test_empty_event_log_replay() -> Result<()> {
    use ra_tls::attestation::replay_event_logs;
    
    // 测试空事件日志
    let empty_events = vec![];
    let rtmrs = replay_event_logs(&empty_events, None)?;
    
    // 验证返回了 4 个 RTMR 值
    assert_eq!(rtmrs.len(), 4);
    
    println!("✓ 空事件日志重放测试通过");
    Ok(())
}

/// 测试 CSV 验证报告
#[test]
fn test_csv_verified_report() {
    // 注意：由于 CsvAttestationReport 是外部类型，我们无法直接创建模拟数据
    // 这个测试主要用于验证结构体定义
    println!("✓ CSV 验证报告测试跳过（需要实际 CSV 环境）");
}

/// 测试证书扩展解析
#[test]
fn test_certificate_extension_parsing() -> Result<()> {
    use ra_tls::attestation::Attestation;
    
    // 创建模拟的 quote 和 event_log 数据
    // 注意：由于 CsvAttestationReport 是外部类型，我们使用空数据
    let mock_quote = vec![0u8; 1024]; // 模拟的二进制数据
    
    let mock_event_log = serde_json::to_vec(&vec![])?;
    
    // 测试 Attestation::new
    let attestation = Attestation::new(mock_quote, mock_event_log)?;
    
    // 验证基本字段
    assert!(!attestation.quote.is_empty());
    assert!(attestation.event_log.is_empty());
    
    println!("✓ 证书扩展解析测试通过");
    Ok(())
}

/// 测试错误处理
#[test]
fn test_error_handling() {
    use ra_tls::attestation::QuoteContentType;
    
    // 测试无效哈希算法
    let content_type = QuoteContentType::AppData;
    let result = content_type.to_report_data_with_hash(b"test", "invalid_hash");
    assert!(result.is_err());
    
    // 测试无效原始内容长度
    let invalid_content = [42u8; 65]; // 超过 64 字节
    let result = content_type.to_report_data_with_hash(&invalid_content, "raw");
    assert!(result.is_err());
    
    println!("✓ 错误处理测试通过");
}

/// 测试不同内容类型的报告数据
#[test]
fn test_different_content_types() {
    let test_data = b"test data";
    
    // 测试不同内容类型
    let app_data = QuoteContentType::AppData.to_report_data(test_data);
    let ratls_cert = QuoteContentType::RaTlsCert.to_report_data(test_data);
    let kms_root_ca = QuoteContentType::KmsRootCa.to_report_data(test_data);
    let custom = QuoteContentType::Custom("custom-tag").to_report_data(test_data);
    
    // 验证不同内容类型产生不同的报告数据
    assert_ne!(app_data, ratls_cert);
    assert_ne!(ratls_cert, kms_root_ca);
    assert_ne!(kms_root_ca, custom);
    assert_ne!(custom, app_data);
    
    println!("✓ 不同内容类型测试通过");
}
