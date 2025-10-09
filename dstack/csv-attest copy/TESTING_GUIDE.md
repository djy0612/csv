# CSV 证明系统测试指南

## 📋 测试环境准备

### 1. 硬件要求
- ✅ **海光 CPU**：支持 CSV (Confidential Secure Virtualization)
- ✅ **内存**：至少 8GB RAM
- ✅ **存储**：至少 50GB 可用空间
- ✅ **网络**：能够访问海光 KDS (Key Distribution Service)

### 2. 软件环境
- ✅ **Yocto 构建环境**：已配置的 Yocto 项目
- ✅ **Rust 工具链**：Rust 1.70+ 和 Cargo
- ✅ **C 编译环境**：GCC 和必要的开发库
- ✅ **OpenSSL/GmSSL**：支持 SM2/SM3 算法

## 🏗 构建步骤

### 步骤 1: 构建 Yocto 镜像

```bash
# 设置环境变量
export MACHINE=csv
export DISTRO=poky

# 初始化构建环境
source poky/oe-init-build-env build

# 构建内核模块
bitbake csv-guest

# 构建证明工具
bitbake csv-attest csv-attest-sys

# 构建完整镜像
bitbake dstack-rootfs-base
```

### 步骤 2: 编译 Rust 组件

```bash
# 进入 dstack 目录
cd dstack

# 编译 csv-attest-sys
cd csv-attest-sys
cargo build --release

# 编译 csv-attest
cd ../csv-attest
cargo build --release

# 运行示例程序
cargo run --example csv_attest_demo
```

## 🧪 测试步骤详解

### 阶段 1: 环境验证测试

#### 1.1 检查 CSV 硬件支持

```bash
# 检查 CPU 是否支持 CSV
cat /proc/cpuinfo | grep -i csv

# 检查内核模块是否加载
lsmod | grep csv

# 检查设备文件是否存在
ls -la /dev/csv-guest
```

**预期结果**：
```
-rw-rw-rw- 1 root root 10, 123 Jan 1 00:00 /dev/csv-guest
```

#### 1.2 验证内核模块功能

```bash
# 加载内核模块
sudo modprobe csv-guest

# 检查模块状态
cat /proc/modules | grep csv

# 检查设备权限
ls -la /dev/csv-guest
```

**预期结果**：
```
csv_guest 16384 0 - Live 0xffffffffc0000000 (O)
```

### 阶段 2: 基础功能测试

#### 2.1 运行基础测试程序

```bash
# 进入测试目录
cd dstack/csv-attest

# 运行基础测试
cargo run --example csv_attest_demo
```

**预期输出**：
```
CSV Attestation Demo
===================
Generating nonce...
Nonce generated successfully

Trying to get attestation report via ioctl...
✓ Attestation report obtained successfully via ioctl
Report VM ID: [16 bytes]
Report VM Version: [16 bytes]
Report Policy: 0x1
Report anonce: 0x12345678

Verifying attestation report...
✓ Report verification successful
```

#### 2.2 测试错误处理

```bash
# 测试无效参数
cargo run --example csv_attest_demo -- --invalid-param

# 测试设备不存在的情况
sudo rmmod csv-guest
cargo run --example csv_attest_demo
```

**预期结果**：应该显示适当的错误消息

### 阶段 3: 证书链验证测试

#### 3.1 准备证书文件

```bash
# 创建证书目录
mkdir -p /tmp/csv-certs

# 下载 HRK 证书
curl -o /tmp/csv-certs/hrk.cert "https://kds.hygon.cn/hrk.cert"

# 获取芯片 ID (从证明报告中提取)
# 这个需要先运行一次证明程序获取
```

#### 3.2 运行证书链验证测试

```bash
# 运行完整验证测试
cargo run --example csv_attest_demo -- --verify-chain

# 预期输出
Verifying certificate chain...
✓ Certificate chain verification successful

Loading certificate files...
✓ HRK certificate loaded: 1024 bytes
✓ HSK certificate loaded: 1024 bytes
✓ CEK certificate loaded: 1028 bytes
```

### 阶段 4: 性能测试

#### 4.1 基准测试

```bash
# 创建性能测试程序
cat > performance_test.rs << 'EOF'
use csv_attest::CsvAttestationClient;
use std::time::Instant;

fn main() -> Result<(), csv_attest::CsvAttestationError> {
    let mut client = CsvAttestationClient::new();
    client.generate_nonce()?;
    
    let start = Instant::now();
    let report = client.get_attestation_report_ioctl()?;
    let duration = start.elapsed();
    
    println!("Attestation report generation: {:?}", duration);
    
    let start = Instant::now();
    client.verify_certificate_chain(&report)?;
    let duration = start.elapsed();
    
    println!("Certificate chain verification: {:?}", duration);
    
    Ok(())
}
EOF

# 运行性能测试
cargo run --bin performance_test
```

#### 4.2 并发测试

```bash
# 创建并发测试脚本
cat > concurrent_test.sh << 'EOF'
#!/bin/bash

# 并发运行多个证明请求
for i in {1..10}; do
    cargo run --example csv_attest_demo &
done

wait
echo "All concurrent tests completed"
EOF

chmod +x concurrent_test.sh
./concurrent_test.sh
```

### 阶段 5: 集成测试

#### 5.1 与 DStack 集成测试

```bash
# 启动 DStack 虚拟机
cd scripts
python3 bin/dstack.py start --machine csv --vcpus 4 --memory 8192

# 在虚拟机内运行测试
ssh root@<vm-ip> "cd /opt/dstack && cargo run --example csv_attest_demo"
```

#### 5.2 网络连接测试

```bash
# 测试 KDS 服务连接
curl -I https://kds.hygon.cn/hrk.cert

# 测试证书下载
curl -o hrk.cert https://kds.hygon.cn/hrk.cert
openssl x509 -in hrk.cert -text -noout
```

## 🔍 故障排除

### 常见问题及解决方案

#### 问题 1: 设备文件不存在

**症状**：
```
Error: No such file or directory (os error 2)
```

**解决方案**：
```bash
# 检查内核模块是否加载
lsmod | grep csv

# 如果没有加载，手动加载
sudo modprobe csv-guest

# 检查设备文件
ls -la /dev/csv-guest
```

#### 问题 2: ioctl 调用失败

**症状**：
```
Error: Invalid argument (os error 22)
```

**解决方案**：
```bash
# 检查设备权限
sudo chmod 666 /dev/csv-guest

# 检查内核日志
dmesg | grep csv

# 重新加载模块
sudo rmmod csv-guest
sudo modprobe csv-guest
```

#### 问题 3: 证书验证失败

**症状**：
```
Certificate chain verification failed
```

**解决方案**：
```bash
# 检查网络连接
ping kds.hygon.cn

# 检查证书文件
ls -la *.cert

# 手动下载证书
curl -v https://kds.hygon.cn/hrk.cert
```

#### 问题 4: 编译错误

**症状**：
```
error: linking with `cc` failed
```

**解决方案**：
```bash
# 安装必要的开发库
sudo apt-get install build-essential libssl-dev

# 设置环境变量
export GMSSL_PATH=/opt/gmssl
export PKG_CONFIG_PATH=/opt/gmssl/lib/pkgconfig

# 重新编译
cargo clean
cargo build
```

## 📊 测试结果验证

### 成功标准

1. ✅ **基础功能**：
   - 内核模块成功加载
   - 设备文件正确创建
   - ioctl 调用成功

2. ✅ **证明功能**：
   - 证明报告成功生成
   - 数据解密正确
   - 随机数生成正常

3. ✅ **验证功能**：
   - 证书链验证通过
   - 签名验证成功
   - 错误处理正确

4. ✅ **性能要求**：
   - 证明报告生成 < 100ms
   - 证书链验证 < 500ms
   - 内存使用 < 100MB

### 测试报告模板

```markdown
# CSV 证明系统测试报告

## 测试环境
- 硬件: 海光 CPU (型号: xxx)
- 软件: Yocto Linux (版本: xxx)
- 内核: Linux 5.x (CSV 支持)

## 测试结果
- [x] 环境验证测试
- [x] 基础功能测试  
- [x] 证书链验证测试
- [x] 性能测试
- [x] 集成测试

## 性能指标
- 证明报告生成: XXms
- 证书链验证: XXms
- 内存使用: XXMB

## 问题记录
- 问题 1: [描述] - 已解决
- 问题 2: [描述] - 待解决

## 结论
系统功能正常，性能满足要求。
```

## 🚀 自动化测试

### 创建测试脚本

```bash
# 创建完整测试脚本
cat > run_all_tests.sh << 'EOF'
#!/bin/bash

set -e

echo "Starting CSV Attestation System Tests"
echo "====================================="

# 环境检查
echo "1. Checking environment..."
lsmod | grep csv || echo "Warning: csv module not loaded"
ls -la /dev/csv-guest || echo "Error: csv-guest device not found"

# 基础测试
echo "2. Running basic tests..."
cd dstack/csv-attest
cargo test

# 示例程序测试
echo "3. Running demo program..."
cargo run --example csv_attest_demo

# 性能测试
echo "4. Running performance tests..."
cargo run --bin performance_test

echo "All tests completed successfully!"
EOF

chmod +x run_all_tests.sh
./run_all_tests.sh
```

这个测试指南提供了从环境准备到自动化测试的完整流程，确保 CSV 证明系统的所有功能都能得到充分验证！🎯
