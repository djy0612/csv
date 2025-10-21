# CSV RA-TLS 模块主机环境测试指南

## 📋 概述

本指南专门针对在 **CSV 主机环境** 中测试 ra-tls 模块的 CSV 适配功能。在主机环境中，CSV 虚拟机相关的功能无法正常工作，但我们可以测试代码逻辑、接口设计和模拟功能。

## 🏗 环境说明

### 当前环境状态
- ✅ **CSV 硬件支持**：海光 CPU 支持 CSV（csv、csv2、csv3 标志）
- ❌ **CSV 虚拟机环境**：未在 CSV 机密虚拟机内部运行
- ❌ **CSV 内核模块**：`csv-guest` 模块未加载
- ❌ **CSV 设备文件**：`/dev/csv-guest` 不存在

### 测试策略
在主机环境中，我们主要测试：
1. **代码编译**：确保代码语法正确
2. **接口设计**：验证 API 接口设计合理
3. **模拟功能**：测试模拟和回退机制
4. **错误处理**：验证错误处理逻辑

## 🚀 快速开始

### 1. 环境检查

```bash
# 检查环境
make check-env

# 或使用脚本
./test_csv_ra_tls_host.sh env
```

### 2. 运行测试

```bash
# 运行主机环境测试
make test-host

# 或使用脚本
./test_csv_ra_tls_host.sh all

# 运行特定测试
make test-unit          # 单元测试
make test-quality       # 代码质量检查
make test-performance   # 性能测试
```

## 🧪 测试类型详解

### 1. 单元测试

**测试内容：**
- CSV 证明报告序列化/反序列化
- 报告数据生成
- 事件日志重放功能
- 错误处理机制

**运行命令：**
```bash
cd dstack/ra-tls
cargo test --test csv_attestation_tests
```

**预期结果：**
- 在主机环境中，CSV 证明相关测试会失败（预期行为）
- 其他逻辑测试应该通过

### 2. 集成测试

**测试内容：**
- 完整的 CSV 证明流程（模拟）
- 证书生成和验证
- 事件日志处理
- 性能基准测试

**运行命令：**
```bash
cd dstack/ra-tls
cargo test --test csv_integration_tests
```

### 3. 演示程序

**功能演示：**
- 基础功能演示（模拟）
- 证书生成演示（模拟）
- 性能测试演示

**运行命令：**
```bash
cd dstack/ra-tls

# 运行所有演示
cargo run --example csv_demo -- all

# 运行特定演示
cargo run --example csv_demo -- basic      # 基础功能
cargo run --example csv_demo -- performance # 性能测试
```

## 🔍 测试结果解读

### 成功指标

1. **代码编译**：✅ 无编译错误
2. **单元测试通过率**：≥ 70%（CSV 相关测试失败是预期的）
3. **代码质量**：✅ 无 Clippy 警告
4. **性能基准**：报告数据生成 < 1μs

### 预期行为

在主机环境中，以下行为是**正常的**：

```
⚠ CSV 证明报告获取失败（非 CSV 环境）
⚠ CSV 特定测试失败（主机环境预期行为）
⚠ 本地证明创建失败（非 CSV 环境）
```

这些警告表明代码正确识别了环境并采取了适当的回退行为。

## 🛠 故障排除

### 常见问题

#### 问题 1：编译错误
```
error: cannot find crate `csv_attest`
```

**解决方案：**
```bash
# 检查依赖
cd dstack/csv-attest
cargo build

# 检查工作空间配置
cd ../..
cargo check --workspace
```

#### 问题 2：测试失败
```
test csv_attestation_creation ... FAILED
```

**说明：** 这是预期行为，在主机环境中 CSV 证明功能无法正常工作。

#### 问题 3：权限问题
```
Permission denied (os error 13)
```

**解决方案：**
```bash
# 检查文件权限
ls -la test_csv_ra_tls_host.sh
chmod +x test_csv_ra_tls_host.sh
```

## 📊 测试报告

### 自动生成报告

```bash
# 生成主机环境测试报告
./test_csv_ra_tls_host.sh all

# 报告文件位置
test_report_host_YYYYMMDD_HHMMSS.txt
```

### 报告内容

- 测试环境信息
- CSV 硬件支持状态
- CSV 虚拟机环境状态
- 测试执行结果
- 注意事项和建议

## 🔄 下一步

### 完整功能测试

要在 CSV 虚拟机环境中进行完整的功能测试，需要：

1. **启动 CSV 虚拟机**
2. **在虚拟机内运行测试**
3. **验证 CSV 证明功能**

### 虚拟机测试命令

```bash
# 在 CSV 虚拟机内运行
cd /opt/dstack/ra-tls
make test-all
```

## 📚 参考资料

- [CSV 证明系统测试指南](../csv-attest/TESTING_GUIDE.md)
- [RA-TLS 协议规范](https://github.com/confidential-containers/ra-tls)
- [海光 CSV 技术文档](https://www.hygon.cn/)

---

**重要提醒：** 在主机环境中，CSV 证明相关功能无法正常工作，这是预期行为。代码逻辑和接口设计测试仍然有效，完整的功能测试需要在 CSV 虚拟机环境中进行。
