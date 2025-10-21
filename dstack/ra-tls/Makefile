# CSV RA-TLS 模块测试 Makefile

.PHONY: help test test-unit test-integration test-demo test-csv test-quality test-performance test-all clean test-host

# 默认目标
help:
	@echo "CSV RA-TLS 模块测试命令"
	@echo "========================"
	@echo "test           - 运行所有测试"
	@echo "test-unit      - 运行单元测试"
	@echo "test-integration - 运行集成测试"
	@echo "test-demo      - 运行演示程序"
	@echo "test-csv       - 运行 CSV 特定测试"
	@echo "test-quality   - 运行代码质量检查"
	@echo "test-performance - 运行性能测试"
	@echo "test-all       - 运行完整测试套件"
	@echo "test-host      - 运行主机环境测试"
	@echo "clean          - 清理构建文件"
	@echo "check-env      - 检查测试环境"

# 检查环境
check-env:
	@echo "检查测试环境..."
	@command -v cargo >/dev/null 2>&1 || (echo "错误: Cargo 未安装" && exit 1)
	@echo "✓ Rust 工具链检查通过"
	@grep -q "csv" /proc/cpuinfo 2>/dev/null && echo "✓ 检测到 CSV 硬件支持" || echo "⚠ 未检测到 CSV 硬件支持"
	@lsmod | grep -q csv && echo "✓ CSV 内核模块已加载" || echo "⚠ CSV 内核模块未加载"
	@test -e /dev/csv-guest && echo "✓ CSV 设备文件存在" || echo "⚠ CSV 设备文件不存在"

# 运行单元测试
test-unit: check-env
	@echo "运行单元测试..."
	cd dstack/ra-tls && cargo test --lib --quiet
	@echo "✓ 单元测试完成"

# 运行集成测试
test-integration: check-env
	@echo "运行集成测试..."
	cd dstack/ra-tls && cargo test --test csv_integration_tests --quiet
	@echo "✓ 集成测试完成"

# 运行演示程序
test-demo: check-env
	@echo "运行演示程序..."
	cd dstack/ra-tls && cargo run --example csv_demo -- basic
	cd dstack/ra-tls && cargo run --example csv_demo -- cert
	cd dstack/ra-tls && cargo run --example csv_demo -- performance
	@echo "✓ 演示程序完成"

# 运行 CSV 特定测试
test-csv: check-env
	@echo "运行 CSV 特定测试..."
	cd dstack/csv-attest && cargo test --quiet
	cd dstack/csv-attest && cargo run --example rtmr_demo
	@echo "✓ CSV 特定测试完成"

# 运行代码质量检查
test-quality:
	@echo "运行代码质量检查..."
	cd dstack/ra-tls && cargo fmt -- --check
	cd dstack/ra-tls && cargo clippy -- -D warnings
	@echo "✓ 代码质量检查完成"

# 运行性能测试
test-performance: check-env
	@echo "运行性能测试..."
	cd dstack/ra-tls && cargo run --example csv_demo -- performance
	@echo "✓ 性能测试完成"

# 运行所有测试
test-all: test-unit test-integration test-demo test-csv test-quality test-performance
	@echo "✓ 所有测试完成"

# 默认测试（运行核心测试）
test: test-unit test-integration test-demo

# 清理构建文件
clean:
	@echo "清理构建文件..."
	cd dstack/ra-tls && cargo clean
	cd dstack/csv-attest && cargo clean
	@echo "✓ 清理完成"

# 快速测试（仅运行单元测试）
quick-test: test-unit

# 主机环境测试
test-host: check-env
	@echo "运行主机环境测试..."
	@./test_csv_ra_tls_host.sh all
	@echo "✓ 主机环境测试完成"

# 完整测试（包含所有检查）
full-test: test-all
	@echo "生成测试报告..."
	@./test_csv_ra_tls.sh all
	@echo "✓ 完整测试完成"
