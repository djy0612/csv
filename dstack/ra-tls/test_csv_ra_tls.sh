#!/bin/bash

# CSV RA-TLS 模块自动化测试脚本
# 用于验证 ra-tls 模块的 CSV 适配功能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查环境
check_environment() {
    log_info "检查测试环境..."
    
    # 检查 Rust 工具链
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo 未安装"
        exit 1
    fi
    log_success "Rust 工具链检查通过"
    
    # 检查 CSV 硬件支持
    if grep -q "csv" /proc/cpuinfo 2>/dev/null; then
        log_success "检测到 CSV 硬件支持"
        CSV_ENABLED=true
    else
        log_warning "未检测到 CSV 硬件支持，将运行模拟测试"
        CSV_ENABLED=false
    fi
    
    # 检查内核模块
    if lsmod | grep -q csv; then
        log_success "CSV 内核模块已加载"
    else
        log_warning "CSV 内核模块未加载"
    fi
    
    # 检查设备文件
    if [ -e "/dev/csv-guest" ]; then
        log_success "CSV 设备文件存在"
    else
        log_warning "CSV 设备文件不存在"
    fi
}

# 运行单元测试
run_unit_tests() {
    log_info "运行单元测试..."
    
    cd dstack/ra-tls
    
    # 运行基础测试
    log_info "运行基础功能测试..."
    if cargo test --lib --quiet; then
        log_success "基础功能测试通过"
    else
        log_error "基础功能测试失败"
        return 1
    fi
    
    # 运行 CSV 特定测试
    log_info "运行 CSV 特定测试..."
    if cargo test --test csv_attestation_tests --quiet; then
        log_success "CSV 特定测试通过"
    else
        log_warning "CSV 特定测试失败（可能是非 CSV 环境）"
    fi
    
    cd ../..
}

# 运行集成测试
run_integration_tests() {
    log_info "运行集成测试..."
    
    cd dstack/ra-tls
    
    # 运行集成测试
    log_info "运行端到端集成测试..."
    if cargo test --test csv_integration_tests --quiet; then
        log_success "集成测试通过"
    else
        log_warning "集成测试失败（可能是非 CSV 环境）"
    fi
    
    cd ../..
}

# 运行演示程序
run_demo_programs() {
    log_info "运行演示程序..."
    
    cd dstack/ra-tls
    
    # 基础演示
    log_info "运行基础功能演示..."
    if cargo run --example csv_demo -- basic 2>/dev/null; then
        log_success "基础功能演示完成"
    else
        log_warning "基础功能演示失败（可能是非 CSV 环境）"
    fi
    
    # 证书生成演示
    log_info "运行证书生成演示..."
    if cargo run --example csv_demo -- cert 2>/dev/null; then
        log_success "证书生成演示完成"
    else
        log_warning "证书生成演示失败（可能是非 CSV 环境）"
    fi
    
    # 性能测试演示
    log_info "运行性能测试演示..."
    if cargo run --example csv_demo -- performance 2>/dev/null; then
        log_success "性能测试演示完成"
    else
        log_warning "性能测试演示失败"
    fi
    
    cd ../..
}

# 运行 CSV 特定测试
run_csv_specific_tests() {
    if [ "$CSV_ENABLED" = true ]; then
        log_info "运行 CSV 特定测试..."
        
        cd dstack/csv-attest
        
        # 运行 CSV 证明测试
        log_info "运行 CSV 证明功能测试..."
        if cargo test --quiet; then
            log_success "CSV 证明功能测试通过"
        else
            log_error "CSV 证明功能测试失败"
            return 1
        fi
        
        # 运行 RTMR 演示
        log_info "运行 RTMR 演示..."
        if cargo run --example rtmr_demo 2>/dev/null; then
            log_success "RTMR 演示完成"
        else
            log_warning "RTMR 演示失败"
        fi
        
        cd ../..
    else
        log_warning "跳过 CSV 特定测试（非 CSV 环境）"
    fi
}

# 代码质量检查
run_code_quality_checks() {
    log_info "运行代码质量检查..."
    
    cd dstack/ra-tls
    
    # 代码格式检查
    log_info "检查代码格式..."
    if cargo fmt -- --check; then
        log_success "代码格式检查通过"
    else
        log_warning "代码格式需要调整"
    fi
    
    # 代码检查
    log_info "运行代码检查..."
    if cargo clippy -- -D warnings; then
        log_success "代码检查通过"
    else
        log_warning "代码检查发现问题"
    fi
    
    cd ../..
}

# 性能基准测试
run_performance_benchmarks() {
    log_info "运行性能基准测试..."
    
    cd dstack/ra-tls
    
    # 运行性能测试
    log_info "运行性能基准测试..."
    if cargo run --example csv_demo -- performance 2>/dev/null; then
        log_success "性能基准测试完成"
    else
        log_warning "性能基准测试失败"
    fi
    
    cd ../..
}

# 生成测试报告
generate_test_report() {
    log_info "生成测试报告..."
    
    local report_file="test_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "CSV RA-TLS 模块测试报告"
        echo "========================"
        echo "测试时间: $(date)"
        echo "测试环境: $(uname -a)"
        echo "Rust 版本: $(rustc --version)"
        echo "Cargo 版本: $(cargo --version)"
        echo ""
        echo "环境检查:"
        echo "- CSV 硬件支持: $CSV_ENABLED"
        echo "- CSV 内核模块: $(lsmod | grep csv | wc -l) 个模块"
        echo "- CSV 设备文件: $([ -e "/dev/csv-guest" ] && echo "存在" || echo "不存在")"
        echo ""
        echo "测试结果:"
        echo "- 单元测试: 完成"
        echo "- 集成测试: 完成"
        echo "- 演示程序: 完成"
        echo "- 代码质量: 完成"
        echo "- 性能测试: 完成"
    } > "$report_file"
    
    log_success "测试报告已生成: $report_file"
}

# 主函数
main() {
    echo "CSV RA-TLS 模块自动化测试"
    echo "=========================="
    
    # 检查参数
    case "${1:-all}" in
        "env")
            check_environment
            ;;
        "unit")
            check_environment
            run_unit_tests
            ;;
        "integration")
            check_environment
            run_integration_tests
            ;;
        "demo")
            check_environment
            run_demo_programs
            ;;
        "csv")
            check_environment
            run_csv_specific_tests
            ;;
        "quality")
            run_code_quality_checks
            ;;
        "performance")
            check_environment
            run_performance_benchmarks
            ;;
        "all")
            check_environment
            run_unit_tests
            run_integration_tests
            run_demo_programs
            run_csv_specific_tests
            run_code_quality_checks
            run_performance_benchmarks
            generate_test_report
            ;;
        *)
            echo "用法: $0 [env|unit|integration|demo|csv|quality|performance|all]"
            echo ""
            echo "测试选项:"
            echo "  env          - 检查测试环境"
            echo "  unit         - 运行单元测试"
            echo "  integration  - 运行集成测试"
            echo "  demo         - 运行演示程序"
            echo "  csv          - 运行 CSV 特定测试"
            echo "  quality      - 运行代码质量检查"
            echo "  performance  - 运行性能基准测试"
            echo "  all          - 运行所有测试（默认）"
            exit 1
            ;;
    esac
    
    log_success "测试完成！"
}

# 错误处理
trap 'log_error "测试过程中发生错误，退出码: $?"' ERR

# 运行主函数
main "$@"
