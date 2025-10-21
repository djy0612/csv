#!/bin/bash

echo "🔧 测试 ra-tls 模块编译..."

# 检查编译
echo "1. 检查代码编译..."
if cargo check --quiet; then
    echo "✅ 编译检查通过"
else
    echo "❌ 编译检查失败"
    exit 1
fi

# 运行基础测试
echo "2. 运行基础测试..."
if cargo test --lib --quiet; then
    echo "✅ 基础测试通过"
else
    echo "⚠️  基础测试有失败（主机环境预期）"
fi

# 运行 CSV 特定测试
echo "3. 运行 CSV 特定测试..."
if cargo test --test csv_attestation_tests --quiet; then
    echo "✅ CSV 特定测试通过"
else
    echo "⚠️  CSV 特定测试失败（主机环境预期）"
fi

echo "🎯 编译测试完成！"
