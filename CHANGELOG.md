# Changelog

## [Unreleased]

### Optimizations (2026-04-10)

#### Deprecated API 修复
- **server.go**: 替换 `net.Error.Temporary()` (Go 1.18 已废弃) 为 `net.Error.Timeout()`
- **client.go**: 同上，替换 `Temporary()` 为 `Timeout()`

#### 现代 Go 特性
- **client.go**: `interface{}` → `any` (Go 1.18+ 泛型风格)
- **client.go**: 精简多余的注释和类型断言检查

#### 内存池优化
- **mpool.go**: `Put` 条件从 `cap(x) == p.sz` 放宽为 `cap(x) >= p.sz`，避免 reslice 后被静默丢弃

#### 日志改进
- **log.go**: 添加 `fmt` 导入，`Panic()` 现在包含实际错误信息而非单纯的 `"!!"`
- **log.go**: 添加 `Logf()` 便捷函数
- **log.go**: 清理注释掉的代码

#### 代码精简
- 移除冗余注释，保持代码简洁
- 统一错误处理风格

## [1.0.0] - 2026-04-03

### Features
- Fork from xjdrew/gotunnel
- RC4 → ChaCha20 加密升级
- MD5 → SHA256 签名升级
- `math/rand` → `crypto/rand` 安全随机数
- 增加 SIGTERM/SIGINT 信号处理
- 优化 client heartbeat 溢出处理
