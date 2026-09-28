根据对比，**ori** 和 **new** 两个项目的差异如下：

## 主要差异总结

### 1. 加密算法升级
| 文件 | ori | new |
|------|-----|-----|
| conn.go | 使用 RC4 加密 | 使用 ChaCha20 加密 |
| auth.go | 使用 MD5 签名 | 使用 SHA256 签名 |
| 函数命名 | `GetRc4key()` | `GetChacha20key()` |

### 2. 随机数生成器
- **ori**: 使用 `math/rand` (非安全随机)
- **new**: 使用 `crypto/rand` (加密安全随机)

### 3. 代码风格
- **ori**: 简洁，无多余注释
- **new**: 添加了大量注释和文档说明

### 4. 文件差异
- **ori** 独有: hub_queue.go (独立文件)
- **new**: 将 hub_queue.go 内容合并到 client.go 中

### 5. 项目结构
- **ori**: 使用 `github.com/xjdrew/gotunnel/tunnel` 导入路径
- **new**: 使用 `gotunnel/tunnel` (模块名: gotunnel)，Go 版本 1.25.6

### 6. 依赖差异
- **new** 新增依赖: `golang.org/x/crypto` (用于 ChaCha20)

### 7. 信号处理
- **ori**: 仅处理 `SIGHUP`
- **new**: 增加处理 `SIGTERM` 和 `SIGINT`，支持优雅退出

### 8. Heartbeat 逻辑优化
- **new** 的 client heartbeat 逻辑更健壮，使用位运算处理 uint16 溢出

---

**结论**: new 是 ori 的现代化升级版本，主要将不安全的 RC4+MD5 加密方案替换为更安全的 ChaCha20+SHA256，并增强了代码可读性和错误处理。