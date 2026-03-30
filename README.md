# gtls — Generic TLS Library

基于 OpenSSL 的通用 TLS 库，C++17 实现，支持多隧道并行连接池、协议适配器回调、证书验证、密钥轮换等功能。适用于 RADIUS (RadSec)、MQTT、HTTPS、gRPC 等任意基于 TCP/TLS 的协议。

## 项目结构

```
├── CMakeLists.txt              # 构建配置
├── include/gtls/               # 公共头文件
│   ├── library.h               # 库初始化 / 清理
│   ├── tls_config.h            # TLS 配置结构体
│   ├── config_parser.h         # 配置解析（键值对文本 → TlsConfig）
│   ├── config_serializer.h     # 配置序列化（TlsConfig → 键值对文本）
│   ├── tls_context.h           # SSL_CTX 管理（缓存 / 热重载）
│   ├── tls_connection.h        # TLS 连接（握手 / 关闭）
│   ├── tls_io.h                # 带超时的 TLS 读写
│   ├── connection_pool.h       # 多隧道连接池
│   ├── protocol_adapter.h      # 协议适配器（帧回调 / 路由回调）
│   ├── certificate_verifier.h  # 证书验证（SAN 匹配 / 热更新重验证）
│   ├── rekey_manager.h         # TLS 1.3 密钥轮换
│   ├── selfie_cache.h          # 自连接攻击检测
│   └── logger.h                # 日志回调 / SSL keylog
├── src/                        # 实现文件
├── tests/                      # Google Test + RapidCheck 测试
├── examples/                   # 示例程序
│   └── radius_demo.cpp         # RadSec 多隧道路由 Demo
├── docs/
│   └── api_guide.md            # API 使用指南
├── ca.pem / client.pem / client.key  # 测试用自签名证书
└── .gitignore
```

## 依赖

| 依赖 | 版本要求 | 说明 |
|------|---------|------|
| CMake | ≥ 3.14 | 构建系统 |
| C++ 编译器 | 支持 C++17 | GCC 7+ / Clang 5+ |
| OpenSSL | ≥ 1.1.1 | TLS 后端（需要开发包） |
| Google Test | v1.14.0 | 自动通过 FetchContent 下载 |
| RapidCheck | master | 自动通过 FetchContent 下载 |

### 安装 OpenSSL 开发包

```bash
# Debian / Ubuntu
sudo apt-get install libssl-dev

# CentOS / RHEL
sudo yum install openssl-devel

# macOS
brew install openssl
```

## 编译

### 基本编译

```bash
# 配置（在项目根目录下）
cmake -S . -B build

# 编译库 + 测试 + 示例
cmake --build build -j$(nproc)
```

### 编译选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `ENABLE_ASAN` | OFF | 启用 AddressSanitizer 内存检测 |
| `BUILD_TESTS` | ON | 编译测试 |
| `BUILD_EXAMPLES` | ON | 编译示例程序 |

```bash
# 启用 ASan 编译
cmake -S . -B build -DENABLE_ASAN=ON
cmake --build build -j$(nproc)

# 仅编译库，不编译测试和示例
cmake -S . -B build -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF
cmake --build build -j$(nproc)
```

### 编译产物

| 产物 | 路径 | 说明 |
|------|------|------|
| `libgtls.a` | `build/libgtls.a` | 静态库 |
| `gtls_tests` | `build/gtls_tests` | 测试可执行文件 |
| `radius_demo` | `build/radius_demo` | RadSec Demo |

## 测试

测试框架使用 Google Test（单元测试）+ RapidCheck（属性测试），首次编译时自动从 GitHub 下载。

### 运行全部测试

```bash
cd build
ctest --output-on-failure
```

### 运行指定模块的测试

```bash
cd build

# 只跑 TlsConfig 相关测试
ctest --output-on-failure -R TlsConfig

# 只跑 TlsContext 相关测试
ctest --output-on-failure -R TlsContext

# 只跑 CertificateVerifier 相关测试
ctest --output-on-failure -R CertVerifier

# 只跑 TlsConnection 相关测试
ctest --output-on-failure -R TlsConnection
```

### 直接运行测试可执行文件

```bash
# 运行全部测试（带详细输出）
./build/gtls_tests

# 使用 GTest filter 运行指定测试
./build/gtls_tests --gtest_filter="TlsConfigValidation.*"
./build/gtls_tests --gtest_filter="TlsConfigProperty.*"
./build/gtls_tests --gtest_filter="TlsContextPropertyTest*"

# 列出所有可用测试
./build/gtls_tests --gtest_list_tests
```

### 测试覆盖的模块

| 测试文件 | 覆盖模块 | 测试类型 |
|---------|---------|---------|
| `tls_config_test.cpp` | TlsConfig / ConfigParser / ConfigSerializer | 单元测试 + 属性测试 (Property 1-3) |
| `tls_context_test.cpp` | TlsContext | 属性测试 (Property 4-7) |
| `certificate_verifier_test.cpp` | CertificateVerifier | 属性测试 (Property 11) |
| `tls_connection_test.cpp` | TlsConnection (SNI) | 属性测试 (Property 8) |
| `tls_io_test.cpp` | TlsIO | 属性测试 (Property 9-10) |
| `rekey_manager_test.cpp` | RekeyManager | 属性测试 (Property 12) |
| `logger_test.cpp` | Logger | 单元测试 |

### ASan 模式测试

```bash
cmake -S . -B build_asan -DENABLE_ASAN=ON
cmake --build build_asan -j$(nproc)
cd build_asan
ctest --output-on-failure
```

## 快速使用

```cpp
#include "gtls/library.h"
#include "gtls/tls_config.h"
#include "gtls/tls_context.h"
#include "gtls/tls_connection.h"
#include "gtls/tls_io.h"

int main() {
    // 1. Initialize
    gtls::Library::init();

    // 2. Configure
    gtls::TlsConfig cfg;
    cfg.ca_cert_file  = "/path/to/ca.pem";
    cfg.cert_file     = "/path/to/client.pem";
    cfg.cert_key_file = "/path/to/client.key";
    cfg.cache_expiry  = 3600;

    // 3. Create context
    gtls::TlsContext ctx(cfg);

    // 4. Connect (assuming sock is a connected TCP socket)
    gtls::TlsConnection conn(ctx, sock);
    conn.connect(30, "server.example.com");

    // 5. Read / Write
    unsigned char buf[4096];
    int n = gtls::TlsIO::read(conn.ssl(), buf, sizeof(buf), 10);
    gtls::TlsIO::write(conn.ssl(), "hello", 5);

    // 6. Cleanup
    conn.shutdown();
    gtls::Library::cleanup();
}
```

### 多隧道连接池用法

```cpp
#include "gtls/connection_pool.h"
#include "gtls/protocol_adapter.h"

// Create pool
gtls::PoolConfig pool_cfg;
pool_cfg.max_connections_per_target = 4;
gtls::ConnectionPool pool(pool_cfg);

// Create adapter with RADIUS framing
gtls::ProtocolAdapter adapter("radius");
adapter.set_frame_callback([](const unsigned char* data, int len) -> int {
    if (len < 4) return 0;
    int pkt_len = (data[2] << 8) | data[3];
    return (len >= pkt_len) ? pkt_len : 0;
});
adapter.set_routing_callback([](const unsigned char* data, int len) -> gtls::TunnelKey {
    return {"10.0.1.100", 2083, "radsec"};
});

// Send through routed tunnel
adapter.send(pool, ctx, packet_data, packet_len);
```

更详细的 API 说明见 [docs/api_guide.md](docs/api_guide.md)。

## License

MIT
