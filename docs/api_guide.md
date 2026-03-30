# gtls — 通用 TLS 库 API 使用指南

## 1. 概述

gtls（Generic TLS Library）是一个基于 OpenSSL 的通用 TLS 库，采用 C++ 实现，支持多隧道并行连接池、协议适配器回调机制、证书验证、密钥轮换等功能。适用于 RADIUS、MQTT、HTTPS、gRPC 等任意基于 TCP/TLS 的协议。

核心特性：
- 分层架构：配置层 → 上下文层 → 连接层 → I/O 层 → 连接池层 → 适配层
- RAII 资源管理：`std::unique_ptr` 配合自定义删除器自动管理 OpenSSL 资源
- 线程安全：所有共享状态通过 `std::mutex` 保护
- 协议无关：通过回调机制支持任意上层协议

命名空间：所有公开接口位于 `gtls` 命名空间下。

## 2. 快速开始

```cpp
#include "gtls/library.h"
#include "gtls/tls_config.h"
#include "gtls/tls_context.h"
#include "gtls/tls_connection.h"
#include "gtls/tls_io.h"

// 1. Initialize the library
gtls::Library::init();

// 2. Configure TLS parameters
gtls::TlsConfig config;
config.ca_cert_file = "/path/to/ca.pem";
config.cert_file    = "/path/to/client.pem";
config.cert_key_file = "/path/to/client-key.pem";

// 3. Validate configuration
std::string err = config.validate();
if (!err.empty()) {
    // Handle validation error
}

// 4. Create TLS context
gtls::TlsContext ctx(config);

// 5. Establish a client connection (assuming sock is a connected TCP socket)
gtls::TlsConnection conn(ctx, sock);
if (!conn.connect(30, "server.example.com")) {
    // Handle connection failure
}

// 6. Read / Write data
unsigned char buf[4096];
int n = gtls::TlsIO::read(conn.ssl(), buf, sizeof(buf), 10);
gtls::TlsIO::write(conn.ssl(), "hello", 5);

// 7. Cleanup
conn.shutdown();
gtls::Library::cleanup();
```

---

## 3. Library 初始化与清理

**头文件：** `#include "gtls/library.h"`

`Library` 类管理 OpenSSL 库的全局初始化和清理，必须在使用任何其他 gtls 功能之前调用。

### 接口

```cpp
class Library {
public:
    static void init();            // Initialize OpenSSL (safe to call multiple times)
    static void cleanup();         // Cleanup all OpenSSL resources
    static bool is_initialized();  // Check initialization state
};
```

### 使用说明

| 方法 | 说明 |
|------|------|
| `init()` | 调用 `OPENSSL_init_ssl()` 初始化 OpenSSL。可多次调用，仅首次生效。 |
| `cleanup()` | 释放所有 OpenSSL 全局资源。调用后可再次调用 `init()` 重新初始化。 |
| `is_initialized()` | 返回当前是否已初始化。 |

### 注意事项

- 必须在程序启动时、使用任何 gtls 功能之前调用 `Library::init()`
- 必须在程序退出前调用 `Library::cleanup()` 释放资源
- 线程安全：内部通过 `std::mutex` 保护初始化状态

---

## 4. TlsConfig 配置管理

**头文件：** `#include "gtls/tls_config.h"`

`TlsConfig` 是一个结构体，包含建立 TLS 连接所需的全部参数。

### 结构定义

```cpp
struct TlsConfig {
    // --- Required fields (mTLS) ---
    std::string ca_cert_file;       // CA certificate file path
    std::string ca_cert_path;       // CA certificate directory (alternative)
    std::string cert_file;          // Client/server certificate file
    std::string cert_key_file;      // Private key file

    // --- Optional fields ---
    std::string cert_key_password;  // Private key password (default: empty)
    bool crl_check = false;         // Enable CRL checking
    std::vector<std::string> policy_oids;  // Policy OID list
    std::string cipher_list;        // TLS 1.2 cipher list
    std::string cipher_suites;      // TLS 1.3 cipher suites
    int tls_min_version = -1;       // Min TLS version (-1 = OpenSSL default)
    int tls_max_version = -1;       // Max TLS version (-1 = OpenSSL default)
    std::string dh_param_file;      // DH parameters file (server-side)
    int cache_expiry = -1;          // SSL_CTX cache expiry in seconds (-1 = no caching)

    std::string validate() const;   // Returns empty string on success
    bool operator==(const TlsConfig& other) const;
    bool operator!=(const TlsConfig& other) const;
};
```

### 验证规则

`validate()` 检查以下约束，不满足时返回错误描述字符串：

| 条件 | 错误 |
|------|------|
| `cert_file` 非空但 `cert_key_file` 为空 | 指定了证书但缺少私钥 |
| `cert_file` 非空但 `ca_cert_file` 和 `ca_cert_path` 均为空 | 指定了证书但缺少 CA |
| `cert_file` 和 `cert_key_file` 均为空 | 证书认证为必选项 |

### 使用示例

```cpp
gtls::TlsConfig config;
config.ca_cert_file  = "/etc/ssl/ca.pem";
config.cert_file     = "/etc/ssl/client.pem";
config.cert_key_file = "/etc/ssl/client-key.pem";
config.tls_min_version = TLS1_2_VERSION;
config.cipher_suites = "TLS_AES_256_GCM_SHA384";
config.cache_expiry  = 3600;  // 1 hour

std::string err = config.validate();
if (!err.empty()) {
    std::cerr << "Config error: " << err << std::endl;
}
```

### 注意事项

- `tls_min_version` / `tls_max_version` 使用 OpenSSL 版本常量（如 `TLS1_2_VERSION`、`TLS1_3_VERSION`），-1 表示使用 OpenSSL 默认值
- `cache_expiry` 设为 -1 表示不缓存 SSL_CTX，每次都重新创建
- `policy_oids` 用于证书策略验证，大多数场景可留空

---

## 5. ConfigParser / ConfigSerializer

**头文件：** `#include "gtls/config_parser.h"` / `#include "gtls/config_serializer.h"`

提供 `TlsConfig` 与键值对文本之间的互转能力。

### ConfigParser

```cpp
struct ParseResult {
    TlsConfig config;   // Parsed config (valid when error is empty)
    std::string error;   // Error message (empty on success)
    bool ok() const;     // Convenience check
};

class ConfigParser {
public:
    static ParseResult parse(const std::string& text);
};
```

### ConfigSerializer

```cpp
class ConfigSerializer {
public:
    static std::string serialize(const TlsConfig& config);
};
```

### 文本格式

```
# Comment lines start with #
ca_cert_file = /path/to/ca.pem
cert_file = /path/to/cert.pem
cert_key_file = /path/to/key.pem
crl_check = true
cipher_list = HIGH:!aNULL
tls_min_version = 771
cache_expiry = 3600
```

支持的键名：`ca_cert_file`、`ca_cert_path`、`cert_file`、`cert_key_file`、`cert_key_password`、`crl_check`、`policy_oids`、`cipher_list`、`cipher_suites`、`tls_min_version`、`tls_max_version`、`dh_param_file`、`cache_expiry`

### 往返一致性

对任意合法 `TlsConfig` 对象，序列化后再解析应得到等价对象：

```cpp
gtls::TlsConfig original = /* ... */;
std::string text = gtls::ConfigSerializer::serialize(original);
auto result = gtls::ConfigParser::parse(text);
assert(result.ok());
assert(result.config == original);
```

### 注意事项

- `ConfigSerializer` 仅输出非默认值字段，保持输出简洁
- 输出顺序确定性，保证往返一致性
- 空行和 `#` 开头的注释行在解析时被忽略

---

## 6. TlsContext — SSL 上下文管理

**头文件：** `#include "gtls/tls_context.h"`

`TlsContext` 封装 `SSL_CTX` 的生命周期管理，支持缓存、过期刷新和热重载。

### 接口

```cpp
// RAII smart pointer for SSL_CTX
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

class TlsContext {
public:
    explicit TlsContext(TlsConfig config);
    ~TlsContext();

    SSL_CTX* get_ctx();              // Get or create cached SSL_CTX (thread-safe)
    bool reload();                   // Force reload SSL_CTX (thread-safe)
    const TlsConfig& config() const; // Get underlying config
};
```

### 缓存机制

- 首次调用 `get_ctx()` 时懒创建 `SSL_CTX`
- 若 `TlsConfig::cache_expiry > 0`，在缓存过期前重复调用 `get_ctx()` 返回同一指针
- 缓存过期后，自动重新创建 `SSL_CTX`（重新加载 CA/CRL）

### 热重载

```cpp
gtls::TlsContext ctx(config);
SSL_CTX* old_ctx = ctx.get_ctx();

// After updating certificate files on disk...
bool ok = ctx.reload();
// ok == true:  new SSL_CTX created, old one freed
// ok == false: old SSL_CTX preserved, error logged
```

### 安全选项

`TlsContext` 创建的 `SSL_CTX` 自动设置以下安全选项：
- `SSL_OP_NO_TICKET` — 禁用会话票据
- 不设置 `SSL_OP_ALLOW_NO_DHE_KEX` — 确保前向保密

### 注意事项

- 不可拷贝、不可移动（内部含 `std::mutex`）
- 线程安全：所有公开方法通过互斥锁保护
- 若 `SSL_CTX` 创建失败且无缓存，`get_ctx()` 返回 `nullptr`
- 支持加密私钥：通过 `TlsConfig::cert_key_password` 提供密码

---

## 7. TlsConnection — 连接管理

**头文件：** `#include "gtls/tls_connection.h"`

`TlsConnection` 管理单个 TLS 连接的 SSL 对象生命周期，支持客户端和服务端握手。

### 接口

```cpp
enum class ConnState { Disconnected, Connecting, Connected, Failing };

class TlsConnection {
public:
    TlsConnection(TlsContext& ctx, int sock);
    ~TlsConnection();

    bool connect(int timeout_sec, const std::string& sni = "");  // Client handshake
    bool accept(int timeout_sec);                                  // Server handshake
    SSL* ssl() const;                                              // Get SSL pointer
    ConnState state() const;                                       // Get connection state
    void shutdown();                                               // Graceful shutdown
    X509* get_peer_certificate() const;                            // Get peer cert (caller owns)
    std::chrono::steady_clock::time_point connect_time() const;    // Connection timestamp
    std::mutex& mutex();                                           // Thread-safe access mutex
};
```

### 客户端连接

```cpp
int sock = /* create and connect TCP socket */;
gtls::TlsConnection conn(ctx, sock);

// Connect with 30s timeout and SNI
if (conn.connect(30, "server.example.com")) {
    // Handshake successful, conn.state() == ConnState::Connected
    // Use conn.ssl() for I/O operations
} else {
    // Handshake failed, resources already cleaned up
}
```

### 服务端接受连接

```cpp
int client_sock = accept(listen_sock, ...);
gtls::TlsConnection conn(ctx, client_sock);

if (conn.accept(30)) {
    // Client connected successfully
    X509* peer = conn.get_peer_certificate();
    // Verify peer certificate...
    if (peer) X509_free(peer);
}
```

### 关闭连接

```cpp
conn.shutdown();
// Executes: SSL_shutdown -> close(sock) -> SSL_free (via smart pointer)
// State becomes ConnState::Disconnected
```

### 注意事项

- 不可拷贝、不可移动
- 握手使用非阻塞模式 + `poll` 机制处理 `SSL_ERROR_WANT_READ/WRITE`
- 握手失败时自动清理 SSL 对象和关闭套接字
- `get_peer_certificate()` 返回的 `X509*` 由调用者负责 `X509_free()`
- 析构函数会自动调用 `shutdown()`（若仍处于连接状态）

---

## 8. TlsIO — 读写操作

**头文件：** `#include "gtls/tls_io.h"`

`TlsIO` 提供基于 `poll` 的带超时 TLS 读写操作，所有方法为静态方法。

### 接口

```cpp
class TlsIO {
public:
    static int read(SSL* ssl, unsigned char* buf, int num,
                    int timeout_sec, std::mutex* lock = nullptr);

    static int write(SSL* ssl, const void* buf, int num,
                     bool blocking = true);
};
```

### read() 返回值

| 返回值 | 含义 |
|--------|------|
| `> 0` | 成功读取的字节数 |
| `0` | 超时（在 `timeout_sec` 内无数据） |
| `-1` | 错误或连接关闭 |

### write() 返回值

| 返回值 | 含义 |
|--------|------|
| `> 0` | 写入的字节数（阻塞模式下等于 `num`） |
| `-1` | 错误（套接字错误或 SSL_write 失败） |

### 使用示例

```cpp
SSL* ssl = conn.ssl();

// Read with 10 second timeout
unsigned char buf[4096];
int n = gtls::TlsIO::read(ssl, buf, sizeof(buf), 10);
if (n > 0) {
    // Process n bytes in buf
} else if (n == 0) {
    // Timeout
} else {
    // Error or connection closed
}

// Blocking read (timeout = 0)
n = gtls::TlsIO::read(ssl, buf, sizeof(buf), 0);

// Blocking write (ensures all data is sent)
int written = gtls::TlsIO::write(ssl, data, data_len, true);

// Thread-safe read with mutex
n = gtls::TlsIO::read(ssl, buf, sizeof(buf), 10, &conn.mutex());
```

### 注意事项

- `timeout_sec = 0` 表示阻塞模式，无限等待
- 内部自动处理 `SSL_ERROR_WANT_READ/WRITE`，通过 `poll` 重试
- 收到 `SSL_ERROR_ZERO_RETURN` 时自动执行 `SSL_shutdown`
- 写操作前通过 `poll` 检测套接字错误（`POLLERR`/`POLLHUP`/`POLLNVAL`）
- `lock` 参数用于多线程环境下保护同一 SSL 对象的并发访问

---

## 9. ConnectionPool — 连接池

**头文件：** `#include "gtls/connection_pool.h"`

`ConnectionPool` 以 `TunnelKey` 为索引管理多条独立的 TLS 连接，支持连接复用、空闲清理和每目标连接数限制。

### 核心类型

```cpp
// Tunnel identifier
struct TunnelKey {
    std::string host;             // Target IP or hostname
    uint16_t port;                // Target port
    std::string tls_config_name;  // Optional config name
    bool operator==(const TunnelKey& other) const;
};

// Pool configuration
struct PoolConfig {
    int max_connections_per_target = 4;   // Max connections per TunnelKey
    int idle_timeout_sec = 600;           // Idle timeout (seconds)
    int connect_timeout_sec = 30;         // Handshake timeout (seconds)
};

// Pool statistics snapshot
struct PoolStats {
    size_t total_active;
    std::unordered_map<TunnelKey, size_t, TunnelKeyHash> per_target;
    size_t total_capacity;
};
```

### ConnectionPool 接口

```cpp
class ConnectionPool {
public:
    explicit ConnectionPool(PoolConfig config = {});
    ~ConnectionPool();

    std::shared_ptr<TlsConnection> acquire(const TunnelKey& key, TlsContext& ctx);
    void release(const TunnelKey& key, std::shared_ptr<TlsConnection> conn);
    void remove(const TunnelKey& key, std::shared_ptr<TlsConnection> conn);
    void remove_tunnel(const TunnelKey& key);
    void cleanup_idle();
    PoolStats stats() const;
    void for_each(std::function<void(const TunnelKey&, TlsConnection&)> fn);
};
```

### acquire() 策略

1. 优先复用该 `TunnelKey` 下已有的空闲连接
2. 若无空闲连接且未达上限，创建新连接
3. 若已达 `max_connections_per_target` 上限，复用最近最少使用的连接（不阻塞、不返回 `nullptr`）

### 使用示例

```cpp
gtls::PoolConfig pool_cfg;
pool_cfg.max_connections_per_target = 8;
pool_cfg.idle_timeout_sec = 300;

gtls::ConnectionPool pool(pool_cfg);

gtls::TunnelKey key{"192.168.1.100", 2083, "radius"};
auto conn = pool.acquire(key, ctx);
if (conn) {
    // Use connection for I/O
    gtls::TlsIO::write(conn->ssl(), data, len);
    pool.release(key, conn);
} else {
    // Connection creation failed
}

// Periodic cleanup
pool.cleanup_idle();

// Get statistics
auto st = pool.stats();
// st.total_active, st.per_target, st.total_capacity
```

### 注意事项

- 线程安全：所有公开方法通过内部互斥锁保护
- 锁获取顺序约定：`ConnectionPool::mutex_` → `TlsContext::mutex_` → `TlsConnection::mutex_`
- `for_each()` 回调期间持有池锁，回调应尽量简短
- 析构函数遍历所有隧道，逐一关闭所有连接
- 移除某条连接不影响其他 `TunnelKey` 下的连接（隧道隔离）

---

## 10. ProtocolAdapter — 协议适配器

**头文件：** `#include "gtls/protocol_adapter.h"`

`ProtocolAdapter` 通过回调机制实现协议无关的消息帧处理、路由决策和事件通知。

### 回调类型

```cpp
// Message framing: return >0 (complete msg len), 0 (need more), <0 (error)
using FrameCallback = std::function<int(const unsigned char* data, int len)>;

// Routing: determine target tunnel from message content
using RoutingCallback = std::function<TunnelKey(const unsigned char* data, int len)>;

// Connection events
enum class ConnEvent { Connected, Disconnected, HandshakeComplete, RekeyComplete };
using EventCallback = std::function<void(ConnEvent event, const TunnelKey& key,
                                         TlsConnection& conn)>;

// Target address resolution from message data
using ResolveCallback = std::function<TunnelKey(const unsigned char* data, int len)>;
```

### ProtocolAdapter 接口

```cpp
class ProtocolAdapter {
public:
    explicit ProtocolAdapter(const std::string& name);

    void set_frame_callback(FrameCallback cb);
    void set_routing_callback(RoutingCallback cb);
    void set_event_callback(EventCallback cb);
    void set_resolve_callback(ResolveCallback cb);

    int read_message(TlsConnection& conn, unsigned char** buf, int timeout_sec);
    int send(ConnectionPool& pool, TlsContext& ctx,
             const unsigned char* data, int len,
             TlsConnection* explicit_conn = nullptr);

    const std::string& name() const;
};
```

### read_message() 行为

| 帧回调状态 | 行为 |
|------------|------|
| 已注册 | 根据帧回调检测消息边界，返回完整协议消息 |
| 未注册 | 原始字节流模式，返回可用数据 |

返回值：`> 0` 消息字节数，`0` 超时，`-1` 错误。缓冲区由 `malloc` 分配，调用者需 `free()`。

### send() 行为

| 路由回调状态 | 行为 |
|-------------|------|
| 已注册 | 调用路由回调获取 `TunnelKey`，从连接池获取连接并发送 |
| 未注册 | 使用 `explicit_conn` 参数直接发送（此时 `explicit_conn` 不可为 `nullptr`） |

### 使用示例（RADIUS 协议适配）

```cpp
gtls::ProtocolAdapter radius_adapter("radius");

// Register RADIUS message framing (4-byte header with length field)
radius_adapter.set_frame_callback([](const unsigned char* data, int len) -> int {
    if (len < 4) return 0;  // Need more data
    int msg_len = (data[2] << 8) | data[3];
    return (len >= msg_len) ? msg_len : 0;
});

// Register routing based on RADIUS packet destination
radius_adapter.set_routing_callback([](const unsigned char* data, int len) -> gtls::TunnelKey {
    // Extract destination from RADIUS packet...
    return {"10.0.0.1", 2083, "default"};
});

// Register event handler
radius_adapter.set_event_callback([](gtls::ConnEvent event,
                                     const gtls::TunnelKey& key,
                                     gtls::TlsConnection& conn) {
    if (event == gtls::ConnEvent::Disconnected) {
        // Handle disconnection for this tunnel
    }
});

// Read a complete RADIUS message
unsigned char* msg = nullptr;
int n = radius_adapter.read_message(conn, &msg, 30);
if (n > 0) {
    // Process complete RADIUS message (n bytes in msg)
    free(msg);
}

// Send through routed tunnel
radius_adapter.send(pool, ctx, packet_data, packet_len);
```

### 注意事项

- 各 `ProtocolAdapter` 实例独立，修改一个实例的回调不影响其他实例
- 可同时创建多个适配器实例用于不同协议
- `read_message()` 返回的缓冲区由 `malloc` 分配，必须用 `free()` 释放

---

## 11. CertificateVerifier — 证书验证

**头文件：** `#include "gtls/certificate_verifier.h"`

`CertificateVerifier` 提供证书链验证、主机名检查、自定义匹配规则和热重载后的重新验证。

### 匹配规则类型

```cpp
struct CertMatchRule {
    enum Type {
        DNS_Regex,      // SAN DNS entry matched by regex
        URI_Regex,      // SAN URI entry matched by regex
        IP_Address,     // SAN IP entry matched by IP string
        RegisteredID,   // SAN registeredID matched by OID
        OtherName,      // SAN otherName matched by OID + regex
        CN_Regex        // Subject CN matched by regex
    };
    Type type;
    std::string pattern;  // Regex, IP string, or OID
    std::string oid;      // Used only for OtherName type
};

using VerifyCallback = std::function<bool(X509* cert, const std::string& hostname)>;
```

### 接口

```cpp
class CertificateVerifier {
public:
    static X509* verify_peer(SSL* ssl);                    // Basic peer verification
    static bool check_hostname(X509* cert,
                               const std::string& name,
                               bool check_cn = true);      // Hostname/IP check
    static bool match_rules(X509* cert,
                            const std::vector<CertMatchRule>& rules);  // Custom rules
    static int reverify(SSL* ssl, SSL_CTX* new_ctx);       // Re-verify against new CTX
    void set_callback(VerifyCallback cb);                   // Custom callback
    static std::string get_subject(X509* cert);             // Get subject string
};
```

### 方法说明

| 方法 | 说明 |
|------|------|
| `verify_peer()` | 检查 `SSL_get_verify_result`，成功返回对端证书（调用者负责 `X509_free`），失败返回 `nullptr` |
| `check_hostname()` | 使用 `X509_check_host()` / `X509_check_ip_asc()` 验证主机名或 IP，可选回退到 Subject CN |
| `match_rules()` | 遍历 SAN 和 Subject CN，任一规则匹配即返回 `true` |
| `reverify()` | 用新 `SSL_CTX` 的信任库重新验证对端证书，返回 1（成功）/ 0（失败）/ -1（错误） |
| `get_subject()` | 返回证书 Subject 的可读字符串 |

### 使用示例

```cpp
// After TLS handshake, verify peer certificate
X509* peer = gtls::CertificateVerifier::verify_peer(conn.ssl());
if (!peer) {
    // Verification failed
    conn.shutdown();
    return;
}

// Check hostname
if (!gtls::CertificateVerifier::check_hostname(peer, "server.example.com")) {
    X509_free(peer);
    conn.shutdown();
    return;
}

// Custom rule matching
std::vector<gtls::CertMatchRule> rules = {
    {gtls::CertMatchRule::DNS_Regex, ".*\\.example\\.com", ""},
    {gtls::CertMatchRule::IP_Address, "192.168.1.100", ""},
};
bool matched = gtls::CertificateVerifier::match_rules(peer, rules);

X509_free(peer);

// Re-verify after certificate hot-reload
int result = gtls::CertificateVerifier::reverify(conn.ssl(), ctx.get_ctx());
if (result != 1) {
    conn.shutdown();  // Certificate no longer trusted
}
```

### 注意事项

- `verify_peer()` 返回的 `X509*` 由调用者负责释放
- `match_rules()` 采用"任一匹配"语义，只要有一条规则匹配即返回 `true`
- `reverify()` 用于证书热更新场景，验证已建立连接的对端证书是否仍被新信任库信任

---

## 12. RekeyManager — 密钥轮换

**头文件：** `#include "gtls/rekey_manager.h"`

`RekeyManager` 管理 TLS 1.3 长连接的定期密钥更新。

### 接口

```cpp
class RekeyManager {
public:
    explicit RekeyManager(int interval_sec = 3600);  // Default: 1 hour
    bool check_and_rekey(TlsConnection& conn);       // Check and trigger rekey
    int interval_sec() const;                         // Get configured interval
};
```

### 使用示例

```cpp
gtls::RekeyManager rekey(3600);  // Rekey every hour

// Periodically check in your I/O loop
if (rekey.check_and_rekey(conn)) {
    // Key update was triggered (connection alive > 3600s)
} else {
    // No rekey needed yet, or error occurred
}
```

### 注意事项

- 仅适用于 TLS 1.3 连接（`SSL_key_update` 为 TLS 1.3 特性）
- 比较 `TlsConnection::connect_time()` 与当前时间判断是否需要轮换
- 轮换失败不终止连接，仅记录警告日志，下次检查时重试
- 默认间隔 3600 秒（1 小时）

---

## 13. Logger — 日志配置

**头文件：** `#include "gtls/logger.h"`

`Logger` 提供全局日志回调和 SSL 密钥日志（用于 Wireshark 调试）。

### 日志级别

```cpp
enum class LogLevel { Error, Warning, Notice, Info, Debug };
```

### 接口

```cpp
using LogCallback = std::function<void(LogLevel level, const std::string& message)>;

class Logger {
public:
    static void set_callback(LogCallback cb);              // Set log handler
    static void log(LogLevel level, const char* fmt, ...); // Log a message (printf-style)
    static void enable_keylog(const std::string& filepath); // Enable SSL keylog
    static void install_keylog_callback(SSL_CTX* ctx);      // Install on SSL_CTX
    static void disable_keylog();                            // Disable keylog
    static const char* level_to_string(LogLevel level);      // Level to string
};
```

### 使用示例

```cpp
// Register a custom log callback
gtls::Logger::set_callback([](gtls::LogLevel level, const std::string& msg) {
    std::cerr << "[" << gtls::Logger::level_to_string(level) << "] " << msg << std::endl;
});

// Log messages from library code
gtls::Logger::log(gtls::LogLevel::Info, "Connection to %s:%d established", host, port);

// Enable SSL keylog for Wireshark debugging
gtls::Logger::enable_keylog("/tmp/sslkeys.log");
gtls::Logger::install_keylog_callback(ctx.get_ctx());

// Disable when done
gtls::Logger::disable_keylog();
```

### 注意事项

- 未注册回调时，所有日志消息被静默丢弃
- 线程安全：回调和密钥日志文件均通过 `std::mutex` 保护
- `enable_keylog()` 以追加模式打开文件，输出 NSS Key Log 格式
- `install_keylog_callback()` 必须在 `enable_keylog()` 之后调用
- 密钥日志仅用于调试，生产环境应禁用

---

## 14. SelfieCache — 自连接检测

**头文件：** `#include "gtls/selfie_cache.h"`

`SelfieCache` 通过缓存 ClientHello 的 random 值检测 TLS 自连接攻击（selfie attack）。

### 接口

```cpp
class SelfieCache {
public:
    static void install(SSL_CTX* ctx);  // Install client_hello callback on SSL_CTX
    static void clear();                // Clear cached random values
};
```

### 使用示例

```cpp
// Install on server-side SSL_CTX
gtls::SelfieCache::install(ctx.get_ctx());

// The callback is automatically invoked during TLS handshake.
// If a duplicate ClientHello random is detected, the handshake is rejected.

// Periodic cache maintenance (optional)
gtls::SelfieCache::clear();
```

### 注意事项

- 仅需在服务端 `SSL_CTX` 上安装，每个 `SSL_CTX` 调用一次
- 通过 `SSL_CTX_set_client_hello_cb` 注册回调
- 检测到重复 random 值时返回 `SSL_CLIENT_HELLO_ERROR`，拒绝连接
- 线程安全：内部缓存通过 `std::mutex` 保护
- 可定期调用 `clear()` 清理缓存，防止内存无限增长
