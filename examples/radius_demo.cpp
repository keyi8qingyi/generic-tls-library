// =============================================================================
// RADIUS over TLS (RadSec) Minimal Demo
// =============================================================================
//
// 【中文说明】
// 本 Demo 演示如何使用 gtls 通用 TLS 库实现 RadSec（RADIUS over TLS）客户端。
//
// 场景描述：
//   交换机作为 RadSec 客户端，需要将 RADIUS UDP 报文通过 TLS 隧道转发到
//   两台不同的 RADIUS 服务器（Server A: 10.0.1.100:2083, Server B: 10.0.2.200:2083）。
//
// 工作流程：
//   1. 初始化 gtls 库（底层初始化 OpenSSL）
//   2. 配置 TLS 参数（CA 证书、本端证书、私钥）
//   3. 创建 TLS 上下文（SSL_CTX），用于后续 TLS 握手
//   4. 创建连接池，管理到不同 RADIUS 服务器的 TLS 隧道
//   5. 创建协议适配器，注册 RADIUS 消息帧回调和路由回调
//      - 帧回调：根据 RADIUS 报文头第 3-4 字节（Length 字段）判断消息边界
//      - 路由回调：根据报文中嵌入的目标地址信息选择对应的 TunnelKey
//   6. 构造示例 RADIUS Access-Request 报文，分别发往两台服务器
//   7. 通过 ProtocolAdapter::send() 发送报文，演示多隧道并行
//   8. 通过 ProtocolAdapter::read_message() 接收响应
//   9. 清理资源并关闭库
//
// 注意：
//   本 Demo 仅为 API 使用示例，不包含真实的 RADIUS 认证逻辑。
//   实际运行需要可达的 RADIUS 服务器和有效的 TLS 证书。
//   RadSec 标准端口为 TCP 2083（RFC 6614）。
//
// RADIUS 报文格式：
//   Code(1 byte) + Identifier(1 byte) + Length(2 bytes, big-endian)
//   + Authenticator(16 bytes) + Attributes(variable)
//   最小报文长度为 20 字节。
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "gtls/library.h"
#include "gtls/logger.h"
#include "gtls/tls_config.h"
#include "gtls/tls_context.h"
#include "gtls/connection_pool.h"
#include "gtls/protocol_adapter.h"

// RADIUS packet codes
static constexpr uint8_t RADIUS_CODE_ACCESS_REQUEST  = 1;
static constexpr uint8_t RADIUS_CODE_ACCESS_ACCEPT   = 2;
static constexpr uint8_t RADIUS_CODE_ACCESS_REJECT   = 3;

// RadSec standard port (RFC 6614)
static constexpr uint16_t RADSEC_PORT = 2083;

// Minimum RADIUS packet length (Code + ID + Length + Authenticator)
static constexpr int RADIUS_MIN_LENGTH = 20;

// RADIUS header size for length field extraction
static constexpr int RADIUS_HEADER_SIZE = 4;

// ============================================================================
// Helper: Build a sample RADIUS Access-Request packet
// ============================================================================

// Build a minimal RADIUS Access-Request packet with a User-Name attribute.
// This is a simplified construction for demonstration purposes only.
// A real implementation would include proper Authenticator computation,
// Message-Authenticator attribute, and shared secret handling.
//
// Parameters:
//   identifier  - RADIUS packet identifier (0-255)
//   username    - User-Name attribute value
//   target_tag  - Extra byte appended to help the routing callback
//                 identify the target server (demo-only trick)
//
// Returns:
//   A vector containing the raw RADIUS packet bytes.
static std::vector<uint8_t> build_access_request(uint8_t identifier,
                                                  const std::string& username,
                                                  uint8_t target_tag) {
    // User-Name attribute: Type(1) = 1, Length(1), Value(variable)
    uint8_t attr_type = 1;  // User-Name
    uint8_t attr_len  = static_cast<uint8_t>(2 + username.size());

    // Total packet length = 20 (header) + attribute length + 1 (target tag)
    uint16_t total_len = static_cast<uint16_t>(RADIUS_MIN_LENGTH + attr_len + 1);

    std::vector<uint8_t> packet(total_len, 0);

    // Code: Access-Request (1)
    packet[0] = RADIUS_CODE_ACCESS_REQUEST;

    // Identifier
    packet[1] = identifier;

    // Length (big-endian)
    packet[2] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
    packet[3] = static_cast<uint8_t>(total_len & 0xFF);

    // Authenticator: 16 bytes of zeros (placeholder for demo)
    // In a real implementation, this would be a random 16-byte value.

    // User-Name attribute starting at offset 20
    size_t offset = RADIUS_MIN_LENGTH;
    packet[offset++] = attr_type;
    packet[offset++] = attr_len;
    std::memcpy(&packet[offset], username.data(), username.size());
    offset += username.size();

    // Target tag: appended as the last byte for routing demo purposes.
    // In a real system, routing would be based on NAS-IP-Address or
    // other RADIUS attributes, not an extra tag byte.
    packet[offset] = target_tag;

    return packet;
}

// ============================================================================
// Helper: Get a human-readable name for a RADIUS code
// ============================================================================
static const char* radius_code_name(uint8_t code) {
    switch (code) {
        case RADIUS_CODE_ACCESS_REQUEST: return "Access-Request";
        case RADIUS_CODE_ACCESS_ACCEPT:  return "Access-Accept";
        case RADIUS_CODE_ACCESS_REJECT:  return "Access-Reject";
        default:                         return "Unknown";
    }
}

// ============================================================================
// Main: RadSec client demo
// ============================================================================
int main() {
    std::printf("=== RadSec (RADIUS over TLS) Demo ===\n\n");

    // -----------------------------------------------------------------------
    // Step 1: Initialize the gtls library
    // 【初始化 gtls 库，底层调用 OPENSSL_init_ssl() 完成 OpenSSL 初始化】
    // -----------------------------------------------------------------------
    std::printf("[Step 1] Initializing gtls library...\n");
    gtls::Library::init();

    // Register a simple log callback to print messages to stdout.
    // In production, this would integrate with the switch's syslog facility.
    gtls::Logger::set_callback([](gtls::LogLevel level, const std::string& msg) {
        std::printf("  [%s] %s\n", gtls::Logger::level_to_string(level), msg.c_str());
    });

    std::printf("  Library initialized.\n\n");

    // -----------------------------------------------------------------------
    // Step 2: Configure TLS parameters
    // 【配置 TLS 参数：CA 证书用于验证服务器身份，本端证书和私钥用于 mTLS 双向认证】
    // -----------------------------------------------------------------------
    std::printf("[Step 2] Configuring TLS...\n");

    gtls::TlsConfig tls_cfg;
    tls_cfg.ca_cert_file   = "/etc/raddb/certs/ca.pem";       // CA certificate for server verification
    tls_cfg.cert_file      = "/etc/raddb/certs/client.pem";    // Client certificate for mTLS
    tls_cfg.cert_key_file  = "/etc/raddb/certs/client.key";    // Client private key
    tls_cfg.tls_min_version = TLS1_2_VERSION;                  // Minimum TLS 1.2
    tls_cfg.tls_max_version = TLS1_3_VERSION;                  // Maximum TLS 1.3
    tls_cfg.cache_expiry    = 3600;                            // SSL_CTX cache expiry: 1 hour

    // Validate the configuration before proceeding.
    std::string validation_error = tls_cfg.validate();
    if (!validation_error.empty()) {
        std::fprintf(stderr, "  TLS config validation failed: %s\n", validation_error.c_str());
        gtls::Library::cleanup();
        return 1;
    }
    std::printf("  TLS configuration validated successfully.\n\n");

    // -----------------------------------------------------------------------
    // Step 3: Create TLS context (SSL_CTX)
    // 【创建 TLS 上下文，内部懒加载 SSL_CTX，支持缓存和热更新】
    // -----------------------------------------------------------------------
    std::printf("[Step 3] Creating TLS context...\n");

    gtls::TlsContext tls_ctx(tls_cfg);

    // The SSL_CTX is lazily created on first get_ctx() call.
    // In a real application, you might call get_ctx() here to verify
    // that certificates load correctly before entering the main loop.
    std::printf("  TLS context created (SSL_CTX will be lazily initialized).\n\n");

    // -----------------------------------------------------------------------
    // Step 4: Create connection pool
    // 【创建连接池，管理到不同 RADIUS 服务器的 TLS 隧道连接】
    // -----------------------------------------------------------------------
    std::printf("[Step 4] Creating connection pool...\n");

    gtls::PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = 2;   // Up to 2 connections per RADIUS server
    pool_cfg.idle_timeout_sec           = 300; // Close idle connections after 5 minutes
    pool_cfg.connect_timeout_sec        = 10;  // 10-second handshake timeout

    gtls::ConnectionPool pool(pool_cfg);
    std::printf("  Connection pool created (max %d conns/target, idle timeout %ds).\n\n",
                pool_cfg.max_connections_per_target, pool_cfg.idle_timeout_sec);

    // -----------------------------------------------------------------------
    // Step 5: Create protocol adapter with RADIUS framing and routing
    // 【创建协议适配器，注册 RADIUS 帧回调和路由回调】
    // -----------------------------------------------------------------------
    std::printf("[Step 5] Setting up RADIUS protocol adapter...\n");

    gtls::ProtocolAdapter adapter("radius");

    // --- 5a: Register RADIUS frame callback ---
    // The frame callback inspects raw bytes to determine complete message length.
    // RADIUS header: Code(1) + ID(1) + Length(2, big-endian) + Authenticator(16)
    // The Length field at bytes [2..3] gives the total packet length.
    adapter.set_frame_callback([](const unsigned char* data, int len) -> int {
        // Need at least 4 bytes to read the Length field
        if (len < RADIUS_HEADER_SIZE) {
            return 0;  // More data needed
        }

        // Extract the Length field (big-endian, bytes 2-3)
        int pkt_len = (static_cast<int>(data[2]) << 8) | static_cast<int>(data[3]);

        // Validate: RADIUS packets must be at least 20 bytes
        if (pkt_len < RADIUS_MIN_LENGTH) {
            return -1;  // Framing error: invalid length
        }

        // Check if we have received the complete packet
        if (len >= pkt_len) {
            return pkt_len;  // Complete message available
        }

        return 0;  // More data needed
    });
    std::printf("  RADIUS frame callback registered (length-delimited framing).\n");

    // --- 5b: Register routing callback ---
    // The routing callback determines which RADIUS server to send the packet to.
    // In this demo, we use the last byte of the packet as a target tag:
    //   tag == 1 -> Server A (10.0.1.100:2083)
    //   tag == 2 -> Server B (10.0.2.200:2083)
    //
    // In a real implementation, routing would be based on RADIUS attributes
    // such as NAS-IP-Address, Realm, or a configured routing table.
    adapter.set_routing_callback([](const unsigned char* data, int len) -> gtls::TunnelKey {
        // Read the target tag from the last byte
        uint8_t tag = (len > 0) ? data[len - 1] : 0;

        gtls::TunnelKey key;
        key.port = RADSEC_PORT;
        key.tls_config_name = "radsec";

        if (tag == 2) {
            key.host = "10.0.2.200";  // RADIUS Server B
        } else {
            key.host = "10.0.1.100";  // RADIUS Server A (default)
        }

        return key;
    });
    std::printf("  Routing callback registered (tag-based server selection).\n");

    // --- 5c: Register connection event callback (optional) ---
    // Receive notifications when connections are established or lost.
    adapter.set_event_callback([](gtls::ConnEvent event,
                                  const gtls::TunnelKey& key,
                                  gtls::TlsConnection& /*conn*/) {
        const char* event_name = "Unknown";
        switch (event) {
            case gtls::ConnEvent::Connected:         event_name = "Connected";         break;
            case gtls::ConnEvent::Disconnected:      event_name = "Disconnected";      break;
            case gtls::ConnEvent::HandshakeComplete: event_name = "HandshakeComplete"; break;
            case gtls::ConnEvent::RekeyComplete:     event_name = "RekeyComplete";     break;
        }
        std::printf("  [Event] %s -> %s:%u\n", event_name, key.host.c_str(), key.port);
    });
    std::printf("  Event callback registered.\n\n");

    // -----------------------------------------------------------------------
    // Step 6: Build sample RADIUS Access-Request packets
    // 【构造两个示例 RADIUS Access-Request 报文，分别发往不同的服务器】
    // -----------------------------------------------------------------------
    std::printf("[Step 6] Building sample RADIUS packets...\n");

    // Packet 1: Access-Request for user "alice" -> Server A (tag=1)
    std::vector<uint8_t> pkt_alice = build_access_request(
        0x01,       // Identifier
        "alice",    // User-Name
        1           // Target tag -> Server A
    );
    std::printf("  Packet 1: %s (ID=0x01, user=alice, target=ServerA, %zu bytes)\n",
                radius_code_name(pkt_alice[0]), pkt_alice.size());

    // Packet 2: Access-Request for user "bob" -> Server B (tag=2)
    std::vector<uint8_t> pkt_bob = build_access_request(
        0x02,       // Identifier
        "bob",      // User-Name
        2           // Target tag -> Server B
    );
    std::printf("  Packet 2: %s (ID=0x02, user=bob, target=ServerB, %zu bytes)\n\n",
                radius_code_name(pkt_bob[0]), pkt_bob.size());

    // -----------------------------------------------------------------------
    // Step 7: Send packets via adapter (multi-tunnel parallel routing)
    // 【通过协议适配器发送报文，路由回调自动选择目标隧道】
    // -----------------------------------------------------------------------
    std::printf("[Step 7] Sending RADIUS packets through TLS tunnels...\n");

    // Send packet 1 to Server A.
    // The routing callback reads tag=1 and returns TunnelKey{10.0.1.100, 2083}.
    // The connection pool acquires (or creates) a TLS connection to Server A.
    int sent_alice = adapter.send(pool, tls_ctx,
                                  pkt_alice.data(),
                                  static_cast<int>(pkt_alice.size()));
    if (sent_alice > 0) {
        std::printf("  Sent %d bytes to Server A (10.0.1.100:%u)\n", sent_alice, RADSEC_PORT);
    } else {
        std::printf("  Failed to send to Server A (error=%d)\n", sent_alice);
        std::printf("  (This is expected in demo mode without real servers)\n");
    }

    // Send packet 2 to Server B.
    // The routing callback reads tag=2 and returns TunnelKey{10.0.2.200, 2083}.
    // A separate TLS tunnel is established to Server B.
    int sent_bob = adapter.send(pool, tls_ctx,
                                pkt_bob.data(),
                                static_cast<int>(pkt_bob.size()));
    if (sent_bob > 0) {
        std::printf("  Sent %d bytes to Server B (10.0.2.200:%u)\n", sent_bob, RADSEC_PORT);
    } else {
        std::printf("  Failed to send to Server B (error=%d)\n", sent_bob);
        std::printf("  (This is expected in demo mode without real servers)\n");
    }
    std::printf("\n");

    // -----------------------------------------------------------------------
    // Step 8: Read responses (demonstration only)
    // 【接收响应报文（仅演示 API 调用方式，实际需要已建立的连接）】
    // -----------------------------------------------------------------------
    std::printf("[Step 8] Reading responses (demo placeholder)...\n");

    // In a real application, you would acquire a connection from the pool
    // and call read_message() on it. The frame callback ensures that only
    // complete RADIUS packets are returned.
    //
    // Example (pseudo-code for illustration):
    //
    //   gtls::TunnelKey server_a_key{"10.0.1.100", RADSEC_PORT, "radsec"};
    //   auto conn = pool.acquire(server_a_key, tls_ctx);
    //   if (conn) {
    //       unsigned char* resp_buf = nullptr;
    //       int resp_len = adapter.read_message(*conn, &resp_buf, 5 /* timeout */);
    //       if (resp_len > 0) {
    //           printf("Received %s (ID=0x%02x, %d bytes)\n",
    //                  radius_code_name(resp_buf[0]), resp_buf[1], resp_len);
    //           free(resp_buf);
    //       }
    //       pool.release(server_a_key, conn);
    //   }
    //
    std::printf("  (Skipped: no real RADIUS servers available in demo mode)\n\n");

    // -----------------------------------------------------------------------
    // Step 9: Display pool statistics and cleanup
    // 【显示连接池统计信息，清理资源】
    // -----------------------------------------------------------------------
    std::printf("[Step 9] Pool statistics and cleanup...\n");

    // Display connection pool statistics
    gtls::PoolStats stats = pool.stats();
    std::printf("  Total active connections: %zu\n", stats.total_active);
    for (const auto& [key, count] : stats.per_target) {
        std::printf("    %s:%u (%s): %zu connection(s)\n",
                    key.host.c_str(), key.port, key.tls_config_name.c_str(), count);
    }

    // Clean up idle connections
    pool.cleanup_idle();
    std::printf("  Idle connections cleaned up.\n");

    // Library cleanup: releases all OpenSSL resources
    gtls::Library::cleanup();
    std::printf("  Library cleaned up.\n\n");

    std::printf("=== Demo complete ===\n");
    return 0;
}
