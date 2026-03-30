// =============================================================================
// Generic TLS Library (gtls) - Logger module
// Provides configurable logging callback and SSL keylog support for debugging.
// =============================================================================
#ifndef GTLS_LOGGER_H
#define GTLS_LOGGER_H

#include <cstdarg>
#include <functional>
#include <fstream>
#include <mutex>
#include <string>

// Forward declaration for OpenSSL types
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace gtls {

// Log severity levels, ordered from most to least severe.
enum class LogLevel {
    Error,
    Warning,
    Notice,
    Info,
    Debug
};

// Callback type for custom log handlers.
// Receives the log level and a pre-formatted message string.
using LogCallback = std::function<void(LogLevel level, const std::string& message)>;

// Static logger providing application-wide log callback and SSL keylog support.
// Thread-safe: all static state is protected by mutexes.
class Logger {
public:
    // Register a custom log callback function.
    // Pass nullptr or empty function to disable logging.
    // Thread-safe.
    static void set_callback(LogCallback cb);

    // Log a formatted message at the given level.
    // Uses printf-style format string with va_list internally.
    // If no callback is registered, the message is silently discarded.
    // Thread-safe.
    static void log(LogLevel level, const char* fmt, ...);

    // Enable SSL keylog output to the specified file path.
    // Opens the file for appending and stores the keylog callback
    // that can be installed on SSL_CTX via install_keylog_callback().
    // Used for Wireshark TLS decryption debugging (NSS Key Log Format).
    // Thread-safe.
    static void enable_keylog(const std::string& filepath);

    // Install the keylog callback on the given SSL_CTX.
    // Must be called after enable_keylog(). If keylog is not enabled,
    // this is a no-op.
    // Thread-safe.
    static void install_keylog_callback(SSL_CTX* ctx);

    // Disable keylog output and close the file.
    // Thread-safe.
    static void disable_keylog();

    // Convert LogLevel enum to a human-readable string.
    static const char* level_to_string(LogLevel level);

private:
    // Internal log implementation using va_list.
    static void log_va(LogLevel level, const char* fmt, va_list args);

    // SSL keylog callback compatible with SSL_CTX_set_keylog_callback().
    static void keylog_callback(const SSL* ssl, const char* line);

    static LogCallback callback_;
    static std::mutex callback_mutex_;

    static std::ofstream keylog_file_;
    static std::mutex keylog_mutex_;
    static bool keylog_enabled_;
};

} // namespace gtls

#endif // GTLS_LOGGER_H
