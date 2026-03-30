// =============================================================================
// Generic TLS Library (gtls) - Logger implementation
// =============================================================================

#include "gtls/logger.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include <openssl/ssl.h>

namespace gtls {

// Static member definitions
LogCallback Logger::callback_;
std::mutex Logger::callback_mutex_;

std::ofstream Logger::keylog_file_;
std::mutex Logger::keylog_mutex_;
bool Logger::keylog_enabled_ = false;

void Logger::set_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    callback_ = std::move(cb);
}

void Logger::log(LogLevel level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_va(level, fmt, args);
    va_end(args);
}

void Logger::log_va(LogLevel level, const char* fmt, va_list args) {
    // Take a snapshot of the callback under the lock to avoid
    // holding the lock during the potentially slow callback invocation.
    LogCallback cb;
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        cb = callback_;
    }

    // If no callback is registered, discard the message silently.
    if (!cb) {
        return;
    }

    // Format the message using vsnprintf.
    // First pass: determine required buffer size.
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, args_copy);
    va_end(args_copy);

    if (needed < 0) {
        // Formatting error; deliver a fallback message.
        cb(level, "[gtls] log formatting error");
        return;
    }

    // Second pass: format into a properly sized buffer.
    std::vector<char> buf(static_cast<size_t>(needed) + 1);
    std::vsnprintf(buf.data(), buf.size(), fmt, args);

    cb(level, std::string(buf.data(), static_cast<size_t>(needed)));
}

void Logger::enable_keylog(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(keylog_mutex_);

    // Close any previously opened keylog file.
    if (keylog_file_.is_open()) {
        keylog_file_.close();
    }

    keylog_file_.open(filepath, std::ios::out | std::ios::app);
    if (!keylog_file_.is_open()) {
        keylog_enabled_ = false;
        // Attempt to log the error through the log callback.
        log(LogLevel::Error, "Failed to open keylog file: %s", filepath.c_str());
        return;
    }

    keylog_enabled_ = true;
    log(LogLevel::Info, "SSL keylog enabled, writing to: %s", filepath.c_str());
}

void Logger::install_keylog_callback(SSL_CTX* ctx) {
    if (!ctx) {
        return;
    }

    std::lock_guard<std::mutex> lock(keylog_mutex_);
    if (keylog_enabled_) {
        SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    }
}

void Logger::disable_keylog() {
    std::lock_guard<std::mutex> lock(keylog_mutex_);
    keylog_enabled_ = false;
    if (keylog_file_.is_open()) {
        keylog_file_.close();
    }
}

void Logger::keylog_callback(const SSL* /*ssl*/, const char* line) {
    std::lock_guard<std::mutex> lock(keylog_mutex_);
    if (keylog_enabled_ && keylog_file_.is_open() && line) {
        keylog_file_ << line << std::endl;
    }
}

const char* Logger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::Error:   return "ERROR";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Notice:  return "NOTICE";
        case LogLevel::Info:    return "INFO";
        case LogLevel::Debug:   return "DEBUG";
        default:                return "UNKNOWN";
    }
}

} // namespace gtls
