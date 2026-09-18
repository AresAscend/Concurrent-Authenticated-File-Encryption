#ifndef TASK_HPP
#define TASK_HPP

#include <filesystem>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>

class Passphrase {
public:
    explicit Passphrase(std::string value) : value_(std::move(value)) {}
    Passphrase(const Passphrase&) = delete;
    Passphrase& operator=(const Passphrase&) = delete;

    ~Passphrase() {
        volatile char* bytes = value_.empty() ? nullptr : value_.data();
        for (std::size_t index = 0; bytes != nullptr && index < value_.size(); ++index) {
            bytes[index] = 0;
        }
    }

    const std::string& value() const { return value_; }

private:
    std::string value_;
};

enum class Action {
    Encrypt,
    Decrypt,
};

struct Task {
    std::filesystem::path inputPath;
    Action action;
    std::shared_ptr<const Passphrase> passphrase;
};

struct TaskResult {
    std::filesystem::path inputPath;
    std::filesystem::path outputPath;
    bool success;
    std::string message;
};

#endif
