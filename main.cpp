#include "src/app/processes/ProcessManagement.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace {

bool parseAction(const std::string& value, Action& action) {
    if (value == "encrypt") {
        action = Action::Encrypt;
        return true;
    }
    if (value == "decrypt") {
        action = Action::Decrypt;
        return true;
    }
    return false;
}

bool shouldProcess(const fs::path& path, Action action) {
    if (path.extension() == ".tmp" || path.extension() == ".decrypted") {
        return false;
    }
    const bool isEncrypted = path.extension() == ".cafe";
    return action == Action::Encrypt ? !isEncrypted : isEncrypted;
}

class TerminalEchoGuard {
public:
    TerminalEchoGuard() {
        if (!isatty(STDIN_FILENO)) {
            return;
        }
        if (tcgetattr(STDIN_FILENO, &original_) != 0) {
            throw std::runtime_error("Unable to read terminal settings");
        }

        struct termios silent = original_;
        silent.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent) != 0) {
            throw std::runtime_error("Unable to disable terminal echo");
        }
        active_ = true;
    }

    TerminalEchoGuard(const TerminalEchoGuard&) = delete;
    TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

    ~TerminalEchoGuard() {
        if (active_) {
            tcsetattr(STDIN_FILENO, TCSANOW, &original_);
        }
    }

    bool active() const { return active_; }

    void restore() {
        if (!active_) {
            return;
        }
        if (tcsetattr(STDIN_FILENO, TCSANOW, &original_) != 0) {
            throw std::runtime_error("Unable to restore terminal echo");
        }
        active_ = false;
    }

private:
    struct termios original_ {};
    bool active_ = false;
};

std::string readPassphrase() {
    if (const char* value = std::getenv("CAFE_PASSPHRASE"); value != nullptr) {
        return value;
    }

    TerminalEchoGuard terminalEcho;
    std::string passphrase;
    std::cerr << "Enter a passphrase: ";
    std::getline(std::cin, passphrase);

    if (terminalEcho.active()) {
        terminalEcho.restore();
        std::cerr << '\n';  // print newline the user's Return key did not echo
    }

    return passphrase;
}

void printUsage() {
    std::cerr << "Usage: encrypt_decrypt <encrypt|decrypt> <path>\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printUsage();
        return 2;
    }

    Action action;
    if (!parseAction(argv[1], action)) {
        std::cerr << "Action must be encrypt or decrypt\n";
        return 2;
    }

    const fs::path target = argv[2];
    if (!fs::exists(target)) {
        std::cerr << "Path does not exist: " << target << '\n';
        return 2;
    }

    std::shared_ptr<Passphrase> passphrase;
    try {
        passphrase = std::make_shared<Passphrase>(readPassphrase());
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
    if (passphrase->value().empty()) {
        std::cerr << "A non-empty passphrase is required\n";
        return 2;
    }

    std::vector<fs::path> files;
    if (fs::is_regular_file(target)) {
        if (shouldProcess(target, action)) {
            files.push_back(target);
        }
    } else if (!fs::is_directory(target)) {
        std::cerr << "Path is neither a regular file nor a directory: " << target << '\n';
        return 2;
    }

    std::error_code error;
    if (fs::is_directory(target)) {
        for (fs::recursive_directory_iterator iterator(target, fs::directory_options::skip_permission_denied, error), end;
             iterator != end;
             iterator.increment(error)) {
            if (error) {
                std::cerr << "Skipping inaccessible path: " << error.message() << '\n';
                error.clear();
                continue;
            }
            if (iterator->is_regular_file(error) && !error && shouldProcess(iterator->path(), action)) {
                files.push_back(iterator->path());
            }
            error.clear();
        }
    }

    if (files.empty()) {
        std::cout << "No matching files found.\n";
        return 0;
    }

    const unsigned int detectedWorkers = std::thread::hardware_concurrency();
    const std::size_t workerCount = std::max(1U, detectedWorkers);
    ProcessManagement processManagement(workerCount);
    for (const fs::path& file : files) {
        processManagement.submitToQueue({file, action, passphrase});
    }

    const std::vector<TaskResult> results = processManagement.executeTasks();
    std::size_t failures = 0;
    for (const TaskResult& result : results) {
        std::cout << (result.success ? "OK" : "ERROR") << " " << result.inputPath << ": " << result.message;
        if (result.success) {
            std::cout << " -> " << result.outputPath;
        }
        std::cout << '\n';
        failures += result.success ? 0 : 1;
    }

    std::cout << "Completed " << results.size() << " file(s) with " << failures << " failure(s) using " << workerCount << " worker(s).\n";
    return failures == 0 ? 0 : 1;
}
