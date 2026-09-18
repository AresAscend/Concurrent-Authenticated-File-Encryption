#include "Cryption.hpp"

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <Security/Security.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <unistd.h>
#include <utility>

namespace {

constexpr std::array<unsigned char, 8> kMagic = {'C', 'A', 'F', 'E', ' ', ' ', ' ', ' '};
constexpr unsigned char kVersion = 1;
constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kIvSize = 16;
constexpr std::size_t kEncryptionKeySize = 32;
constexpr std::size_t kMacKeySize = 32;
constexpr std::size_t kMacSize = 32;
constexpr std::size_t kHeaderSize = kMagic.size() + 1 + kSaltSize + kIvSize;
constexpr std::size_t kBufferSize = 64 * 1024;
constexpr unsigned int kPbkdfIterations = 200000;

using Header = std::array<unsigned char, kHeaderSize>;

class TemporaryPath {
public:
    explicit TemporaryPath(std::filesystem::path path) : path_(std::move(path)) {}

    TemporaryPath(const TemporaryPath&) = delete;
    TemporaryPath& operator=(const TemporaryPath&) = delete;

    ~TemporaryPath() {
        if (created_) {
            std::error_code ignored;
            std::filesystem::remove(path_, ignored);
        }
    }

    const std::filesystem::path& path() const { return path_; }
    void markCreated() { created_ = true; }
    void release() { created_ = false; }

private:
    std::filesystem::path path_;
    bool created_ = false;
};
struct KeyMaterial {
    std::array<unsigned char, kEncryptionKeySize + kMacKeySize> bytes{};

    KeyMaterial() = default;
    KeyMaterial(const KeyMaterial&) = delete;
    KeyMaterial& operator=(const KeyMaterial&) = delete;
    KeyMaterial(KeyMaterial&&) = default;
    KeyMaterial& operator=(KeyMaterial&&) = default;

    ~KeyMaterial() {
        volatile unsigned char* keyBytes = bytes.data();
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            keyBytes[index] = 0;
        }
    }
};

struct CryptorDeleter {
    void operator()(CCCryptorRef cryptor) const {
        if (cryptor != nullptr) {
            CCCryptorRelease(cryptor);
        }
    }
};

using CryptorHandle = std::unique_ptr<std::remove_pointer<CCCryptorRef>::type, CryptorDeleter>;

std::filesystem::path outputPathFor(const Task& task) {
    if (task.action == Action::Encrypt) {
        return task.inputPath.string() + ".cafe";
    }

    std::filesystem::path output = task.inputPath;
    output.replace_extension();
    return output.string() + ".decrypted";
}

Header makeHeader() {
    Header header{};
    std::copy(kMagic.begin(), kMagic.end(), header.begin());
    header[kMagic.size()] = kVersion;
    if (SecRandomCopyBytes(kSecRandomDefault, kSaltSize + kIvSize, header.data() + kMagic.size() + 1) != errSecSuccess) {
        throw std::runtime_error("Unable to generate cryptographic randomness");
    }
    return header;
}

void validateHeader(const Header& header) {
    if (!std::equal(kMagic.begin(), kMagic.end(), header.begin()) || header[kMagic.size()] != kVersion) {
        throw std::runtime_error("Unsupported or invalid CAFE file format");
    }
}

KeyMaterial deriveKeys(const Passphrase& passphrase, const Header& header) {
    if (passphrase.value().empty()) {
        throw std::runtime_error("A non-empty passphrase is required");
    }

    KeyMaterial keys{};
    const unsigned char* salt = header.data() + kMagic.size() + 1;
    const int status = CCKeyDerivationPBKDF(
        kCCPBKDF2,
        passphrase.value().data(),
        passphrase.value().size(),
        salt,
        kSaltSize,
        kCCPRFHmacAlgSHA256,
        kPbkdfIterations,
        keys.bytes.data(),
        keys.bytes.size());
    if (status != kCCSuccess) {
        throw std::runtime_error("Unable to derive encryption keys");
    }
    return keys;
}

CryptorHandle makeCryptor(CCOperation operation, const KeyMaterial& keys, const Header& header) {
    CCCryptorRef rawCryptor = nullptr;
    const unsigned char* iv = header.data() + kMagic.size() + 1 + kSaltSize;
    const CCCryptorStatus status = CCCryptorCreateWithMode(
        operation,
        kCCModeCTR,
        kCCAlgorithmAES,
        ccNoPadding,
        iv,
        keys.bytes.data(),
        kEncryptionKeySize,
        nullptr,
        0,
        0,
        kCCModeOptionCTR_BE,
        &rawCryptor);
    if (status != kCCSuccess) {
        throw std::runtime_error("Unable to initialize AES-256-CTR");
    }
    return CryptorHandle(rawCryptor);
}

bool constantTimeEqual(const std::array<unsigned char, kMacSize>& left, const std::array<unsigned char, kMacSize>& right) {
    unsigned char difference = 0;
    for (std::size_t index = 0; index < kMacSize; ++index) {
        difference |= static_cast<unsigned char>(left[index] ^ right[index]);
    }
    return difference == 0;
}

void writeBytes(std::ofstream& output, const unsigned char* bytes, std::size_t count) {
    output.write(reinterpret_cast<const char*>(bytes), static_cast<std::streamsize>(count));
    if (!output) {
        throw std::runtime_error("Failed while writing output file");
    }
}

std::ofstream createPrivateTemporaryFile(const std::filesystem::path& temporaryPath) {
    const int descriptor = open(temporaryPath.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        throw std::runtime_error("Unable to create private temporary output file");
    }
    if (close(descriptor) != 0) {
        std::error_code ignored;
        std::filesystem::remove(temporaryPath, ignored);
        throw std::runtime_error("Unable to close private temporary output file");
    }

    std::ofstream output(temporaryPath, std::ios::binary | std::ios::trunc);
    if (!output) {
        std::filesystem::remove(temporaryPath);
        throw std::runtime_error("Unable to open temporary output file");
    }
    return output;
}

void copySourcePermissions(const std::filesystem::path& sourcePath, const std::filesystem::path& outputPath) {
    std::error_code error;
    const std::filesystem::perms permissions = std::filesystem::status(sourcePath, error).permissions();
    if (error) {
        throw std::runtime_error("Unable to read source permissions");
    }
    std::filesystem::permissions(outputPath, permissions, std::filesystem::perm_options::replace, error);
    if (error) {
        throw std::runtime_error("Unable to apply source permissions to output");
    }
}

bool publishTemporaryFile(const std::filesystem::path& temporaryPath, const std::filesystem::path& outputPath) {
    // link() creates the destination atomically and fails with EEXIST instead of
    // replacing it. Both paths are in the same directory and therefore on the same filesystem.
    if (link(temporaryPath.c_str(), outputPath.c_str()) != 0) {
        if (errno == EEXIST) {
            throw std::runtime_error("refusing to overwrite existing output");
        }
        throw std::runtime_error(std::string("Unable to publish output file: ") + std::strerror(errno));
    }

    // The output is fully published at outputPath. A failure to remove the now-redundant
    // temporary hard-link does not invalidate it. Leave the RAII guard active so it can
    // retry cleanup at scope exit; a missing path is also a successful cleanup.
    std::error_code error;
    std::filesystem::remove(temporaryPath, error);
    return !error;
}

void transform(
    std::ifstream& input,
    std::ofstream& output,
    CCCryptorRef cryptor,
    CCHmacContext* mac,
    std::uintmax_t bytesToRead,
    bool authenticateOutput) {
    std::array<unsigned char, kBufferSize> inputBuffer{};
    std::array<unsigned char, kBufferSize + 16> outputBuffer{};

    while (bytesToRead > 0) {
        const std::size_t requested = static_cast<std::size_t>(std::min<std::uintmax_t>(bytesToRead, inputBuffer.size()));
        input.read(reinterpret_cast<char*>(inputBuffer.data()), static_cast<std::streamsize>(requested));
        if (input.gcount() != static_cast<std::streamsize>(requested)) {
            throw std::runtime_error("Input file ended unexpectedly");
        }
        if (mac != nullptr && !authenticateOutput) {
            CCHmacUpdate(mac, inputBuffer.data(), requested);
        }

        std::size_t outputCount = 0;
        if (CCCryptorUpdate(cryptor, inputBuffer.data(), requested, outputBuffer.data(), outputBuffer.size(), &outputCount) != kCCSuccess) {
            throw std::runtime_error("AES transformation failed");
        }
        if (mac != nullptr && authenticateOutput) {
            CCHmacUpdate(mac, outputBuffer.data(), outputCount);
        }
        writeBytes(output, outputBuffer.data(), outputCount);
        bytesToRead -= requested;
    }
}

std::array<unsigned char, kMacSize> authenticateAndStageCiphertext(
    std::ifstream& input,
    const Header& header,
    const KeyMaterial& keys,
    std::uintmax_t ciphertextSize,
    std::ofstream& stagedCiphertext) {
    input.clear();
    input.seekg(static_cast<std::streamoff>(kHeaderSize));
    if (!input) {
        throw std::runtime_error("Unable to seek encrypted file");
    }

    CCHmacContext mac;
    CCHmacInit(&mac, kCCHmacAlgSHA256, keys.bytes.data() + kEncryptionKeySize, kMacKeySize);
    CCHmacUpdate(&mac, header.data(), header.size());
    std::array<unsigned char, kBufferSize> buffer{};
    while (ciphertextSize > 0) {
        const std::size_t requested = static_cast<std::size_t>(std::min<std::uintmax_t>(ciphertextSize, buffer.size()));
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(requested));
        if (input.gcount() != static_cast<std::streamsize>(requested)) {
            throw std::runtime_error("Encrypted file ended unexpectedly");
        }
        CCHmacUpdate(&mac, buffer.data(), requested);
        writeBytes(stagedCiphertext, buffer.data(), requested);
        ciphertextSize -= requested;
    }

    std::array<unsigned char, kMacSize> tag{};
    CCHmacFinal(&mac, tag.data());
    return tag;
}

TaskResult encryptFile(const Task& task, const std::filesystem::path& outputPath) {
    Header header = makeHeader();
    KeyMaterial keys = deriveKeys(*task.passphrase, header);
    CryptorHandle cryptor = makeCryptor(kCCEncrypt, keys, header);
    std::ifstream input(task.inputPath, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open input file");
    }
    TemporaryPath temporaryPath(outputPath.string() + ".tmp");
    std::ofstream output = createPrivateTemporaryFile(temporaryPath.path());
    temporaryPath.markCreated();

    CCHmacContext mac;
    CCHmacInit(&mac, kCCHmacAlgSHA256, keys.bytes.data() + kEncryptionKeySize, kMacKeySize);
    CCHmacUpdate(&mac, header.data(), header.size());
    writeBytes(output, header.data(), header.size());
    transform(input, output, cryptor.get(), &mac, std::filesystem::file_size(task.inputPath), true);

    std::array<unsigned char, kMacSize> tag{};
    CCHmacFinal(&mac, tag.data());
    writeBytes(output, tag.data(), tag.size());
    output.close();
    if (!output) {
        throw std::runtime_error("Failed to flush encrypted output file");
    }
    copySourcePermissions(task.inputPath, temporaryPath.path());
    if (publishTemporaryFile(temporaryPath.path(), outputPath)) {
        temporaryPath.release();
    }
    return {task.inputPath, outputPath, true, "encrypted"};
}

TaskResult decryptFile(const Task& task, const std::filesystem::path& outputPath) {
    const std::uintmax_t inputSize = std::filesystem::file_size(task.inputPath);
    if (inputSize < kHeaderSize + kMacSize) {
        throw std::runtime_error("Encrypted file is too small");
    }

    std::ifstream input(task.inputPath, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open encrypted file");
    }
    Header header{};
    input.read(reinterpret_cast<char*>(header.data()), header.size());
    if (input.gcount() != static_cast<std::streamsize>(header.size())) {
        throw std::runtime_error("Unable to read encrypted file header");
    }
    validateHeader(header);
    KeyMaterial keys = deriveKeys(*task.passphrase, header);
    CryptorHandle cryptor = makeCryptor(kCCDecrypt, keys, header);

    const std::uintmax_t ciphertextSize = inputSize - kHeaderSize - kMacSize;
    input.seekg(static_cast<std::streamoff>(kHeaderSize + ciphertextSize));
    std::array<unsigned char, kMacSize> expectedTag{};
    input.read(reinterpret_cast<char*>(expectedTag.data()), expectedTag.size());
    if (input.gcount() != static_cast<std::streamsize>(expectedTag.size())) {
        throw std::runtime_error("Unable to read authentication tag");
    }
    // Authenticate a private ciphertext snapshot before creating the plaintext
    // temporary file.  Decrypting the original path after authentication would
    // leave a time-of-check/time-of-use window for a concurrent file writer.
    TemporaryPath stagedPath(outputPath.string() + ".verify.tmp");
    std::ofstream stagedCiphertext = createPrivateTemporaryFile(stagedPath.path());
    stagedPath.markCreated();
    const std::array<unsigned char, kMacSize> actualTag =
        authenticateAndStageCiphertext(input, header, keys, ciphertextSize, stagedCiphertext);
    stagedCiphertext.close();
    if (!stagedCiphertext) {
        throw std::runtime_error("Failed to flush verified ciphertext snapshot");
    }
    if (!constantTimeEqual(actualTag, expectedTag)) {
        throw std::runtime_error("Authentication failed: incorrect passphrase or modified file");
    }

    std::ifstream verifiedCiphertext(stagedPath.path(), std::ios::binary);
    if (!verifiedCiphertext) {
        throw std::runtime_error("Unable to open verified ciphertext snapshot");
    }
    TemporaryPath temporaryPath(outputPath.string() + ".tmp");
    std::ofstream output = createPrivateTemporaryFile(temporaryPath.path());
    temporaryPath.markCreated();
    transform(verifiedCiphertext, output, cryptor.get(), nullptr, ciphertextSize, false);
    output.close();
    if (!output) {
        throw std::runtime_error("Failed to flush decrypted output file");
    }
    copySourcePermissions(task.inputPath, temporaryPath.path());
    if (publishTemporaryFile(temporaryPath.path(), outputPath)) {
        temporaryPath.release();
    }
    return {task.inputPath, outputPath, true, "decrypted"};
}

}  // namespace

TaskResult processFile(const Task& task) {
    const std::filesystem::path outputPath = outputPathFor(task);
    try {
        if (std::filesystem::exists(outputPath)) {
            return {task.inputPath, outputPath, false, "refusing to overwrite existing output"};
        }
        return task.action == Action::Encrypt ? encryptFile(task, outputPath) : decryptFile(task, outputPath);
    } catch (const std::exception& error) {
        return {task.inputPath, outputPath, false, error.what()};
    }
}
