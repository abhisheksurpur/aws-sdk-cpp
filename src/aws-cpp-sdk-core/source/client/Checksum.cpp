#include <aws/core/client/Checksum.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/crypto/Sha1.h>
#include <aws/core/utils/crypto/Sha256.h>
#include <aws/core/utils/crypto/CRC32.h>

using namespace Aws::Utils;
using namespace Aws::Utils;
using namespace Aws::Utils::Crypto;

static const char* CHECKSUM_ALLOCATION_TAG = "ChecksumAlgorithm";

AwsChecksumAlgorithm Client::ChecksumAlgorithmFromString(Aws::String& name)
{
    const Aws::Map<const char*, AwsChecksumAlgorithm> mapping{
        {"md5", AwsChecksumAlgorithm::MD5},
        {"sha1", AwsChecksumAlgorithm::SHA1},
        {"sha256", AwsChecksumAlgorithm::SHA256},
        {"crc32", AwsChecksumAlgorithm::CRC32},
        {"crc32c", AwsChecksumAlgorithm::CRC32C},
    };

    auto it = mapping.find(name.c_str());
    return it == mapping.end() ? AwsChecksumAlgorithm::NOT_SET : it->second;
}

String Client::ChecksumAlgorithmToString(AwsChecksumAlgorithm checksumAlgorithm)
{
    const Aws::Map<AwsChecksumAlgorithm, const char*> mapping{
        {AwsChecksumAlgorithm::MD5, "md5"},
        {AwsChecksumAlgorithm::SHA1, "sha1"},
        {AwsChecksumAlgorithm::SHA256, "sha256"},
        {AwsChecksumAlgorithm::CRC32, "crc32"},
        {AwsChecksumAlgorithm::CRC32C, "crc32c"},
    };

    auto it = mapping.find(checksumAlgorithm);
    return it == mapping.end() ? "NOT_SET" : it->second;
}

Crt::Optional<HashProvider> Client::ChecksumAlgorithmHashProvider(AwsChecksumAlgorithm checksumAlgorithm)
{
    const Aws::Map<AwsChecksumAlgorithm, std::function<std::shared_ptr<Hash>()>> mapping{
        {AwsChecksumAlgorithm::SHA1, [] {return Aws::MakeShared<Sha1>(CHECKSUM_ALLOCATION_TAG); }},
        {AwsChecksumAlgorithm::SHA256, [] {return Aws::MakeShared<Sha256>(CHECKSUM_ALLOCATION_TAG); }},
        {AwsChecksumAlgorithm::CRC32, [] {return Aws::MakeShared<CRC32>(CHECKSUM_ALLOCATION_TAG); }},
        {AwsChecksumAlgorithm::CRC32C, [] {return Aws::MakeShared<CRC32C>(CHECKSUM_ALLOCATION_TAG); }},
    };

    auto it = mapping.find(checksumAlgorithm);
    return it == mapping.end() ? nullptr : it->second;
}

Crt::Optional<Aws::String> Client::ChecksumAlgorithmHeader(AwsChecksumAlgorithm checksumAlgorithm)
{
    const Aws::Map<AwsChecksumAlgorithm, Aws::String> mapping{
        {AwsChecksumAlgorithm::SHA1, "x-amz-checksum-" + ChecksumAlgorithmToString(checksumAlgorithm)},
        {AwsChecksumAlgorithm::SHA256, "x-amz-checksum-" + ChecksumAlgorithmToString(checksumAlgorithm)},
        {AwsChecksumAlgorithm::CRC32, "x-amz-checksum-" + ChecksumAlgorithmToString(checksumAlgorithm)},
        {AwsChecksumAlgorithm::CRC32C, "x-amz-checksum-" + ChecksumAlgorithmToString(checksumAlgorithm)},
        {AwsChecksumAlgorithm::MD5, Aws::Http::CONTENT_MD5_HEADER},
    };

    auto it = mapping.find(checksumAlgorithm);
    return it == mapping.end() ? nullptr : it->second;
}

Crt::Optional<HashFunc> Client::ChecksumAlgorithmHashFunc(const Checksum& checksum)
{
    if (checksum.GetChecksum().has_value())
    {
        return {[&checksum](IOStream&){return checksum.GetChecksum().value();}};
    }
    const Aws::Map<AwsChecksumAlgorithm, HashFunc> mapping{
        {AwsChecksumAlgorithm::SHA1, [](IOStream& stream){return HashingUtils::Base64Encode(HashingUtils::CalculateSHA1(stream)); }},
        {AwsChecksumAlgorithm::SHA256, [](IOStream& stream){return HashingUtils::Base64Encode(HashingUtils::CalculateSHA256(stream)); }},
        {AwsChecksumAlgorithm::CRC32, [](IOStream& stream){return HashingUtils::Base64Encode(HashingUtils::CalculateCRC32(stream)); }},
        {AwsChecksumAlgorithm::CRC32C, [](IOStream& stream){return HashingUtils::Base64Encode(HashingUtils::CalculateCRC32C(stream)); }},
        {AwsChecksumAlgorithm::MD5, [](IOStream& stream){return HashingUtils::Base64Encode(HashingUtils::CalculateMD5(stream)); }},
    };
    auto it = mapping.find(checksum.GetChecksumAlgorithm());
    return it == mapping.end() ? nullptr : it->second;
}
