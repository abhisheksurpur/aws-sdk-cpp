/**
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#pragma once

#include <aws/core/Core_EXPORTS.h>
#include <aws/crt/Optional.h>
#include <aws/core/utils/crypto/Hash.h>

namespace Aws
{
    namespace Client
    {
        /**
         * List of supported checksums in the sdk.
         */
        enum class AwsChecksumAlgorithm
        {
            MD5,
            SHA1,
            SHA256,
            CRC32,
            CRC32C,
            NOT_SET,
        };

        AWS_CORE_API AwsChecksumAlgorithm ChecksumAlgorithmFromString(Aws::String& name);

        AWS_CORE_API String ChecksumAlgorithmToString(AwsChecksumAlgorithm checksumAlgorithm);

        using HashProvider = std::function<std::shared_ptr<Utils::Crypto::Hash>()>;
        AWS_CORE_API Crt::Optional<HashProvider> ChecksumAlgorithmHashProvider(AwsChecksumAlgorithm checksumAlgorithm);

        AWS_CORE_API Crt::Optional<Aws::String> ChecksumAlgorithmHeader(AwsChecksumAlgorithm checksumAlgorithm);

        /**
         * Class representing supported checksum algorithms in the sdk, alongside a optionallay
         * precalulated checksum
         */
        class Checksum
        {
        public:
            Checksum() = default;

            explicit Checksum(AwsChecksumAlgorithm checksumAlgorithm)
                : checksumAlgorithm_(checksumAlgorithm)
            {
            }

            explicit Checksum(AwsChecksumAlgorithm checksumAlgorithm, const Aws::Crt::Optional<String>& checksum)
                : checksumAlgorithm_(checksumAlgorithm), checksum_(checksum)
            {
            }


            Checksum(const Checksum& other) = delete;
            Checksum(Checksum&& other) noexcept = default;
            Checksum& operator=(const Checksum& other) = delete;
            Checksum& operator=(Checksum&& other) noexcept = default;

            AwsChecksumAlgorithm GetChecksumAlgorithm() const
            {
                return checksumAlgorithm_;
            }

            Crt::Optional<String> GetChecksum() const
            {
                return checksum_;
            }

        private:
            AwsChecksumAlgorithm checksumAlgorithm_ = AwsChecksumAlgorithm::NOT_SET;
            Crt::Optional<String> checksum_;
        };

        using HashFunc = std::function<String (Aws::IOStream&)>;
        AWS_CORE_API Crt::Optional<HashFunc> ChecksumAlgorithmHashFunc(const Checksum& checksum);
    } // namespace Client
} // namespace Aws
