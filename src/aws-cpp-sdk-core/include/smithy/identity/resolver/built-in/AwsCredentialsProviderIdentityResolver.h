/**
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#pragma once

#include <smithy/identity/resolver/AwsCredentialIdentityResolver.h>

#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>

namespace smithy
{
    /**
     * A smithy SigV4 AWS Credentials resolver wrapper on top of legacy SDK Credentials provider
     * TODO: refactor into own signer using smithy design
     */
    class AwsCredentialsProviderIdentityResolver : public AwsCredentialIdentityResolver
    {
    public:
        using SigV4AuthSchemeParameters = DefaultAuthSchemeResolverParameters;

        explicit AwsCredentialsProviderIdentityResolver(std::shared_ptr<Aws::Auth::AWSCredentialsProvider> credentialsProvider)
            : credentialsProvider_(credentialsProvider)
        {
        }

        ResolveIdentityFutureOutcome getIdentity(const IdentityProperties& identityProperties,
                                                 const AdditionalParameters& additionalParameters) override
        {
            AWS_UNREFERENCED_PARAM(identityProperties);
            AWS_UNREFERENCED_PARAM(additionalParameters);

            const auto fetchedCreds = credentialsProvider_->GetAWSCredentials();

            auto smithyCreds = Aws::MakeUnique<AwsCredentialIdentity>("DefaultAwsCredentialIdentityResolver",
                                                                     fetchedCreds.GetAWSAccessKeyId(), fetchedCreds.GetAWSSecretKey(),
                                                                     fetchedCreds.GetSessionToken(), fetchedCreds.GetExpiration());

            return ResolveIdentityFutureOutcome(std::move(smithyCreds));
        }

        virtual ~AwsCredentialsProviderIdentityResolver()
        {
        };

    protected:
        std::shared_ptr<Aws::Auth::AWSCredentialsProvider> credentialsProvider_;
    };
}
