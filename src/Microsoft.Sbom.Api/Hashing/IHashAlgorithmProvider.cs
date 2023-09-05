// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Hashing;

public interface IHashAlgorithmProvider
{
    AlgorithmName Get(string algorithmName);
}
