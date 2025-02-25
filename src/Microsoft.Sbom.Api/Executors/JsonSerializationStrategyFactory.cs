// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

public static class JsonSerializationStrategyFactory
{
    public static IJsonSerializationStrategy GetStrategy(string manifestInfoSpdxVersion)
    {
        if (manifestInfoSpdxVersion == Constants.SPDX30ManifestInfo.Version)
        {
            return new Spdx3SerializationStrategy();
        }
        else
        {
            return new Spdx2SerializationStrategy();
        }
    }
}
