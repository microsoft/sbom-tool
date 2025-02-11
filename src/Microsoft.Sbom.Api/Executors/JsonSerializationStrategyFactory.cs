// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

public static class JsonSerializationStrategyFactory
{
    public static IJsonSerializationStrategy GetStrategy(string manifestInfoSpdxVersion)
    {
        if (manifestInfoSpdxVersion == SpdxConstants.SPDX30ManifestInfo.Version)
        {
            return new Spdx3SerializationStrategy();
        }
        else
        {
            return new Spdx2SerializationStrategy();
        }
    }
}
