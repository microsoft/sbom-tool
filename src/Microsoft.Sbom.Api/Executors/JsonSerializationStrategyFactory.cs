// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Workflows.Helpers;

public static class JsonSerializationStrategyFactory
{
    public static IJsonSerializationStrategy GetStrategy(string manifestInfoSpdxVersion)
    {
        if (manifestInfoSpdxVersion == "3.0")
        {
            return new Spdx3SerializationStrategy();
        }
        else
        {
            return new Spdx2SerializationStrategy();
        }
    }
}
