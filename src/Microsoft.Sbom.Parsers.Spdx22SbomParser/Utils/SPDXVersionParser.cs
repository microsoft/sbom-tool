// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Utils;

using System;

public static class SPDXVersionParser
{
    // SPDX versions are of the form "SPDX-m.n". We only care about the major version.
    public static bool VersionMatchesRequiredVersion(string spdxVersionString, int requiredMajorVersion)
    {
        if (string.IsNullOrEmpty(spdxVersionString))
        {
            return false;
        }

        var spdxTag = "SPDX-";
        var start = spdxVersionString.IndexOf(spdxTag, StringComparison.InvariantCulture);
        if (start == -1)
        {
            return false;
        }

        start += spdxTag.Length;

        var end = spdxVersionString.IndexOf(".", start, StringComparison.InvariantCulture);
        if (!int.TryParse(spdxVersionString[start..end], out var majorVersion))
        {
            return false;
        }

        return majorVersion == requiredMajorVersion;
    }
}
