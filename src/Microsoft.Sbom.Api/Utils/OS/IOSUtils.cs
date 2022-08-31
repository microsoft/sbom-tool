// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

namespace Microsoft.Sbom.Api.Utils.OS
{
    public interface IOSUtils
    {
        OSPlatform GetCurrentOSPlatform();

        string GetEnvironmentVariable(string variableName);

        StringComparer GetFileSystemStringComparer();

        StringComparison GetFileSystemStringComparisonType();
    }
}
