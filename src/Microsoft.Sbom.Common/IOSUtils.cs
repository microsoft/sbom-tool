// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

namespace Microsoft.Sbom.Common;

public interface IOSUtils
{
    public OSPlatform GetCurrentOSPlatform();

    public string GetEnvironmentVariable(string variableName);

    public StringComparer GetFileSystemStringComparer();

    public StringComparison GetFileSystemStringComparisonType();

    public bool IsCaseSensitiveOS();
}
