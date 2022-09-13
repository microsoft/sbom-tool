// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;

namespace Microsoft.Sbom.Parser;

internal ref struct SbomPackageParser
{
    private readonly Stream stream;

    public SbomPackageParser(Stream stream)
    {
        this.stream = stream ?? throw new System.ArgumentNullException(nameof(stream));
    }
}
