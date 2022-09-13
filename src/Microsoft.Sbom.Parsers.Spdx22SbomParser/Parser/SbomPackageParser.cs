// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using System;
using System.IO;
using System.Text.Json;

namespace Microsoft.Sbom.Parser;

internal ref struct SbomPackageParser
{
    private readonly Stream stream;

    public SbomPackageParser(Stream stream)
    {
        this.stream = stream ?? throw new System.ArgumentNullException(nameof(stream));
    }

    internal long GetSbomPackage(ref byte[] buffer, ref Utf8JsonReader reader, out SBOMPackage sbomPackage)
    {
        throw new NotImplementedException();
    }
}
