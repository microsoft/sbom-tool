// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Utils;

public interface ISPDXFormatDetector
{
    public bool TryDetectFormat(string filePath, out ManifestInfo detectedManifestInfo);

    public bool TryDetectFormat(Stream stream, out ManifestInfo detectedManifestInfo);

    public bool TryGetSbomsWithVersion(string manifestDirPath, out IDictionary<string, ManifestInfo> detectedSboms);
}
