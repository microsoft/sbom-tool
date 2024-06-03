// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Filters;

public class ManifestFolderFilter : IFilter<ManifestFolderFilter>
{
    private readonly IConfiguration configuration;
    private readonly IOSUtils osUtils;

    public ManifestFolderFilter(
        IConfiguration configuration,
        IOSUtils osUtils)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));

        Init();
    }

    public bool IsValid(string filePath)
    {
        var manifestFolderPath = new FileInfo(configuration.ManifestDirPath.Value).FullName;

        if (string.IsNullOrEmpty(filePath))
        {
            return false;
        }

        var normalizedPath = new FileInfo(filePath).FullName;

        return !normalizedPath.StartsWith(manifestFolderPath, osUtils.GetFileSystemStringComparisonType());
    }

    public void Init()
    {
    }
}
