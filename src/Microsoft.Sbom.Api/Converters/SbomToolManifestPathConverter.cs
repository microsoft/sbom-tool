// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Convertors;

/// <summary>
/// Converts a regular file path to a relative file path in the format the
/// SbomTool expects. The expected format looks like this:
///
/// Root                  : C:\dropRoot
/// Absolute path         : C:\dropRoot\folder1\file1.txt
/// Relative path         : folder1\file1.txt
/// SbomTool Format  : /folder1/file1.txt
///
/// Throws a <see cref="InvalidPathException"/> if the file is outside the root folder.
/// </summary>
public class SbomToolManifestPathConverter : IManifestPathConverter
{
    private readonly IConfiguration configuration;
    private readonly IOSUtils osUtils;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IFileSystemUtilsExtension fileSystemUtilsExtension;

    public SbomToolManifestPathConverter(IConfiguration configuration, IOSUtils osUtils, IFileSystemUtils fileSystemUtils, IFileSystemUtilsExtension fileSystemUtilsExtension)
    {
        this.configuration = configuration;
        this.osUtils = osUtils;
        this.fileSystemUtils = fileSystemUtils;
        this.fileSystemUtilsExtension = fileSystemUtilsExtension;
    }

    public (string, bool) Convert(string path, bool prependDotToPath = false)
    {
        var dotString = prependDotToPath ? "." : string.Empty;

        // relativeTo
        var buildDropPath = configuration.BuildDropPath.Value;
        var isOutsideDropPath = false;
        if (path == null)
        {
            throw new ArgumentNullException(nameof(path));
        }

        if (!fileSystemUtilsExtension.IsTargetPathInSource(path, buildDropPath))
        {
            isOutsideDropPath = true;

            // Allow spdx files to be outside the root path, all externalDocumentReference must be in the file array regardless of where they are located.
            // More details are in this spec: https://github.com/spdx/spdx-spec/issues/571
            if (!path.EndsWith(Constants.SPDXFileExtension, osUtils.GetFileSystemStringComparisonType()))
            {
                throw new InvalidPathException($"The file at {path} is outside the root path {buildDropPath}.");
            }
        }

        var relativePath = fileSystemUtils.GetRelativePath(buildDropPath, path);
        var formattedRelativePath = $"{dotString}/{relativePath.Replace("\\", "/")}";

        return (formattedRelativePath, isOutsideDropPath);
    }
}
