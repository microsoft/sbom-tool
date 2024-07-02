// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Utils;

public static class Constants
{
    public const string ManifestFolder = "_manifest";
    public const string LoggerTemplate = "##[{Level:w}]{Message}{NewLine}{Exception}";

    public static ManifestInfo SPDX22ManifestInfo = new ManifestInfo
    {
        Name = "SPDX",
        Version = "2.2"
    };

    public static SbomSpecification SPDX22Specification = SPDX22ManifestInfo.ToSBOMSpecification();

    // TODO: move to test csproj
    public static ManifestInfo TestManifestInfo = new ManifestInfo
    {
        Name = "TestManifest",
        Version = "1.0.0"
    };

    public static List<Entities.ErrorType> SkipFailureReportingForErrors = new()
    {
        Entities.ErrorType.ManifestFolder,
        Entities.ErrorType.FilteredRootPath,
        Entities.ErrorType.ReferencedSbomFile,
    };

    public static AlgorithmName DefaultHashAlgorithmName = AlgorithmName.SHA256;

    public const string SPDXFileExtension = ".spdx.json";
    public const string DocumentNamespaceString = "documentNamespace";
    public const string NameString = "name";
    public const string DocumentDescribesString = "documentDescribes";
    public const string SpdxVersionString = "spdxVersion";
    public const string DefaultRootElement = "SPDXRef-Document";
    public const string CatalogFileName = "manifest.cat";
    public const string BsiFileName = "bsi.json";

    public const string DeleteManifestDirBoolVariableName = "DeleteManifestDirIfPresent";
}
