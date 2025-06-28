// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parser;

namespace Microsoft.Sbom.Api.Utils;

public class SPDXFormatDetector : ISPDXFormatDetector
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IDictionary<ManifestInfo, Func<Stream, bool>> supportedManifestInfos;
    private readonly ISbomConfigFactory sbomConfigFactory;

    public SPDXFormatDetector(
        IFileSystemUtils fileSystemUtils,
        IManifestParserProvider manifestParserProvider,
        ISbomConfigFactory sbomConfigFactory)
    {
        this.fileSystemUtils = fileSystemUtils;
        supportedManifestInfos = new Dictionary<ManifestInfo, Func<Stream, bool>>()
        {
            { Constants.SPDX22ManifestInfo, TryParse22 },
            { Constants.SPDX30ManifestInfo, TryParse30 }
        };
        this.sbomConfigFactory = sbomConfigFactory;
    }

    public bool TryGetSbomsWithVersion(string manifestDirPath, out IList<(string sbomFilePath, ManifestInfo manifestInfo)> detectedSboms)
    {
        detectedSboms = new List<(string, ManifestInfo)>();
        foreach (var mi in supportedManifestInfos.Keys)
        {
            var filePath = sbomConfigFactory.GetSbomFilePath(manifestDirPath, mi);
            if (fileSystemUtils.FileExists(filePath) && fileSystemUtils.GetFileSize(filePath) > 0)
            {
                var result = TryDetectFormat(filePath, out var detectedManifestInfo);
                if (result && mi.Equals(detectedManifestInfo))
                {
                    detectedSboms.Add((filePath, detectedManifestInfo));
                }
            }
        }

        if (detectedSboms.Any())
        {
            return true;
        }

        detectedSboms = null;
        return false;
    }

    public bool TryDetectFormat(string filePath, out ManifestInfo detectedManifestInfo)
    {
        using var stream = fileSystemUtils.OpenRead(filePath);
        return TryDetectFormat(stream, out detectedManifestInfo);
    }

    public bool TryDetectFormat(Stream stream, out ManifestInfo detectedManifestInfo)
    {
        foreach (var (mi, tryParse) in supportedManifestInfos)
        {
            if (tryParse(stream))
            {
                detectedManifestInfo = mi;
                return true;
            }
        }

        detectedManifestInfo = null;
        return false;
    }

    private bool TryParse22(Stream stream)
    {
        try
        {
            var parser = new SPDXParser(stream, new List<string>() { SPDXParser.FilesProperty, SPDXParser.PackagesProperty, SPDXParser.ReferenceProperty, SPDXParser.RelationshipsProperty });
            ParserStateResult? result = null;
            do
            {
                result = parser.Next();
                if (result is not null)
                {
                    switch (result.FieldName)
                    {
                        case Constants.SpdxVersionString:
                            return result.Result.ToString().ToUpperInvariant().Equals("SPDX-2.2");
                    }
                }
            }
            while (result is not null);

            return false;
        }
        catch
        {
            return false;
        }
    }

    private bool TryParse30(Stream stream)
    {
        try
        {
            var parser = new SPDX30Parser(stream);
            ParserStateResult? result = null;
            do
            {
                result = parser.Next();

                if (result?.Result is not null)
                {
                    switch (result.FieldName)
                    {
                        case Constants.SPDXContextHeaderName:
                            var contextResult = (result as ContextsResult)?.Contexts.FirstOrDefault();
                            return contextResult != null && contextResult.Contains("3.0");
                        default:
                            break;
                    }
                }
            }
            while (result is not null);

            return false;
        }
        catch
        {
            return false;
        }
    }
}
