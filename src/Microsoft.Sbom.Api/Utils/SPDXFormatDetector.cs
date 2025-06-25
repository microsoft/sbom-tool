// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parser;

namespace Microsoft.Sbom.Api.Utils;

public class SPDXFormatDetector : ISPDXFormatDetector
{
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IManifestParserProvider manifestParserProvider;
    private readonly IDictionary<ManifestInfo, Func<ISbomParser, Stream, bool>> supportedManifestInfos;

    public SPDXFormatDetector(
        IFileSystemUtils fileSystemUtils,
        IManifestParserProvider manifestParserProvider)
    {
        this.fileSystemUtils = fileSystemUtils;
        this.manifestParserProvider = manifestParserProvider;
        supportedManifestInfos = new Dictionary<ManifestInfo, Func<ISbomParser, Stream, bool>>()
        {
            { ManifestInfo.Parse("SPDX:2.2"), TryParse22 },
            { ManifestInfo.Parse("SPDX:3.0"), TryParse30 }
        };
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
            var manifestInterface = manifestParserProvider.Get(mi);
            var sbomParser = manifestInterface.CreateParser(stream);

            if (tryParse(sbomParser, stream))
            {
                detectedManifestInfo = mi;
                return true;
            }
        }

        detectedManifestInfo = null;
        return false;
    }

    private bool TryParse22(ISbomParser parser, Stream stream)
    {
        try
        {
            ParserStateResult? result = null;
            var requiredFieldsFound = 0;
            do
            {
                result = parser.Next();
                if (result is not null)
                {
                    switch (result.FieldName)
                    {
                        case SPDXParser.FilesProperty:
                        case SPDXParser.PackagesProperty:
                        case SPDXParser.ReferenceProperty:
                        case SPDXParser.RelationshipsProperty:
                            requiredFieldsFound++;
                            break;
                        default:
                            break;
                    }
                }
            }
            while (result is not null && requiredFieldsFound < 4);

            return requiredFieldsFound == 4;
        }
        catch
        {
            return false;
        }
    }

    private bool TryParse30(ISbomParser parser, Stream stream)
    {
        try
        {
            ParserStateResult? result = null;
            var requiredFieldsFound = 0;
            do
            {
                result = parser.Next();

                if (result is not null && result.Result is not null)
                {
                    switch (result.FieldName)
                    {
                        case Constants.SPDXContextHeaderName:
                        case Constants.SPDXGraphHeaderName:
                            requiredFieldsFound++;
                            break;
                        default:
                            break;
                    }
                }
            }
            while (result is not null && requiredFieldsFound < 2);

            return requiredFieldsFound == 2;
        }
        catch
        {
            return false;
        }
    }
}
