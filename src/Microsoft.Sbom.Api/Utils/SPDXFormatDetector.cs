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

    public SPDXFormatDetector(
        IFileSystemUtils fileSystemUtils,
        IManifestParserProvider manifestParserProvider)
    {
        this.fileSystemUtils = fileSystemUtils;
        supportedManifestInfos = new Dictionary<ManifestInfo, Func<Stream, bool>>()
        {
            { Constants.SPDX22ManifestInfo, TryParse22 },
            { Constants.SPDX30ManifestInfo, TryParse30 }
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

                if (result is not null && result.Result is not null)
                {
                    switch (result.FieldName)
                    {
                        case Constants.SPDXContextHeaderName:
                            var contextReslt = (result as ContextsResult)?.Contexts.FirstOrDefault();
                            return contextReslt != null && contextReslt.Contains("3.0");
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
