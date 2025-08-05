// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Executors;

using System;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

public class Spdx22SbomReference : ISbomReferenceDescriber, IDisposable
{
    private bool disposed = false;
    private JsonDocument document;
    private string currentDocumentPath;
    private readonly IHashCodeGenerator hashCodeGenerator;
    private readonly AlgorithmName[] hashAlgorithmNames;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly string supportedSPDXVersion = "SPDX-2.2";

    public Spdx22SbomReference(IHashCodeGenerator hashCodeGenerator, IFileSystemUtils fileSystemUtils, AlgorithmName[] hashAlgorithmNames)
    {
        this.hashCodeGenerator = hashCodeGenerator ?? throw new ArgumentNullException(nameof(hashCodeGenerator));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.hashAlgorithmNames = hashAlgorithmNames ?? throw new ArgumentNullException(nameof(hashAlgorithmNames));
    }

    private bool IsSPDXVersionSupported(string version) => string.Equals(supportedSPDXVersion, version, StringComparison.OrdinalIgnoreCase);
    private bool DocumentAlreadyLoaded(string sbomFilePath) => document is not null && sbomFilePath.Equals(currentDocumentPath, StringComparison.InvariantCultureIgnoreCase);

    public bool IsSupportedFormat(string sbomFilePath)
    {
        // Since this may frequently be called for non-supported format documents, we
        // want to be very forgiving about any errors that occur. Catch everything and
        // simply tell the caller that the format is not supported.
        try
        {
            LoadDocument(sbomFilePath);

            var root = document.RootElement;
            if (root.TryGetProperty(Constants.SpdxVersionString, out var version))
            {
                var versionValue = version.GetString();
                if (!IsSPDXVersionSupported(versionValue))
                    return false;
                return true;
            }
        }
        catch 
        { 
        }

        return false;
    }

    public ExternalDocumentReferenceInfo CreateExternalDocumentRefererence(string sbomFilePath)
    {
        return ExtractDocumentReferenceInfo(sbomFilePath);
    }

    private void LoadDocument(string sbomFilePath)
    {
        // Need to add unit test for the reuse path.
        if (DocumentAlreadyLoaded(sbomFilePath))
            return;

        // Add unit test to verify Dispose is called?
        document?.Dispose();

        // This might be unacceptably non-performant with Very Large (tm) SBOMs - e.g. multi-GB
        using (var openStream = fileSystemUtils.OpenRead(sbomFilePath))
        {
            document = JsonDocument.Parse(openStream);
            currentDocumentPath = sbomFilePath;
        }

        return;
    }

    private ExternalDocumentReferenceInfo ExtractDocumentReferenceInfo(string sbomFilePath)
    {
        Checksum[] checksums;
        checksums = hashCodeGenerator.GenerateHashes(sbomFilePath, hashAlgorithmNames);

        LoadDocument(sbomFilePath);

        string nameValue;
        string documentNamespaceValue;
        string versionValue;
        string rootElementValue;

        var root = document.RootElement;
        if (root.TryGetProperty(Constants.SpdxVersionString, out var version))
        {
            versionValue = version.GetString();
        }
        else
        {
            throw new Exception($"{Constants.SpdxVersionString} property could not be parsed from referenced SPDX Document '{sbomFilePath}', this is not a valid SPDX-2.2 Document.");
        }

        if (!IsSPDXVersionSupported(versionValue))
        {
            throw new Exception($"The SPDX version ${versionValue} is not valid format in the referenced SBOM, we currently only support SPDX-2.2 SBOM format.");
        }

        if (root.TryGetProperty(Constants.NameString, out var name))
        {
            nameValue = name.GetString();
        }
        else
        {
            throw new Exception($"{Constants.NameString} property could not be parsed from referenced SPDX Document '{sbomFilePath}'.");
        }

        if (root.TryGetProperty(Constants.DocumentNamespaceString, out var documentNamespace))
        {
            documentNamespaceValue = documentNamespace.GetString();
        }
        else
        {
            throw new Exception($"{Constants.DocumentNamespaceString} property could not be parsed from referenced SPDX Document '{sbomFilePath}'.");
        }

        if (root.TryGetProperty(Constants.DocumentDescribesString, out var rootElements))
        {
            rootElementValue = rootElements.EnumerateArray().FirstOrDefault().ToString() ?? Constants.DefaultRootElement;
        }
        else
        {
            throw new Exception($"{Constants.DocumentDescribesString} property could not be parsed from referenced SPDX Document '{sbomFilePath}'.");
        }

        return new ExternalDocumentReferenceInfo
        {
            DocumentNamespace = documentNamespaceValue,
            ExternalDocumentName = nameValue,
            Checksum = checksums,
            DescribedElementID = rootElementValue
        };
    }

    public void Dispose()
    {
        if(!disposed)
        {
            Dispose(true);
            GC.SuppressFinalize(this);
            disposed = true;
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            document?.Dispose();
        }
    }
}
