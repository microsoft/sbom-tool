// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Contracts;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Sbom.Api.Recorder;

/// <summary>
/// A recorder class, injected as a singleton that records details about files and
/// packages encountered while traversing the drop.
/// </summary>
public class SbomPackageDetailsRecorder : ISbomPackageDetailsRecorder
{
    private string rootPackageId;
    private string documentId;
    private readonly ConcurrentBag<string> fileIds = new ConcurrentBag<string>();
    private readonly ConcurrentBag<string> spdxFileIds = new ConcurrentBag<string>();
    private readonly ConcurrentBag<string> packageIds = new ConcurrentBag<string>();
    private readonly ConcurrentBag<KeyValuePair<string, string>> externalDocumentRefIdRootElementPairs = new ConcurrentBag<KeyValuePair<string, string>>();
    private readonly ConcurrentBag<Checksum[]> checksums = new ConcurrentBag<Checksum[]>();

    /// <summary>
    /// Record a fileId that is included in this SBOM.
    /// </summary>
    /// <param name="fileId"></param>
    public void RecordFileId(string fileId)
    {
        if (string.IsNullOrEmpty(fileId))
        {
            throw new ArgumentException($"'{nameof(fileId)}' cannot be null or empty.", nameof(fileId));
        }

        fileIds.Add(fileId);
    }

    public void RecordSPDXFileId(string spdxFileId)
    {
        if (string.IsNullOrEmpty(spdxFileId))
        {
            throw new ArgumentException($"'{nameof(spdxFileId)}' cannot be null or empty.", nameof(spdxFileId));
        }

        spdxFileIds.Add(spdxFileId);
    }

    /// <summary>
    /// Record a packageId that is included in this SBOM.
    /// </summary>
    /// <param name="packageId"></param>
    public void RecordPackageId(string packageId)
    {
        if (string.IsNullOrEmpty(packageId))
        {
            throw new ArgumentException($"'{nameof(packageId)}' cannot be null or empty.", nameof(packageId));
        }

        packageIds.Add(packageId);
    }

    /// <summary>
    /// Record a externalDocumentReference Id that is included in this SBOM.
    /// </summary>
    /// <param name="fileId"></param>
    public void RecordExternalDocumentReferenceIdAndRootElement(string externalDocumentReferenceId, string rootElement)
    {
        if (string.IsNullOrEmpty(externalDocumentReferenceId))
        {
            throw new ArgumentException($"'{nameof(externalDocumentReferenceId)}' cannot be null or empty.", nameof(externalDocumentReferenceId));
        }

        externalDocumentRefIdRootElementPairs.Add(new KeyValuePair<string, string>(externalDocumentReferenceId, rootElement));
    }

    public GenerationData GetGenerationData()
    {
        return new GenerationData
        {
            Checksums = checksums.ToList(),
            FileIds = fileIds.ToList(),
            SPDXFileIds = spdxFileIds.ToList(),
            PackageIds = packageIds.ToList(),
            ExternalDocumentReferenceIDs = externalDocumentRefIdRootElementPairs.ToList(),
            RootPackageId = rootPackageId,
            DocumentId = documentId
        };
    }

    /// <summary>
    /// Record the SHA1 hash for the file.
    /// </summary>
    /// <param name="hash"></param>
    public void RecordChecksumForFile(Checksum[] checksums)
    {
        if (checksums is null)
        {
            throw new ArgumentNullException(nameof(checksums));
        }

        this.checksums.Add(checksums);
    }

    public void RecordRootPackageId(string rootPackageId)
    {
        if (rootPackageId is null)
        {
            throw new ArgumentNullException(nameof(rootPackageId));
        }

        this.rootPackageId = rootPackageId;
    }

    public void RecordDocumentId(string documentId)
    {
        if (documentId is null)
        {
            throw new ArgumentNullException(nameof(documentId));
        }

        this.documentId = documentId;
    }
}