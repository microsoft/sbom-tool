// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Parser;

public class TestSPDXParser : NewSPDXParser
{
    public int? PackageCount { get; private set; } = null;

    public int? ReferenceCount { get; private set; } = null;

    public int? RelationshipCount { get; private set; } = null;

    public int? FilesCount { get; private set; } = null;

    public bool BlockExecution { get; set; }

    public TestSPDXParser(Stream stream, bool requiredFields = false, IEnumerable<string>? skippedProperties = null, int? bufferSize = null, bool block = false)
#pragma warning disable CS0618 // Type or member is obsolete
        : base(stream, requiredFields, skippedProperties, bufferSize: bufferSize)
#pragma warning restore CS0618 // Type or member is obsolete
    {
        this.BlockExecution = block;
    }

    public override async Task HandlePackagesAsync(IEnumerable<SbomPackage> packages, CancellationToken cancellationToken)
    {
        await this.BlockExecutionAsync(cancellationToken);
        var list = packages.ToList();
        this.PackageCount = list.Count;
    }

    public override async Task HandleReferencesAsync(IEnumerable<SBOMReference> references, CancellationToken cancellationToken)
    {
        await this.BlockExecutionAsync(cancellationToken);
        var list = references.ToList();
        this.ReferenceCount = list.Count;
    }

    public override async Task HandleRelationshipsAsync(IEnumerable<SBOMRelationship> relationships, CancellationToken cancellationToken)
    {
        await this.BlockExecutionAsync(cancellationToken);
        var list = relationships.ToList();
        this.RelationshipCount = list.Count;
    }

    public override async Task HandleFilesAsync(IEnumerable<SbomFile> files, CancellationToken cancellationToken)
    {
        await this.BlockExecutionAsync(cancellationToken);
        var list = files.ToList();
        this.FilesCount = list.Count;
    }

    private async Task BlockExecutionAsync(CancellationToken cancellationToken)
    {
        if (this.BlockExecution)
        {
            await Task.Delay(500, cancellationToken);
        }
    }
}
