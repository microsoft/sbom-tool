// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// SBOM redactor that removes file information from SBOMs
/// </summary>
public class SbomRedactor: ISbomRedactor
{
    private const string SpdxFileRelationshipPrefix = "SPDXRef-File-";

    private readonly ILogger log;

    public SbomRedactor(
        ILogger log)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public virtual async Task<FormatEnforcedSPDX2> RedactSBOMAsync(IValidatedSBOM_ sbom)
    {
        var spdx = await sbom.GetRawSPDXDocument();

        if (spdx.Files != null)
        {
            this.log.Debug("Removing files section from SBOM.");
            spdx.Files = null;
        }

        RemovePackageFileRefs(spdx);
        RemoveRelationshipsWithFileRefs(spdx);
        UpdateDocumentNamespace(spdx);

        return spdx;
    }

    private void RemovePackageFileRefs(FormatEnforcedSPDX2 spdx)
    {
        if (spdx.Packages != null)
        {
            foreach (var package in spdx.Packages)
            {
                if (package.HasFiles != null)
                {
                    this.log.Debug($"Removing has files property from package {package.Name}.");
                    package.HasFiles = null;
                }

                if (package.SourceInfo != null)
                {
                    this.log.Debug($"Removing has sourceInfo property from package {package.Name}.");
                    package.SourceInfo = null;
                }
            }
        }
    }

    private void RemoveRelationshipsWithFileRefs(FormatEnforcedSPDX2 spdx)
    {
        if (spdx.Relationships != null)
        {
            var relationshipsToRemove = new List<SPDXRelationship>();
            foreach (var relationship in spdx.Relationships)
            {
                if (relationship.SourceElementId.Contains(SpdxFileRelationshipPrefix) || relationship.TargetElementId.Contains(SpdxFileRelationshipPrefix))
                {
                    relationshipsToRemove.Add(relationship);
                }
            }

            if (relationshipsToRemove.Any())
            {
                this.log.Debug($"Removing {relationshipsToRemove.Count()} relationships with file references from SBOM.");
                spdx.Relationships = spdx.Relationships.Except(relationshipsToRemove);
            }
        }
    }

    private void UpdateDocumentNamespace(FormatEnforcedSPDX2 spdx)
    {
        if (!string.IsNullOrWhiteSpace(spdx.DocumentNamespace) && spdx.CreationInfo.Creators.Any(c => c.StartsWith("Tool: Microsoft.SBOMTool", StringComparison.OrdinalIgnoreCase)))
        {
            var existingNamespaceComponents = spdx.DocumentNamespace.Split('/');
            var uniqueComponent = IdentifierUtils.GetShortGuid(Guid.NewGuid());
            existingNamespaceComponents[^1] = uniqueComponent;
            spdx.DocumentNamespace = string.Join("/", existingNamespaceComponents);

            this.log.Debug($"Updated document namespace to {spdx.DocumentNamespace}.");
        }
    }
}
