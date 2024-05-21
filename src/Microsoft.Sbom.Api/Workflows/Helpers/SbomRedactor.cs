// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// SBOM redactor that removes file information from SBOMs
/// </summary>
public class SbomRedactor
{
    private const string SpdxFileRelationshipPrefix = "SPDXRef-File-";

    public virtual async Task<FormatEnforcedSPDX2> RedactSBOMAsync(IValidatedSBOM sbom)
    {
        var spdx = await sbom.GetRawSPDXDocument();

        if (spdx.Files != null)
        {
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
                    package.HasFiles = null;
                }

                if (package.SourceInfo != null)
                {
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
                spdx.Relationships = spdx.Relationships.Except(relationshipsToRemove);
            }
        }
    }

    private void UpdateDocumentNamespace(FormatEnforcedSPDX2 spdx)
    {
        if (string.IsNullOrWhiteSpace(spdx.DocumentNamespace) || !spdx.DocumentNamespace.Contains("microsoft"))
        {
            return;
        }

        var existingNamespaceComponents = spdx.DocumentNamespace.Split('/');
        var uniqueComponent = IdentifierUtils.GetShortGuid(Guid.NewGuid());
        existingNamespaceComponents[^1] = uniqueComponent;
        spdx.DocumentNamespace = string.Join("/", existingNamespaceComponents);
    }
}
