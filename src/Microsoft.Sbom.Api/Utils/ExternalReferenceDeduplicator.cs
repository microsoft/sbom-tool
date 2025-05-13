// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// Provides deduplication of ExternalDocumentReferenceInfo objects inside a channel.
/// </summary>
public class ExternalReferenceDeduplicator : ChannelDeduplicator<ExternalDocumentReferenceInfo>
{
    public override string GetKey(ExternalDocumentReferenceInfo obj)
    {
        return obj?.DocumentNamespace;
    }
}
