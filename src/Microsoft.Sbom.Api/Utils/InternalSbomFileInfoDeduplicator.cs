// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// Provides deduplication of InternalSbomFileInfo objects inside a channel.
/// </summary>
public class InternalSbomFileInfoDeduplicator : ChannelDeduplicator<InternalSbomFileInfo>
{
    public InternalSbomFileInfoDeduplicator()
        : base() { }

    public override string GetKey(InternalSbomFileInfo obj)
    {
        return obj?.Path;
    }
}
