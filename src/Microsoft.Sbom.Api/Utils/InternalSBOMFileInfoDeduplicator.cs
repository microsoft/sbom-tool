// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// Provides deduplication of InternalSBOMFileInfo objects inside a channel. 
    /// </summary>
    public class InternalSBOMFileInfoDeduplicator : ChannelDeduplicator<InternalSbomFileInfo>
    {
        public InternalSBOMFileInfoDeduplicator()
            : base() { }

        public override string GetKey(InternalSbomFileInfo obj)
        {
            return obj?.Path;
        }
    }
}
