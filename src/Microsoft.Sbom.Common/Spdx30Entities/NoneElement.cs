// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.Spdx30Entities;

public class NoneElement : Element
{
    public NoneElement()
    {
        Name = "NoneElement";
        SpdxId = "SPDXRef-None";
        Type = nameof(Element);
    }
}
