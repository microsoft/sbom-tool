// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.Spdx30Entities;

public class NoAssertionElement : Element
{
    public NoAssertionElement()
    {
        Name = Constants.NoAssertionValue;
        Type = nameof(Element);
    }
}
