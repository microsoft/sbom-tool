// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

public class NoneElement : Element
{
    public NoneElement()
    {
        Name = "NoneElement";
        SpdxId = "SPDXRef-None";
        Type = "Element";
    }
}
