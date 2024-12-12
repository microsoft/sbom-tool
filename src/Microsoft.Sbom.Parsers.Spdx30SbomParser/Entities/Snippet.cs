// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

/// <summary>
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Snippet/
/// </summary>
public class Snippet : Software
{
    public Snippet()
    {
        Type = nameof(Snippet);
    }
}
