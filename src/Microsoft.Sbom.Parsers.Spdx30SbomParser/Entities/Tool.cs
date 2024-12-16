// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

using System.Text.Json.Serialization;

/// <summary>
/// A tool is an element of hardware and/or software utilized to carry out a particular function.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Tool/
/// </summary>
public class Tool : Element
{
    public Tool()
    {
    }
}
