// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Entities.Output;

/// <summary>
/// The result of the validation.
/// </summary>
public enum Result
{
    [EnumMember(Value = "Success")]
    Success = 0,

    [EnumMember(Value = "Failure")]
    Failure = 1
}
