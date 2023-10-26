// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Utils;

#pragma warning disable SA1313 // Parameter names should begin with lower-case letter
internal record ParserStateResult(ParserState State, string? PropertyName = null, string? NextToken = null);
#pragma warning restore SA1313 // Parameter names should begin with lower-case letter
