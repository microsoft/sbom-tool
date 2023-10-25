// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.JsonAsynchronousNodeKit;

#nullable enable

public record ParserStateResult(
    string FieldName,
    object? Result,
    bool ExplicitField,
    bool YieldReturn);
