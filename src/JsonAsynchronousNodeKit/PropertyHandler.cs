// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace JsonAsynchronousNodeKit;

public record PropertyHandler(ParameterType Type);

#pragma warning disable SA1402 // File may only contain a single type
public record PropertyHandler<T>(ParameterType ParameterType)
#pragma warning restore SA1402 // File may only contain a single type
    : PropertyHandler(ParameterType);
