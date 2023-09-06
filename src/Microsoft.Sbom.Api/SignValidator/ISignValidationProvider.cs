// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.SignValidator;

/// <summary>
/// A type that provides a <see cref="ISignValidator"/> implementation based on the
/// current operating system type.
/// </summary>
public interface ISignValidationProvider
{
    ISignValidator Get();

    void Init();
}
