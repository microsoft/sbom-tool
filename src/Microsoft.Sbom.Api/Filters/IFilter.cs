// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Filters;

/// <summary>
/// A filter that, given a file path, returns whther it is valid.
/// </summary>
/// <typeparam name="T"></typeparam>
public interface IFilter<T>
    where T : IFilter<T>
{
    bool IsValid(string filePath);

    void Init();
}
