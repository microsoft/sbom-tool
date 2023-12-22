// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Output;

public interface IOutputWriter
{
    /// <summary>
    /// Writes a string to a file asynchronously.
    /// </summary>
    /// <param name="output"></param>
    /// <returns></returns>
    Task WriteAsync(string output);
}
