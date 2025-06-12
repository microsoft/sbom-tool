// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Executors;

using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;

public static class ChannelExtensions
{
    public static async Task WriteResult(this Channel<FileValidationResult> channel, string filePath)
    {
        await channel.Writer.WriteAsync(new FileValidationResult
        {
            ErrorType = ErrorType.Other,
            Path = filePath
        });
    }
}