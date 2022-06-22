// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Given a list of objects returns a stream of each of those individual objects in a channel stream.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class ListWalker<T>
    {
        public (ChannelReader<T> output, ChannelReader<FileValidationResult> error) GetComponents(IEnumerable<T> components)
        {
            if (components is null)
            {
                throw new ArgumentNullException(nameof(components));
            }

            var output = Channel.CreateUnbounded<T>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {
                try
                {
                    foreach(var component in components)
                    {
                        await output.Writer.WriteAsync(component);
                    }
                }
                catch (Exception ex)
                {
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.PackageError,
                        Path = ex.Message
                    });
                }
                finally
                {
                    output.Writer.Complete();
                    errors.Writer.Complete();
                }
            });

            return (output, errors);
        }
    }
}
