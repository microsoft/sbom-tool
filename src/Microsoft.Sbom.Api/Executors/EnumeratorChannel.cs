// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// A executor that enumerates over objects in an enumerator.
    /// </summary>
    public class EnumeratorChannel
    {
        private readonly ILogger log;

        public EnumeratorChannel(ILogger log)
        {
            this.log = log;
        }

        /// <summary>
        /// Takes in an enumerator delegate that enumerates over objects of <typeparamref name="T"/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="enumerator"></param>
        /// <returns></returns>
        public (ChannelReader<T>, ChannelReader<FileValidationResult>) Enumerate<T>(Func<IEnumerable<T>> enumerator)
        {
            var output = Channel.CreateUnbounded<T>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            async Task Enumerate()
            {
                try
                {
                    foreach (var value in enumerator())
                    {
                        await output.Writer.WriteAsync(value);
                    }
                }
                catch (Exception e)
                {
                    log.Debug($"Encountered an unknown error while enumerating: {e.Message}");
                    await errors.Writer.WriteAsync(new FileValidationResult
                    {
                        ErrorType = ErrorType.Other
                    });
                }
            }

            Task.Run(async () =>
            {
                await Enumerate();
                output.Writer.Complete();
                errors.Writer.Complete();
            });

            return (output, errors);
        }
    }
}
