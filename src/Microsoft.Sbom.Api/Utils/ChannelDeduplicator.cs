// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// Provides deduplication of T objects inside a channel. 
    /// </summary>
    public abstract class ChannelDeduplicator<T>
    {
        protected ConcurrentDictionary<string, bool> uniqueObjects;

        protected ChannelDeduplicator()
        {
            uniqueObjects = new ConcurrentDictionary<string, bool>();
        }

        /// <summary>
        /// Removes duplicate T objects from a channel.
        /// </summary>
        /// <param name="input">Input channel.</param>
        /// <returns>Output channel without duplicates.</returns>
        public ChannelReader<T> Deduplicate(ChannelReader<T> input)
        {
            var output = Channel.CreateUnbounded<T>();

            Task.Run(async () =>
            {
                await foreach (var obj in input.ReadAllAsync())
                {
                    if (uniqueObjects.TryAdd(GetKey(obj), true))
                    {
                        await output.Writer.WriteAsync(obj);
                    }
                }

                output.Writer.Complete();
            });

            return output;
        }

        public abstract string GetKey(T obj);
    }
}
