// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    public class ChannelUtils
    {
        /// <summary>
        /// Merges a given array of input channels into a common input channel.
        /// </summary>
        /// <typeparam name="T">Type of the channel.</typeparam>
        /// <param name="inputs">The list of input channels.</param>
        /// <returns>A <see cref="ChannelReader{T}"/> for all the combined inputs.</returns>
        public ChannelReader<T> Merge<T>(params ChannelReader<T>[] inputs)
        {
            var output = Channel.CreateUnbounded<T>();

            Task.Run(async () =>
            {
                async Task Redirect(ChannelReader<T> input)
                {

                    await foreach (T item in input.ReadAllAsync())
                        await output.Writer.WriteAsync(item);

                }

                await Task.WhenAll(inputs.Select(i => Redirect(i)).ToArray());
                output.Writer.Complete();
            });

            return output;
        }

        /// <summary>
        /// Splits a given input channel into 'n' seperate channels.
        /// </summary>
        /// <typeparam name="T">The type of the channel.</typeparam>
        /// <param name="input">The input channel.</param>
        /// <param name="n">The number of channels to create.</param>
        /// <returns>A <see cref="List{T}"/> of <see cref="ChannelReader{T}"/>s.</returns>
        public IList<ChannelReader<T>> Split<T>(ChannelReader<T> input, int n)
        {
            var outputs = new Channel<T>[n];
            for (var i = 0; i < n; i++)
                outputs[i] = Channel.CreateUnbounded<T>();

            Task.Run(async () =>
            {
                var index = 0;

                await foreach (T item in input.ReadAllAsync())
                {
                    await outputs[index].Writer.WriteAsync(item);
                    index = (index + 1) % n;
                }

                foreach (Channel<T> ch in outputs)
                {
                    ch.Writer.Complete();
                }
            });

            return outputs.Select(ch => ch.Reader).ToArray();
        }
    }
}
