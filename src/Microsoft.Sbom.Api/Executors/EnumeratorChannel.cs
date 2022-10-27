using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    public class EnumeratorChannel
    {
        private readonly ILogger log;

        public EnumeratorChannel(ILogger log)
        {
            this.log = log;
        }

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
                    log.Debug($"Encountered an unknown error: {e.Message}");
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
