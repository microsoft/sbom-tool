using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
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
    public class NullExecutor
    {
        private readonly ILogger log;

        public NullExecutor(ILogger log)
        {
            this.log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public (ChannelReader<string> file, ChannelReader<FileValidationResult> errors) Execute(string root)
        { 
            var output = Channel.CreateUnbounded<string>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();


            Task.Run(async () =>
            {
                
            });

            return (output, errors);
        }

        internal void Execute<T>(Func<IEnumerable<T>> enumerable)
        {
            var output = Channel.CreateUnbounded<string>();
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            try
            {
                foreach (var value in enumerable())
                {

                }

                output.Writer.Complete();
                errors.Writer.Complete();
            }
            catch (Exception ex)
            {
                
            }
        }
    }
}
