using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors
{
    public class HashValidator2
    {
        private readonly IConfiguration configuration;

        public HashValidator2(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public (ChannelReader<FileValidationResult> output, ChannelReader<FileValidationResult> errors)
            Validate(ChannelReader<InternalSBOMFileInfo> fileWithHash)
        {

        }
    }
}
