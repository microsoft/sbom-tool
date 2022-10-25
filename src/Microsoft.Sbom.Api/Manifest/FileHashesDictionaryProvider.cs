using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common;
using Ninject.Activation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Manifest
{
    public class FileHashesDictionaryProvider : Provider<FileHashesDictionary>
    {
        private readonly IOSUtils osUtils;

        public FileHashesDictionaryProvider(IOSUtils osUtils)
        {
            this.osUtils = osUtils;
        }

        protected override FileHashesDictionary CreateInstance(IContext context)
        {
            throw new NotImplementedException();
        }
    }
}
