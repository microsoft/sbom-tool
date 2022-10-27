using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common;
using Ninject.Activation;
using System.Collections.Concurrent;

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
            return new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes.FileHashes>());
        }
    }
}
