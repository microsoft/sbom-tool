using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows.Helpers
{
    public class FilesValidator
    {
        private readonly DirectoryWalker directoryWalker;
        private readonly IConfiguration configuration;
        private readonly ManifestFileFilterer manifestFileFilterer;
        private readonly ChannelUtils channelUtils;
        private readonly ILogger log;
        private readonly FileHasher fileHasher;
        private readonly ManifestFolderFilterer fileFilterer;

        public async Task<IList<FileValidationResult>> Validate(ISbomParser sbomParser)
        {
            var errors = new List<ChannelReader<FileValidationResult>>();
            var filesWithHashes = new List<ChannelReader<InternalSBOMFileInfo>>();

            // Read all files
            var (files, dirErrors) = directoryWalker.GetFilesRecursively(configuration.BuildDropPath.Value);
            errors.Add(dirErrors);

            // Filter root path matching files from the manifest map.
            var manifestFilterErrors = manifestFileFilterer.FilterManifestFiles();
            errors.Add(manifestFilterErrors);

            log.Debug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
            var splitFilesChannels = channelUtils.Split(files, configuration.Parallelism.Value);

            log.Debug("Waiting for the workflow to finish...");
            foreach (var fileChannel in splitFilesChannels)
            {
                // Filter files
                var (filteredFiles, filteringErrors) = fileFilterer.FilterFiles(fileChannel);
                errors.Add(filteringErrors);

                // Generate hash code for each file.
                var (fileHashes, hashingErrors) = fileHasher.Run(filteredFiles);
                errors.Add(hashingErrors);


                filesWithHashes.Add(fileHashes);
            }
            
            return null;
        }
    }
}
