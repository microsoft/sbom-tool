// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Workflows;

using System;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Serilog;

public class SbomValidationWorkflowFactory : ISbomValidationWorkflowFactory
{
    private readonly IRecorder recorder;
    private readonly ISignValidationProvider signValidationProvider;
    private readonly ILogger log;
    private readonly IManifestParserProvider manifestParserProvider;
    private readonly ValidationResultGenerator validationResultGenerator;
    private readonly IOutputWriter outputWriter;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly IOSUtils osUtils;
    private readonly DirectoryWalker directoryWalker;
    private readonly FileHasher fileHasher;
    private readonly ManifestFolderFilterer fileFilterer;
    private readonly EnumeratorChannel enumeratorChannel;
    private readonly SbomFileToFileInfoConverter fileConverter;
    private readonly FileFilterer spdxFileFilterer;

    public SbomValidationWorkflowFactory(
        IRecorder recorder,
        ISignValidationProvider signValidationProvider,
        ILogger log,
        IManifestParserProvider manifestParserProvider,
        ValidationResultGenerator validationResultGenerator,
        IOutputWriter outputWriter,
        IFileSystemUtils fileSystemUtils,
        IOSUtils osUtils,
        DirectoryWalker directoryWalker,
        FileHasher fileHasher,
        ManifestFolderFilterer fileFilterer,
        EnumeratorChannel enumeratorChannel,
        SbomFileToFileInfoConverter fileConverter,
        FileFilterer spdxFileFilterer)
    {
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.signValidationProvider = signValidationProvider ?? throw new ArgumentNullException(nameof(signValidationProvider));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.manifestParserProvider = manifestParserProvider ?? throw new ArgumentNullException(nameof(manifestParserProvider));
        this.validationResultGenerator = validationResultGenerator ?? throw new ArgumentNullException(nameof(validationResultGenerator));
        this.outputWriter = outputWriter ?? throw new ArgumentNullException(nameof(outputWriter));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.osUtils = osUtils ?? throw new ArgumentNullException(nameof(osUtils));
        this.directoryWalker = directoryWalker ?? throw new ArgumentNullException(nameof(directoryWalker));
        this.fileHasher = fileHasher ?? throw new ArgumentNullException(nameof(fileHasher));
        this.fileFilterer = fileFilterer ?? throw new ArgumentNullException(nameof(fileFilterer));
        this.enumeratorChannel = enumeratorChannel ?? throw new ArgumentNullException(nameof(enumeratorChannel));
        this.fileConverter = fileConverter ?? throw new ArgumentNullException(nameof(fileConverter));
        this.spdxFileFilterer = spdxFileFilterer ?? throw new ArgumentNullException(nameof(spdxFileFilterer));
    }

    public IWorkflow<SbomParserBasedValidationWorkflow> Get(IConfiguration configuration, ISbomConfig sbomConfig, string eventName)
    {
        var fileHashesDictionary = new FileHashesDictionary(new System.Collections.Concurrent.ConcurrentDictionary<string, FileHashes>(osUtils.GetFileSystemStringComparer()));
        var hashValidator = new ConcurrentSha256HashValidator(fileHashesDictionary);
        var filesValidator = new FilesValidator(directoryWalker, configuration, log, fileHasher, fileFilterer, hashValidator, enumeratorChannel, fileConverter, fileHashesDictionary, spdxFileFilterer);
        return new SbomParserBasedValidationWorkflow(recorder, signValidationProvider, log, manifestParserProvider, configuration, sbomConfig, filesValidator, validationResultGenerator, outputWriter, fileSystemUtils, osUtils, eventName);
    }
}
