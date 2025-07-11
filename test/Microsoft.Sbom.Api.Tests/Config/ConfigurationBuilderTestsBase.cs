// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using AutoMapper;
using Microsoft.Sbom.Api.Config.Validators;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Contracts.Entities;
using Microsoft.Sbom.Contracts.Interfaces;
using Microsoft.Sbom.Extensions.Entities;
using Moq;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Config.Tests;

public class ConfigurationBuilderTestsBase
{
    protected Mock<IFileSystemUtils> fileSystemUtilsMock;
    private protected IMapper mapper;
    protected ConfigValidator[] configValidators;
    protected Mock<IAssemblyConfig> mockAssemblyConfig;

    protected void Init()
    {
        fileSystemUtilsMock = new Mock<IFileSystemUtils>();
        mockAssemblyConfig = new Mock<IAssemblyConfig>();
        mockAssemblyConfig.SetupGet(a => a.DefaultManifestInfoForValidationAction).Returns(Constants.TestManifestInfo);
        mockAssemblyConfig.SetupGet(a => a.DefaultManifestInfoForGenerationAction).Returns(Constants.TestManifestInfo);

        configValidators = new ConfigValidator[]
        {
            new ValueRequiredValidator(mockAssemblyConfig.Object),
            new FilePathIsWritableValidator(fileSystemUtilsMock.Object, mockAssemblyConfig.Object),
            new IntRangeValidator(mockAssemblyConfig.Object),
            new FileExistsValidator(fileSystemUtilsMock.Object, mockAssemblyConfig.Object),
            new DirectoryExistsValidator(fileSystemUtilsMock.Object, mockAssemblyConfig.Object),
            new DirectoryPathIsWritableValidator(fileSystemUtilsMock.Object, mockAssemblyConfig.Object),
            new UriValidator(mockAssemblyConfig.Object),
            new ManifestInfoValidator(mockAssemblyConfig.Object, new HashSet<ManifestInfo> { Constants.SPDX22ManifestInfo }) // We only need 1 for testing
        };

        var hashAlgorithmProvider = new HashAlgorithmProvider(new IAlgorithmNames[] { new AlgorithmNames() });
        hashAlgorithmProvider.Init();

        var configSanitizer = new ConfigSanitizer(hashAlgorithmProvider, fileSystemUtilsMock.Object, mockAssemblyConfig.Object);
        object Ctor(Type type)
        {
            if (type == typeof(ConfigPostProcessor))
            {
                return new ConfigPostProcessor(configValidators, configSanitizer, fileSystemUtilsMock.Object);
            }

            return Activator.CreateInstance(type);
        }

        var mapperConfiguration = new MapperConfiguration(cfg =>
        {
            cfg.ConstructServicesUsing(Ctor);
            cfg.AddProfile<ConfigurationProfile>();
        });

        mapper = mapperConfiguration.CreateMapper();
    }

    protected const string JSONConfigWithManifestPath = "{ \"ManifestDirPath\": \"manifestDirPath\"}";
    protected const string JSONConfigGoodWithManifestInfo = "{ \"ManifestInfo\": [{ \"Name\":\"SPDX\", \"Version\":\"2.2\"}]}";
}
