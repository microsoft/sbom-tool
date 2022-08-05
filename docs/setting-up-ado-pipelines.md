# Adding SBOM generation to your Azure DevOps Pipeline

This document provides an example on how to integrate SBOM tool into Azure DevOps Pipelines, you may use this as a guide to adding the tool to your Azure DevOps Pipeline.

## Existing setup

In our Azure DevOps project, the source contains a project called Demo. We also have a Build pipeline that builds the project and saves the generated binaries as a pipeline artifact.

```yaml
pool:
  vmImage: ubuntu-latest

steps:
- task: UseDotNet@2
  inputs:
    packageType: 'sdk'
    version: '6.x'

- script: |
    dotnet build $(Build.SourcesDirectory)/Demo.csproj --output $(Build.ArtifactStagingDirectory)
  displayName: 'Build the project'

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)'
    ArtifactName: 'drop'
    publishLocation: 'Container'
```

In this pipeline, we first build the dotnet project and the generated binaries are stored in the artifacts staging directory. In the final step, we upload these artifacts to the pipline artifacts. Any dependent pipeline or release can now consume these binaries using this pipeline artifact. You can check the build pipeline artifacts for our project, and we see a bunch of binaries generated for the Demo project.

![ado-artifact-without-sbom](./images/ado-artifacts-without-sbom.png)

## Adding the SBOM generation task

We will generate the SBOM for the pipeline artifacts we generate in the previous step. We will store the generated SBOM as part of the pipeline artifacts, as we will be distributing this artifact to our downstream dependencies. 

```yaml
pool:
  vmImage: ubuntu-latest

steps:
- task: UseDotNet@2
  inputs:
    packageType: 'sdk'
    version: '6.x'

- script: |
    dotnet build $(Build.SourcesDirectory)/Demo.csproj --output $(Build.ArtifactStagingDirectory)
  displayName: 'Build the project'

- script: |
    curl -Lo $(Agent.TempDirectory)/sbom-tool https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-linux-x64
    chmod +x $(Agent.TempDirectory)/sbom-tool
    $(Agent.TempDirectory)/sbom-tool generate -b $(Build.ArtifactStagingDirectory) -bc $(Build.SourcesDirectory) -pn Test -pv 1.0.0 -ps MyCompany -nsb https://sbom.mycompany.com -V Verbose
  displayName: Generate SBOM

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)'
    ArtifactName: 'drop'
    publishLocation: 'Container'
```

We added the SBOM generation task after the build ran and produced artifacts in the `$(Build.ArtifactStagingDirectory)` directory. The `$(Build.SourcesDirectory)` folder contains the `Demo.csproj` file that contains the dependencies for our project, so we pass it as the parameter to the build components path. The package name, version and namespace base uri are static strings for our tool. We also have set verbosity to `Verbose` right now as we want to see additional output while we test our SBOM generation.

Since our tool will place the generation SBOM in the build drop folder (`$(Build.ArtifactStagingDirectory)` folder in our case), our original artifact upload task now also uploads the SBOM to the Actions artifacts as seen below.

![ado-artifact-with-sbom](./images/ado-artifacts-with-sbom.png)

With the above our SBOM has the same retention as the pipeline artifacts for the Azure DevOps pipeline.

## Further reading

If your team uses a central repository to store SBOMs, you can generate the SBOM to a special folder using the `-manifestDirPath` parameter, and upload the generated file to the central repository.