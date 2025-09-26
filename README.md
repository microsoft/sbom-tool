# SBOM Tool

![GitHub all releases](https://img.shields.io/github/downloads/microsoft/sbom-tool/total)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/microsoft/sbom-tool?include_prereleases)

## Introduction

The SBOM tool is a highly scalable and enterprise ready tool to create SPDX 2.2 and SPDX 3.0 compatible SBOMs for any variety of artifacts. The tool uses the [Component Detection](https://github.com/microsoft/component-detection) libraries to detect components and the [ClearlyDefined](https://github.com/clearlydefined/clearlydefined) API to populate license information for these components.

## Table of Contents

* [Download and Installation](#download-and-installation)
* [Run the tool](#run-the-tool)
* [Integrating SBOM tool to your CI/CD pipelines](#integrating-sbom-tool-to-your-cicd-pipelines)
* [Telemetry](#telemetry)
* [Contributing](#contributing)
* [Security](#security)
* [Trademarks](#trademarks)

## Download and Installation

### Executables for Windows, Linux, macOS

We distribute executables and SBOM files of the tool in [GitHub Releases](https://github.com/microsoft/sbom-tool/releases) page. You can go and download binaries manually or use commands below to get the latest version of the tool for your platform.

Please check the [CLI Reference](docs/sbom-tool-cli-reference.md) document for additional help regarding the CLI tool.

#### Package managers

##### WinGet

```shell
winget install Microsoft.SbomTool
```

##### Homebrew

```shell
brew install sbom-tool
```

#### Manual download

##### Windows (PowerShell)

```powershell
Invoke-WebRequest -Uri "https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-win-x64.exe" -OutFile "sbom-tool.exe"
```

##### Linux (curl)

```bash
curl -Lo sbom-tool https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-linux-x64
chmod +x sbom-tool
```

##### macOS (curl)

```bash
curl -Lo sbom-tool https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-osx-x64
chmod +x sbom-tool
```

#### Building SBOM tool as docker image

Clone this repo and build the docker image.

```bash
git clone https://github.com/microsoft/sbom-tool
cd sbom-tool
docker build . -t ms_sbom_tool
```

You can then use the tool normally, by mounting the directories to be scanned using docker bind mounts.

### SBOM .NET Tool

The sbom-tool can also be installed as a .NET tool using the following command:

```powershell
dotnet tool install --global Microsoft.Sbom.DotNetTool
```

### SBOM API NuGet package

Please add and authenticate the Microsoft GitHub NuGet package [registry](https://github.com/orgs/microsoft/packages?repo_name=sbom-tool) to your nuget.config. Then install the `Microsoft.Sbom.Api` package to your project using these [instructions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-nuget-registry#installing-a-package)

Please check the [API Reference](docs/sbom-tool-api-reference.md) document for additional help regarding the SBOM tool C# Api.

## Run the tool

### SBOM Generation

Once you have installed the command line tool for your OS, run the tool using this command:

```
sbom-tool generate -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -ps <package supplier> -nsb <namespace uri base>
```

The drop path is the folder where all the files to be shipped are located. All these files will be hashed and added to the files section of the SBOM. The build components path is usually your source folder, tool will scan this folder to search for project files like *.csproj or package.json to see what components were used to build the package. Tool uses [component-detection](https://github.com/microsoft/component-detection) to scan for components and dependencies, visit its Github page to get more information about supported components. The package name and version represent the package the SBOM is describing.

Each SBOM has a unique namespace that uniquely identifies the SBOM, we generate a unique identifier for the namespace field inside the SBOM, however we need a base URI that would be common for your entire organization. For example, a sample value for the `-nsb` parameter could be `https://companyName.com/teamName`, then the generator will create the namespace that would look like `https://companyName.com/teamName/<packageName>/<packageVersion>/<new-guid>`. Read more about the document namespace field [for SPDX 2.2](https://spdx.github.io/spdx-spec/v2.2.2/document-creation-information/#65-spdx-document-namespace-field) and [for SPDX 3.0 where it is part of namespaceMap](https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/SpdxDocument/).

Generation defaults to using SPDX 2.2. However you can modify the command to generate an SPDX 3.0 SBOM by adding the `-mi` argument with the value `SPDX:3.0` like below:
```
sbom-tool generate -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -ps <package supplier> -nsb <namespace uri base> -mi SPDX:3.0
```

A more detailed list of available CLI arguments for the tool can be found [here](docs/sbom-tool-arguments.md)

### SBOM Validation

With an SBOM file in hand, use the tool to validate the output file with either command depending on the SPDX version:

```
sbom-tool validate -b <drop path> -o <output path> -mi SPDX:2.2
sbom-tool validate -b <drop path> -o <output path> -mi SPDX:3.0
```

This sample command provides the minimum mandatory arguments required to validate an SBOM:
     `-b` should be the same path used to generate the SBOM file.
     In the first scenario above, the tool will default to searching for an SBOM at the `<drop path>\_manifest\spdx_2.2\manifest.spdx.json` path.
     In the first scenario above, the tool will default to searching for an SBOM at the `<drop path>\_manifest\spdx_3.0\manifest.spdx.json` path.
     `-o` is the output path, including file name, where the tool should write the results to.
     `-mi` is the ManifestInfo, which provides the user's desired name and version of the manifest format.

### SBOM Redact

Use the tool to redact any references to files from a given SBOM or set of SBOMs with either of the following commands:

```
sbom-tool redact -sd <directory containing SBOMs to redact> -o <output path>
```

```
sbom-tool redact -sp <path to the SBOM to redact> -o <output path>
```

This command will generate a mirrored set of SBOMs in the output directory, but with the file references removed. Note that the SBOM directory and output path arguments can not reference the same directory and the output path should point to an existing, empty directory.

Currently we only support redacting SPDX 2.2 SBOMs.

## Integrating SBOM tool to your CI/CD pipelines

You can follow these guides to integrate the SBOM tool into your CI/CD pipelines

* [Setting up GitHub Actions to use the SBOM tool](docs/setting-up-github-actions.md).
* [Setting up Azure DevOps Pipelines to use the SBOM tool](docs/setting-up-ado-pipelines.md).

## Telemetry

By default, telemetry will output to your output file path and will be a JSON blob. No data is submitted to Microsoft.

## Contributing

This project does not accept open-source contributions due to the sensitive, regulatory nature of SBOMs. If you are external to Microsoft and need modifications to the tool, you are welcome to fork and maintain a version of the tool.
If you are internal, please contact SBOM Support to discuss your scenario.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Security

Microsoft takes the security of our software products and services seriously, which includes all source code repositories managed through our GitHub organizations, which include [Microsoft](https://github.com/Microsoft), [Azure](https://github.com/Azure), [DotNet](https://github.com/dotnet), [AspNet](https://github.com/aspnet), [Xamarin](https://github.com/xamarin), and [our GitHub organizations](https://opensource.microsoft.com/).

If you believe you have found a security vulnerability in any Microsoft-owned repository that meets [Microsoft's definition of a security vulnerability](https://aka.ms/opensource/security/definition), please report it to us as described in the [Security.md](https://github.com/microsoft/sbom-tool/blob/main/SECURITY.md).

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
