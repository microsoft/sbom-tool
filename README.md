# Salus - SBOM Tool

[![Build](https://github.com/microsoft/sbom-tool/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/microsoft/sbom-tool/actions/workflows/build.yml)
[![GitHub release (latest by date)](https://img.shields.io/github/downloads/microsoft/sbom-tool/latest/total)](https://img.shields.io/github/downloads/microsoft/sbom-tool/total)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/microsoft/sbom-tool?include_prereleases)

## Introduction

The SBOM tool is a highly scalable and enterprise ready tool to create SPDX 2.2 compatible SBOMs for any variety of artifacts.

## Table of Contents

* [Installation](#installation)
* [Run the tool](#run-the-tool-to-generate-an-sbom)
* [Telemetry](#Telemetry)
* [Contributing](#Contributing)
* [Security](#Security)
* [Trademarks](#Trademarks)

## Installation

### Windows, Mac and Linux executable.
Please check the [Releases](https://github.com/microsoft/sbom-tool/releases) page to go to the version of the tool you want to install. Then download the tool from the release assets for the required runtime. 

Please check the [arguments](docs/sbom-tool-arguments.md) that you can provide to the sbom tool.

### Sbom tool C# Api
Please add and authenticate the Microsoft GitHub NuGet package [registry](https://github.com/orgs/microsoft/packages?repo_name=sbom-tool) to your nuget.config. Then install the `Microsoft.Sbom.Api` package to your project using these [instructions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-nuget-registry#installing-a-package)

## Run the tool to generate an SBOM

Once you have installed the command line tool for your OS, run the tool using this command:

```
generate -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -nsb <namespace uri base>
```

The drop path is the folder where all the files to be shipped are located. All these files will be hashed and added to the files section of the SBOM. The build components path is usually your source folder, we will scan this folder to search for project files like *.csproj or package.json to see what components were used to build the package. The package name and version represent the package the SBOM is describing. 

Each SBOM has a unique namespace that uniquely identifies the SBOM, we generate a unique identifier for the namespace field inside the SBOM, however we need a base URI that would be common for your entire organization. For example, a sample value for the `-nsb` parameter could be `https://companyName.com/teamName`, then the generator will create the namespace that would look like `https://companyName.com/teamName/<packageName>/<packageVersion>/<new-guid>`. Read more about the document namespace field [here](https://spdx.github.io/spdx-spec/document-creation-information/#65-spdx-document-namespace-field). 

A more detailed list of available arguments can be found [here](docs/sbom-tool-arguments.md)

## Telemetry

By default, telemetry will output to your output file path and will be a JSON blob. No data is submitted to Microsoft.

## Contributing

Please follow the steps [here](docs/build-and-run.md) to clone and build this repository from source.

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

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
