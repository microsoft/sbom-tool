# Building the SBOM tool from source code.

The SBOM tool is a cross-platform, C#-based tool compiled using the  Microsoft .NET 6 cross-platform, open-source developer platform. Follow the instructions provided which will guide the user in building the sbom tool from the source file.

## Prerequisites
* Download and install [Dotnet SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) version 6.0.400 or later.
* Clone this GitHub repo (see steps to clone repo [here](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository)).
* A text editor or integrated development environment (IDE) such as [Visual Studio Code](https://code.visualstudio.com) or [Visual Studio](https://visualstudio.microsoft.com).

## Understanding the source structure

Users can find source files in the following folder locations:
* All the source code for the tool: `src` folder
* Tests: `test` folder
* The core engine (generates SBOMs): `Microsoft.Sbom.Api` project

The sbom tool code is designed to be as extensible as possible. All the interfaces for extending the SBOM tool are located in the `Microsoft.Sbom.Extensions` project. Once such extension is the `IManifestGenerator` interface, which the SBOM tool uses to serialize a SBOM to a specific format.  The `Microsoft.Sbom.Parsers.Spdx22SbomParser` project implements this interface, allowing the SBOM tool to serialize a SBOM in accordance with the prescribed SPDX version 2.2 standard format. The extensions project has additional interfaces designed to extend the SBOM tool.

The `Microsoft.Sbom.Common` project contains the base of common code, constants, etc. that all the projects can call.

The `Microsoft.Sbom.Contracts` project defines the interfaces that the tool uses to call the SBOM tool using a C# API. The `ISBOMGenerator` class defines two methods that the tool uses to directly call the SBOM tool from C# code. The `Microsoft.Sbom.Tool` project defines a command line interface (CLI) interface to talk to the SBOM tool.

## Building on Visual Studio 

After opening the Visual Studio 2022 application, open the Microsoft.Sbom.sln file in the root of the repository. Users can either press `Ctrl + Shift + B` or select Build from the menu in order to build the application.

1. Set the Microsoft.Sbom.Tool project as the startup project (rightclick-> Set as Startup Project)
2. Set Run arguments for the Microsoft.Sbom.Tool project (rightclick->properties->Debug)  
	*Minimum:* `generate -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -ps <company name> -nsb <namespace uri base>`
3. Going forward, users can press 'F5' after making changes. This action will build the changes and start the process in debug mode (stopping at breakpoints).

A good new-user tutorial for Visual Studio is available at [this](https://www.youtube.com/watch?v=iC3CJcYxkl0&t=31s).

## Building on the command line

In the user's shell of choice, ensure that the Dotnet SDK is installed and available on the `PATH` for the shell. Navigate to the root of the repository, then execute the following command for building the repository:

```
dotnet build
```

Users can run the sbom tool using this command which contains the minimum required set of paramaters:

```
dotnet run --project src/Microsoft.Sbom.Tool generate -- -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -ps <company name> -nsb <namespace uri base>
```

## Building using Codespaces

After accessing [GitHub Codespaces](https://docs.github.com/en/free-pro-team@latest/github/developing-online-with-codespaces/about-codespaces), select the `Code` button from the [repository homepage](https://github.com/microsoft/sbom-tool), then select `Open with Codespaces`. That's it!  Users will then have a full developer environment that supports debugging, testing, auto complete, jump to definitions, and everything that one would expect.

## Building using Docker

Follow applicable steps or procedures for starting up the applicable Linux distribution.

Clone this repo.

Build the docker image.

```bash
git clone https://github.com/microsoft/sbom-tool
cd sbom-tool
docker build . -t ms_sbom_tool
```

Use docker bind mounts when using the tool to scan the desired target directories.
