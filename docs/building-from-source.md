# Building the SBOM tool from source.

The SBOM tool is a cross-platform tool written in C# and is compiled using .NET 6. Follow the instructions below to build the tool from source.

## Prerequisites
* Please download and install [Dotnet SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) version 6.0.400 or greater.
* Clone this GitHub repo (See steps to clone repo [here](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository)).
* A text editor or IDE like [Visual Studio Code](https://code.visualstudio.com) or [Visual Studio](https://visualstudio.microsoft.com).

## Understanding the source structure

All the source code for the tool lives in the `src` folder, and the tests in the `test` folder. The core engine that drives the sbom tool to generate SBOMs lives in the `Microsoft.Sbom.Api` project. 

The code is designed to be as extensible as possible and all the interfaces that can be use to extend the SBOM tool are placed in the `Microsoft.Sbom.Extensions` project. Once such extension is the `IManifestGenerator` interface. The SBOM tool uses this interface to serialize a SBOM to a specific format, in our case, the `Microsoft.Sbom.Parsers.Spdx22SbomParser` project implements this interface and allows the SBOM tool to serialize a SBOM to specifically the SPDX 2.2 format. The extensions project has additional interfaces that are used to extend the SBOM tool.

The `Microsoft.Sbom.Common` project contains any common code, constants, etc that are used by all the projects in this solution.

The `Microsoft.Sbom.Contracts` project defines the interfaces that are used to call the SBOM tool through a C# API. The `ISBOMGenerator` class defines two methods that can be used to directly call the SBOM tool from C# code directly. The `Microsoft.Sbom.Tool` project defines a CLI interface to talk to the SBOM tool.

## Building on Visual Studio 

Start Visual Studio 2022, and open the Microsoft.Sbom.sln file in the root of the repository. You can press `Ctrl + Shift + b` or select Build from the menu to build the application.

1. Set the Microsoft.Sbom.Tool project as the startup project (rightclick-> Set as Startup Project)
1. Set Run arguments for the Microsoft.Sbom.Tool project (rightclick->properties->Debug)  
	*Minimum:* `generate -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -ps <company name> -nsb <namespace uri base>`
1. Now, any time you make a change, you can press `F5`. This will build the changes, and start the process in debug mode (hitting any breakpoints you set)

You can follow [this](https://www.youtube.com/watch?v=iC3CJcYxkl0&t=31s) small tutorial to get started with Visual Studio.

## Building on the command line

Go to the shell of your choice, make sure that the Dotnet SDK is installed and available on the `PATH` for the shell. Navigate to the root of the repository and execute the following command to build the repository.

```
dotnet build
```

You can run the tool using this minimal command

```
dotnet run --project src/Microsoft.Sbom.Tool generate -- -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -ps <company name> -nsb <namespace uri base>
```

## Building using Codespaces

If you have access to [GitHub Codespaces](https://docs.github.com/en/free-pro-team@latest/github/developing-online-with-codespaces/about-codespaces), select the `Code` button from the [repository homepage](https://github.com/microsoft/sbom-tool) then select `Open with Codespaces`. That's it! You have a full developer environment that supports debugging, testing, auto complete, jump to definition, everything you would expect.

## Building using Docker

Make sure you use linux system.

Clone this repo and build the docker image.

```bash
git clone https://github.com/microsoft/sbom-tool
cd sbom-tool
docker build . -t ms_sbom_tool
```

You can then use the tool, by mounting the directories to be scanned using docker bind mounts.
