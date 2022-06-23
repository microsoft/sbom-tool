# Build and run the Sbom tool

## Prerequisites
* In order to build the SBOM tool, please download and install [Dotnet SDK](https://dotnet.microsoft.com/en-us/download/dotnet/3.1) version 3.1.300 or greater.
* Clone this GitHub repo.

## Running from command line
Execute the following dotnet command from the root of the sbom tool repo to build the tool.
```
dotnet build
````
The most basic run:
```
dotnet run --project src/Microsoft.Sbom.Tool generate -b <drop path> -pn <package name> -pv <package version> -nsb <namespace uri base>
```
You can add `--no-restore` or `--no-build` if you don't want to rebuild before the run
	
You can add `--Debug` to get the application to wait for debugger attachment to complete.

## Running in Visual Studio (2019+)
1. open [Microsoft.Sbom.sln](../Microsoft.Sbom.sln) in Visual Studio
1. Set the Microsoft.Sbom.Tool project as the startup project (rightclick-> Set as Startup Project)
1. Set Run arguments for the Microsoft.Sbom.Tool project (rightclick->properties->Debug)  
	*Minimum:* `generate -b <drop path> -pn <package name> -pv <package version> -nsb <namespace uri base>`
1. Now, any time you make a change, you can press `F5`. This will build the changes, and start the process in debug mode (hitting any breakpoints you set)

## Using Codespaces

If you have access to [GitHub Codespaces](https://docs.github.com/en/free-pro-team@latest/github/developing-online-with-codespaces/about-codespaces), select the `Code` button from the [repository homepage](https://github.com/microsoft/sbom-tool) then select `Open with Codespaces`. That's it! You have a full developer environment that supports debugging, testing, auto complete, jump to definition, everything you would expect.

## Using VS Code DevContainer

This is similar to Codespaces:

1. Make sure you meet [the requirements](https://code.visualstudio.com/docs/remote/containers#_getting-started) and follow the installation steps for DevContainers in VS Code
1. `git clone https://github.com/microsoft/sbom-tool`
1. Open this repo in VS Code
1. A notification should popup to reopen the workspace in the container. If it doesn't, open the [`Command Palette`](https://code.visualstudio.com/docs/getstarted/tips-and-tricks#_command-palette) and type `Remote-Containers: Reopen in Container`.


## After building
A full list of arguments can be found in [here](sbom-tool-arguments.md)
