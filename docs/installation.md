# Installation

## Dotnet tool
Please add and authenticate the Microsoft GitHub NuGet package registry to your nuget.config. Then, run the following command to install the [tool](https://docs.microsoft.com/en-us/dotnet/core/tools/global-tools) globally

`dotnet tool install -g Microsoft.Sbom.Tool`

You can then run the tool using the command

`dotnet tool run sbomtool <arguments>`

Please check the [arguments](sbom-tool-arguments.md) that you can provide to the sbom tool.


## Windows, Mac and Linux executable.
Please check the ['Releases'](https://github.com/microsoft/sbom-tool/releases) page to go to the version of the tool you want to install. Then download the tool from the release assets for the required runtime. 

Please check the [arguments](sbom-tool-arguments.md) that you can provide to the sbom tool.

## Sbom tool C# Api
Please add and authenticate the Microsoft GitHub NuGet package registry to your nuget.config. Then install the `Microsoft.Sbom.Api` package to your project using these [instructions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-nuget-registry#installing-a-package)
