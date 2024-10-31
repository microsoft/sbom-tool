# SBOM Tool CLI Reference

## Installation

The SBOM tool CLI is distributed through [GitHub Releases](https://github.com/microsoft/sbom-tool/releases). The tool is packaged as a single platform-dependent executable file. Executable platform-specific and release-specific versions of the tool are available for download at [latest](https://github.com/microsoft/sbom-tool/releases/latest). Users can also download the executable file for each of the binaries for verification.

| Platform | Binary filename           | SBOM filename                    |
|----------|-----------------------|------------------------------|
| Windows  | sbom-tool-win-x64.exe | win-x64-manifest.spdx.json   |
| Linux    | sbom-tool-linux-x64   | linux-x64-manifest.spdx.json |
| MacOS    | sbom-tool-osx-x64     | osx-x64-manifest.spdx.json   |

## Running the tool

A user has a `dotnet` project for which they are building a SBOM. In this example case, the source for the project lives in `c:\Users\test\TestProject`.

The user may first build the above project by running the following command, which should build the project and place all binaries in the `c:\outputDrop` folder.

```powershell
dotnet build --output c:\outputDrop
```

Now the user can generate a SBOM for the above project by running the tool they just downloaded:

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com
```

In this scenario, the user configured the sbom tool to generate an SBOM for all the files in the `c:\outputDrop` folder.  The sbom tool will search the `c:\Users\test\TestProject` path for *.csproj or packages.config files in order to build the list of dependency packages for inclusion in the SBOM file. The -pn and -pv parameters configure the package name and version.  A globally-unique -nsb parameter specifies the namespace base URI for use in documentation of the namespace in the final SPDX 2.2-formatted SBOM file.  If the command fails to provide the -nsb parameter, then the tool will provide a default globally-unique namespace base URI that complies with the SPDX 2.2 specifications.

By default, the tool will place the generated SBOM inside the `_manifest\spdx_2.2\` subfolder under the path which the -b argument specifies. In this example, the SBOM will be located here: `c:\outputDrop\_manifest\spdx_2.2\manifest.spdx.json`

Successful runs of the tool require full write permissions for the path specified in the -b argument.  Users encountering errors when the tool is attempting to write the `_manifest\spdx_2.2\` subfolder should consider these steps:

1. If someone else controls the user's network or hardware settings (such as employer-owned infrastructure), contact the respective network administrator(s) for assistance.
2. If the user controls their own infrastructure, review and (as needed) update folder security and attribute settings.  Consult the hardware manufacturer or user support communities as needed for further assistance.
3. Update the path specified in the -b argument to an externally connected hard drive or another alternate folder located off-device.

Common errors in these situations may include variations of these messages:

```text
## [error]Encountered an error while generating the manifest.
## [error]Error details: Could not find file `c:\outputDrop\_manifest\spdx_2.2\manifest.spdx.json`.
```

The above list contains the minimum mandatory parameters that the user needs to provide in order for the tool to generate the SBOM file.  A full list of arguments is listed in [here](sbom-tool-arguments.md).

## Common scenarios where the user can provide additional parameters

### Place the generated SBOM in a separate folder

By default, the tool will generate SBOM file in a newly created subfolder called `_manifest` inside the BuildDropPath (-b).  In case the user wants to place the SBOM in a different path, specify the `ManifestDirPath -m` parameter, e.g.:

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -m c:\sboms
```

This command will cause the SBOM tool to generate the SBOM inside the `c:\sboms` folder. The tool will create a new `_manifest\spdx_2.2` subfolder for use in storing the SBOM being generated. In this scenario, the tool will store the SBOM generated during this run in the path `c:\sboms\_manifest\spdx_2.2\manifest.spdx.json`.

> Please note that the tool will generate the `_manifest` subfolder inside the ManifestDirPath folder.  The command will not need to provide a folder path that ends in `_manifest` for this parameter.

### Get verbose logging

The user can specify verbose logging just by specifying the -V parameter, e.g:

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -V Verbose
```

### Scan docker images for dependency packages

Users can scan docker images in order to determine dependency packages.  In this scenario, the user wants to gather dependencies from the docker image `testImage:0.0.1`.  The user can run the following command:

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -di testImage:0.0.1
```

In addition to the test image, the user may also want to gather all dependencies in a build machine named `ubuntu:1.9`.  The command can specify multiple image arguments for this parameter by separating them with a comma:

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -di testImage:0.0.1,ubuntu:1.9
```

The arguments for `-b` and `-bc` will specify the path that the tool will scan. For example, the user can generate an SBOM for only the dependency packages of the Docker image with the command:

```shell
./sbom-tool-win-x64.exe generate -m c:\outputPath -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -di testImage:0.0.1
```

`-m` provides the user-defined path for generating the SBOM. The tool will generate a new `_manifest\spdx_2.2` subfolder which will hold the SBOM file created during this run. The files section for these parameters will be empty as this run will only scan for the dependency packages of the image.

In order to scan a path to populate the files section of the SBOM, the user can run the following command:

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -m c:\outputPath -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -di testImage:0.0.1
```

### Excluding Directories from Component Scan

You can exclude directories from the component scan by specifying the `-cd` parameter you can pass arguments directly to Component Detection. One of these arguments is `--DirectoryExclusionList`  Filters out specific directories following a minimatch pattern from the component scan which will leave
the contents of these directories out of the packages section of the SBOM. For example, if you wanted to exclude the `bin` directory from the component scan you would run the following command

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -cd "--DirectoryExclusionList **/bin/**"
```

You can give multiple exclusion patterns by repeating the `--DirectoryExclusionList` argument. (Note that minimatch combines like `**/bin/**|**/obj/**` won't work):

```shell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -cd "--DirectoryExclusionList **/bin/** --DirectoryExclusionList **/obj/**"
```

### Write telemetry to a file

By default, users commonly log telemetry to the console output. In order to log the telemetry as part of the SBOM file, specify the `-t` parameter:

```powershell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -t c:\telemetry
```

## Validating an SBOM

With a SBOM file in hand, use the tool to validate the output file with the command:

```powershell
./sbom-tool-win-x64.exe validate -b c:\outputDrop -o c:\validationOutputPath\output.json -mi SPDX:2.2
```

This sample command provides the minimum mandatory arguments required to validate an SBOM:
     `-b` should be the path same path used to generate the SBOM file.
     In this scenario, the tool will default to searching for an SBOM at the `c:\outputDrop\_manifest\spdx_2.2\manifest.spdx.json` path.
     `-o` is the output path where the tool will write the validation results. This path can be any file path on the system. In this case the tool will look for the validationOutputPath directory, create a file named output.json, and write the validation output.
     `-mi` is the ManifestInfo, which provides the user's desired name and version of the manifest format.

Currently only SPDX2.2 is supported.

## Common scenarios where users can provide additional parameters

### SBOM was placed in a different folder

If the original command created the SBOM files with the following parameters:

```powershell
./sbom-tool-win-x64.exe generate -b c:\outputDrop -bc c:\Users\test\TestProject -pn TestProject -pv 1.0.0 -ps MyCompany -nsb http://mycompany.com -m c:\sboms
```

Then the SBOM will not be located at the default location. In order to allow the tool to validate the SBOM at the different location, the user must provide the path to the `_manifest` subfolder that was created in that directory:

```powershell
./sbom-tool-win-x64.exe validate -b c:\outputDrop -o c:\validationOutputPath\output.json -mi SPDX:2.2 -m c:\sboms\_manifest
```

### Additional parameters

Verbose logging and writing telemetry to a file will function in the same way they do when generating an SBOM. Here is an example of using both parameters when validating and SBOM:

```powershell
./sbom-tool-win-x64.exe validate -b c:\outputDrop -o c:\validationOutputPath\output.json -mi SPDX:2.2 -t c:\telemetry -V verbose
```
