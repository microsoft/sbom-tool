# Sbom tool arguments on Windows

```
dotnet run -p src/Microsoft.Sbom.Tool generate -- -h
```

```

The Sbom tool generates a SBOM for any build artifact.


GlobalOption    Description
Help (-?, -h)   Prints this help message

Generate - Generate a SBOM for all the files in the given build drop folder, and the packages in the components path.

Usage - Microsoft.Sbom.Tool Generate -options

Generate Options
Option                                    Description
BuildDropPath (-b)                        The root folder of the drop directory for which the manifest file will be
                                          generated.
BuildComponentPath (-bc)                  The folder containing the build components and packages.
BuildListFile (-bl)                       The file path to a file containing a list of files one file per line for
                                          which the manifest file will be generated. Only files listed in the file
                                          will be inlcuded in the generated manifest.
ManifestDirPath (-m)                      The path of the directory where the generated manifest files will be
                                          placed. If this parameter is not specified, the files will be placed in
                                          {BuildDropPath}/_manifest directory.
PackageName (-pn)                         The name of the package this SBOM represents. If this is not provided, we
                                          will try to infer this name from the build that generated this package,
                                          if that also fails, the SBOM generation fails.
PackageVersion (-pv)                      The version of the package this SBOM represents. If this is not provided,
                                          we will try to infer the version from the build that generated this
                                          package, if that also fails, the SBOM generation fails.
DockerImagesToScan (-di)                  Comma separated list of docker image names or hashes to be scanned for
                                          packages, ex: ubuntu:16.04, 56bab49eef2ef07505f6a1b0d5bd3a601dfc3c76ad4460
                                          f24c91d6fa298369ab.
AdditionalComponentDetectorArgs (-cd)     Additional set of arguments for Component Detector.  An appropriate usage
                                          of this would be a space-delimited list of `--key value` pairs,
                                          respresenting command-line switches.
ExternalDocumentReferenceListFile (-er)   The path to a file containing a list of external SBOMs that will be
                                          included as external document reference in the output SBOM. SPDX 2.2 is
                                          the only supported format for now.
NamespaceUriUniquePart (-nsu)             A unique valid URI part that will be appended to the SPDX SBOM namespace
                                          URI. This value should be globally unique.
NamespaceUriBase (-nsb)                   The base path of the SBOM namespace URI.
GenerationTimestamp (-gt)                 A timestamp in the format 'yyyy-MM-ddTHH:mm:ssZ' that will be used as the
                                          generated timestamp for the SBOM.
Verbosity (-V)                            Display this amount of detail in the logging output.
                                          Verbose
                                          Debug
                                          Information
                                          Warning
                                          Error
                                          Fatal
Parallelism (-P)                          The number of parallel threads to use for the workflows.
ConfigFilePath (-C)                       The json file that contains the configuration for the DropValidator.
TelemetryFilePath (-t)                    Specify a file where we should write detailed telemetry for the workflow.
FollowSymlinks (-F)                       If set to false, we will not follow symlinks while traversing the build
                                          drop folder. Default is set to 'true'.
ManifestInfo (-mi)                        A list of the name and version of the manifest format that we are using.


```

# Sbom tool arguments for Linux on x86_64
```
./sbom-tool-linux-x64 [validate|generate] [options...]

Startup:
  -h,  --help                      print this help

Options
-b      The root folder of the drop directory to validate.
-bc     Only for "generate" action. The folder containing the build components and packages.
-bl     Only for "generate" action. The file path to a file containing a list of files one file per line for which the manifest file will be generated. Only files listed in the file will be inlcuded in the generated manifest.
-cd     Only for "generate" action. Additional set of arguments for Component Detector.  An appropriate usage of this would be a space-delimited list of `--key value` pairs, respresenting command-line switches.
-C      The path of signed catalog file that is used to verify the signature of the manifest json file.
-Co     Only for "validate" action.The json file that contains the configuration for the DropValidator.
-di     Only for "generate" action. Comma separated list of docker image names or hashes to be scanned for packages, ex: ubuntu:16.04, 56bab49eef2ef07505f6a1b0d5bd3a601dfc3c76ad4460f24c91d6fa298369ab.
-er     Only for "generate" action. The path to a file containing a list of external SBOMs that will be included as external document reference in the output SBOM. SPDX 2.2 is the only supported format for now.
-F      If set to false, we will not follow symlinks while traversing the build drop folder. Default is set to 'true'.
-gt     Only for "generate" action. A timestamp in the format 'yyyy-MM-ddTHH:mm:ssZ' that will be used as the generated timestamp for the SBOM.
-Ha     Only for "generate" action. The Hash algorithm to use while verifying or generating the hash value of a file
-im     Only for "generate" action. If set, will not fail validation on the files presented in Manifest but missing on the disk.
-m      Only for "generate" action. The path of the directory where the manifest is. Default is set to: {BuildDropPath}/_manifest.
-mi     A list of the name and version of the manifest format that we are using.
-nsu    Only for "generate" action. A unique valid URI part that will be appended to the SPDX SBOM namespace URI. This value should be globally unique.
-nsb    Only for "generate" action. The base path of the SBOM namespace URI.
-o      Only for "generate" action. The path where the output json should be written.
-pn     Only for "generate" action. The name of the package this SBOM represents. If this is not provided, we will try to infer this name from the build that generated this package, if that also fails, the SBOM generation fails.
-pv     Only for "generate" action. The version of the package this SBOM represents. If this is not provided, we will try to infer the version from the build that generated this package, if that also fails, the SBOM generation fails.
-P      The number of parallel threads to use for the workflows.
-r      Only for "generate" action. If you're downloading only a part of the drop using the '-r' or 'root' parameter in the drop client, specify the same string value here in order to skip validating paths that are not downloaded.
-s      Only for "generate" action. If set, will validate the manifest using the signed catalog file.
-t      Specify a file where we should write detailed telemetry for the workflow.
-V      Display detail in the logging output: Verbose, Debug, Information, Warning, Error, Fatal
```