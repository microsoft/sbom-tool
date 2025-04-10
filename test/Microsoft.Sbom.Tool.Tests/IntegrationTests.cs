// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace Microsoft.Sbom.Tools.Tests;

[TestClass]
public class IntegrationTests
{
    private const string ManifestRootFolderName = "_manifest";
    private const string ManifestFileName = "manifest.spdx.json";

    private static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    public TestContext TestContext { get; set; }

    private static string testRunDirectory;
    private static string testDropDirectory;

    [ClassInitialize]
    public static void Setup(TestContext context)
    {
        testRunDirectory = context.TestRunDirectory;
        var executingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        testDropDirectory = Path.GetFullPath(Path.Combine(executingDirectory, "..", nameof(IntegrationTests)));
        Xcopy(executingDirectory, testDropDirectory);
    }

    [ClassCleanup(ClassCleanupBehavior.EndOfClass)]
    public static void TearDown()
    {
        // Clean up test directories
        if (testRunDirectory is not null)
        {
            if (Directory.Exists(testRunDirectory))
            {
                Directory.Delete(testRunDirectory, true);
            }
        }

        if (testDropDirectory is not null)
        {
            if (Directory.Exists(testDropDirectory))
            {
                Directory.Delete(testDropDirectory, true);
            }
        }
    }

    [TestMethod]
    public void TargetAppExists()
    {
        Assert.IsTrue(File.Exists(GetAppName()));
    }

    [TestMethod]
    public void E2E_NoParameters_DisplaysHelpMessage_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(null);

        Assert.AreEqual(stderr, string.Empty);
        Assert.IsTrue(stdout.Contains("Validate -options"));
        Assert.IsTrue(stdout.Contains("Generate -options"));
        Assert.IsTrue(stdout.Contains("Redact -options"));
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_GenerateManifest_GeneratesManifest_ReturnsZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);
    }

    [TestMethod]
    public void E2E_GenerateAndValidateSPDX22Manifest_ValidationSucceeds_ReturnsZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath);

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        Assert.AreEqual(0, exitCode.Value, $"Unexpected failure: stdout = {stdout}");
        Assert.IsTrue(File.Exists(outputFile), $"{outputFile} should have been created during validation");
        Assert.IsTrue(File.ReadAllText(outputFile).Contains("\"Result\":\"Success\"", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void E2E_GenerateAndValidateSPDX30Manifest_ValidationSucceeds_ReturnsZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: "3.0");

        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: "3.0");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        Assert.AreEqual(0, exitCode.Value, $"Unexpected failure: stdout = {stdout}");
        Assert.IsTrue(File.Exists(outputFile), $"{outputFile} should have been created during validation");
        Assert.IsTrue(File.ReadAllText(outputFile).Contains("\"Result\":\"Success\"", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void E2E_GenerateAndRedactManifest_RedactedFileIsSmaller_ReturnsZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var outputFolder = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "redacted");
        var originalManifestFolderPath = AppendFullManifestFolderPath(testFolderPath);
        var originalManifestFilePath = Path.Combine(AppendFullManifestFolderPath(testFolderPath), ManifestFileName);
        var arguments = $"redact -sp \"{originalManifestFilePath}\" -o \"{outputFolder}\" -verbosity verbose";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        Assert.AreEqual(0, exitCode.Value);
        Assert.IsTrue(stdout.Contains("Result=Success", StringComparison.OrdinalIgnoreCase));
        var redactedManifestFilePath = Path.Combine(outputFolder, ManifestFileName);
        var originalManifestSize = File.ReadAllText(originalManifestFilePath).Length;
        var redactedManifestSize = File.ReadAllText(redactedManifestFilePath).Length;
        Assert.IsTrue(redactedManifestSize > 0, "Redacted file must not be empty");
        Assert.IsTrue(redactedManifestSize < originalManifestSize, "Redacted file must be smaller than the original");
    }

    [TestMethod]
    public void E2E_GenerateAndRedactSPDX30Manifest_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: "3.0");

        var outputFolder = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "redacted");
        var originalManifestFolderPath = AppendFullManifestFolderPath(testFolderPath, spdxVersion: "3.0");
        var originalManifestFilePath = Path.Combine(originalManifestFolderPath, ManifestFileName);
        var arguments = $"redact -sp \"{originalManifestFilePath}\" -o \"{outputFolder}\" -verbosity verbose";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.IsTrue(stdout.Contains("Redaction is only supported for SPDX 2.2 currently. Please provide a valid SPDX 2.2 SBOM."), $"Unexpected output: {stdout}");
        Assert.AreEqual(1, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Generate_WithBadManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        var arguments = $"generate -ps IntegrationTests -pn IntegrationTests -pv 1.2.3 -m \"{testFolderPath}\" -b \"{testDropDirectory}\" -bc \"{GetSolutionFolderPath()}\" -mi randomName:randomVersion";
        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual("Please provide a valid value for the ManifestInfo (-mi) parameter. Supported values include: SPDX:2.2, SPDX:3.0. The values are case-insensitive.\r\n", stderr);
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithBadManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, "randomVersion");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual("Please provide a valid value for the ManifestInfo (-mi) parameter. Supported values include: SPDX:2.2, SPDX:3.0. The values are case-insensitive.\r\n", stderr);
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithBadComplianceStandard_SupportedManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: "3.0");

        // Add the compliance standard
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: "3.0", complianceStandardValue: "aeg12");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.IsTrue(stdout.Contains("Unknown Compliance Standard 'aeg12'. Options are NTIA"));
        Assert.AreEqual(1, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithValidComplianceStandard_UnsupportedManifestInfo_ReturnsNonZeroExitCode()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: "2.2");

        // Add the compliance standard
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: "2.2", complianceStandardValue: "NTIA");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.IsTrue(stderr.Contains("Please use a supported combination."));
        Assert.AreNotEqual(0, exitCode.Value);
    }

    [TestMethod]
    public void E2E_Validate_WithNoneComplianceStandard_SupportedManifestInfo_StdOutDoesNotHaveComplianceStandardErrors()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: "3.0");

        // Add the compliance standard
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: "3.0", complianceStandardValue: "none");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        // Assert that the validation failures show up
        Assert.IsFalse(stdout.Contains("Elements in the manifest that are non-compliant"));
    }

    [TestMethod]
    public void E2E_Validate_WithValidComplianceStandard_SupportedManifestInfo_StdOutContainsNTIAErrors()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: "3.0");

        // Add the compliance standard
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: "3.0", complianceStandardValue: "NTIA");

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        // Assert that the validation failures show up
        Assert.IsFalse(stdout.Contains("Elements in the manifest that are non-compliant with NTIA . . . 0"));
        Assert.IsTrue(stdout.Contains("SPDXRef-Package"));
    }

    [TestMethod]
    public void E2E_Validate_WithAdditionalFile_SPDX22_StdOutContainsAdditionalFileErrors()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var version = "2.2";
        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: version);

        // Add additional file
        var newFilePath = Path.Combine(testDropDirectory, "newFile");
        File.WriteAllText(newFilePath, "This is a test file.");

        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: version);

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual(3, exitCode.Value, $"Unexpected failure: stdout = {stdout}");
        Assert.IsTrue(stdout.Contains("Additional files not in the manifest . . . . . . 1"));
        Assert.IsTrue(stdout.Contains("newFile"));

        if (File.Exists(newFilePath))
        {
            File.Delete(newFilePath);
        }
    }

    [TestMethod]
    public void E2E_Validate_WithAdditionalFile_SPDX30_StdOutContainsAdditionalFileErrors()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var version = "3.0";
        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: version);

        // Add additional file
        var newFilePath = Path.Combine(testDropDirectory, "newFile");
        File.WriteAllText(newFilePath, "This is a test file.");

        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: version);

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual(3, exitCode.Value, $"Unexpected failure: stdout = {stdout}");
        Assert.IsTrue(stdout.Contains("Additional files not in the manifest . . . . . . 1"));
        Assert.IsTrue(stdout.Contains("newFile"));

        if (File.Exists(newFilePath))
        {
            File.Delete(newFilePath);
        }
    }

    [TestMethod]
    public void E2E_Validate_WithMissingFile_SPDX22_StdOutContainsMissingFileErrors()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var spdxVersion = "2.2";
        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: spdxVersion);

        var newFile = new
        {
            fileName = "newFile",
            checksums = new[] { new { algorithm = "sha1", checksumValue = "abc123" } },
            SPDXID = "SPDXRef-File-newFile"
        };

        AddExtraFileToManifest(testFolderPath, spdxVersion, newFile);
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: spdxVersion);

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual(3, exitCode.Value, $"Unexpected failure: stdout = {stdout}");
        Assert.IsTrue(stdout.Contains("Files in the manifest missing from the disk . . .1"));
        Assert.IsTrue(stdout.Contains("newFile"));
    }

    [TestMethod]
    public void E2E_Validate_WithMissingFile_SPDX30_StdOutContainsMissingFileErrors()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var spdxVersion = "3.0";
        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath, manifestInfoSpdxVersion: spdxVersion);

        var newFile = new
        {
            name = "newFile",
            verifiedUsing = new[] { new { algorithm = "sha1", hashValue = "abc123", creationInfo = "_:creationInfo", spdxId = "SPDXRef-PackVerCode", type = "PackageVerificationCode" } },
            spdxId = "SPDXRef-File-newFile",
            creationInfo = "_:creationInfo",
            type = "software_File",
        };

        AddExtraFileToManifest(testFolderPath, spdxVersion, newFile);
        var (arguments, outputFile) = GetValidateManifestArguments(testFolderPath, manifestInfoSpdxVersion: spdxVersion);

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.AreEqual(3, exitCode.Value, $"Unexpected failure: stdout = {stdout}");
        Assert.IsTrue(stdout.Contains("Files in the manifest missing from the disk . . .1"));
        Assert.IsTrue(stdout.Contains("newFile"));
    }

    [DataRow("SPDX:2.2")]
    [DataRow("SPDX:3.0")]
    [DataRow("randomName:randomVersion")]
    [TestMethod]
    public void E2E_Redact_WithManifestInfo_ReturnsNonZeroExitCode(string manifestInfoValue)
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var outputFolder = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "redacted");
        var originalManifestFolderPath = AppendFullManifestFolderPath(testFolderPath);
        var originalManifestFilePath = Path.Combine(AppendFullManifestFolderPath(testFolderPath), ManifestFileName);
        var arguments = $"redact -sp \"{originalManifestFilePath}\" -o \"{outputFolder}\" -verbosity verbose";
        arguments += $" -mi {manifestInfoValue}";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);
        Assert.IsTrue(stdout.Contains("Unexpected named argument: mi"));
        Assert.AreNotEqual(0, exitCode.Value);
    }

    private void GenerateManifestAndValidateSuccess(string testFolderPath, string manifestInfoSpdxVersion = null)
    {
        var manifestInfoArg = string.IsNullOrEmpty(manifestInfoSpdxVersion) ? string.Empty : $"-mi SPDX:{manifestInfoSpdxVersion}";
        var arguments = $"generate -ps IntegrationTests -pn IntegrationTests -pv 1.2.3 -m \"{testFolderPath}\" -b \"{testDropDirectory}\" -bc \"{GetSolutionFolderPath()}\" {manifestInfoArg}";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        var manifestFolderPath = AppendFullManifestFolderPath(testFolderPath, spdxVersion: manifestInfoSpdxVersion);
        var jsonFilePath = Path.Combine(manifestFolderPath, ManifestFileName);
        var shaFilePath = Path.Combine(manifestFolderPath, "manifest.spdx.json.sha256");
        Assert.IsTrue(File.Exists(jsonFilePath));
        Assert.IsTrue(File.Exists(shaFilePath));

        // Check that manifestFolderPath is the only folder in the directory
        var directories = Directory.GetDirectories(Path.Combine(testFolderPath, ManifestRootFolderName));
        Assert.AreEqual(1, directories.Length, "There should be only one folder in the test directory.");
        Assert.AreEqual(manifestFolderPath, directories[0], "The only folder in the test directory should be a folder with the correct SBOM version name.");

        Assert.AreEqual(0, exitCode.Value, $"Unexpected failure. stdout = {stdout}");
    }

    private (string arguments, string outputFile) GetValidateManifestArguments(string testFolderPath, string manifestInfoSpdxVersion = "2.2", string complianceStandardValue = "")
    {
        var outputFile = Path.Combine(TestContext.TestRunDirectory, TestContext.TestName, "validation.json");
        var manifestRootFolderName = Path.Combine(testFolderPath, ManifestRootFolderName);
        var manifestInfoArg = string.IsNullOrEmpty(manifestInfoSpdxVersion) ? string.Empty : $" -mi SPDX:{manifestInfoSpdxVersion}";
        var complianceStandardArg = string.IsNullOrEmpty(complianceStandardValue) ? string.Empty : $" -cs {complianceStandardValue}";
        var arguments = $"validate -m \"{manifestRootFolderName}\" -b \"{testDropDirectory}\" -o \"{outputFile}\" {manifestInfoArg} {complianceStandardArg}";
        return (arguments, outputFile);
    }

    private string CreateTestFolder()
    {
        var testFolderPath = Path.GetFullPath(Path.Combine(TestContext.TestRunDirectory, TestContext.TestName));
        Directory.CreateDirectory(testFolderPath);
        return testFolderPath;
    }

    private static string AppendFullManifestFolderPath(string manifestDir, string spdxVersion = null)
    {
        return Path.Combine(manifestDir, ManifestRootFolderName, $"spdx_{spdxVersion ?? "2.2"}");
    }

    /// <summary>
    /// Consistently return the path that contains our solution file. Starts from the location of the executing
    /// assembly, then walks up the tree until is finds a solution file
    /// </summary>
    /// <returns>The path to the folder that contains the solution file</returns>
    private static string GetSolutionFolderPath()
    {
        var pathToCheck = Path.GetFullPath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
        while (!Directory.EnumerateFiles(pathToCheck, "*.sln").Any())
        {
            pathToCheck = Path.GetFullPath(Path.Combine(pathToCheck, ".."));
        }

        return pathToCheck;
    }

    private static string GetAppName()
    {
        return IsWindows ? "Microsoft.Sbom.Tool.exe" : "Microsoft.Sbom.Tool";
    }

    private void AddExtraFileToManifest(string testFolderPath, string version, object newFile)
    {
        // Determine the array to modify based on the version
        var keyForArrayToModify = version switch
        {
            "2.2" => "files",
            "3.0" => "@graph",
            _ => throw new ArgumentException("Unsupported version", nameof(version))
        };

        var manifestFolderPath = AppendFullManifestFolderPath(testFolderPath, spdxVersion: version);
        var jsonFilePath = Path.Combine(manifestFolderPath, ManifestFileName);

        // Read and deserialize the JSON content
        var jsonContent = File.ReadAllText(jsonFilePath);
        var jsonDocument = JsonDocument.Parse(jsonContent);
        var rootElement = jsonDocument.RootElement;
        var originalArrayToModify = rootElement.GetProperty(keyForArrayToModify).EnumerateArray()
                .Select(element => JsonSerializer.Deserialize<JsonElement>(element.GetRawText()))
                .ToList();

        // Add a new file to manifest.spdx.json
        var modifiedArray = originalArrayToModify;
        modifiedArray.Add(JsonSerializer.SerializeToElement(newFile));
        var serializedModifiedArray = JsonSerializer.Serialize(modifiedArray);

        // Update the JSON with the modified array
        var updatedJson = JsonConvert.SerializeObject(rootElement.EnumerateObject()
            .ToDictionary(
                property => property.Name,
                property => property.Name.Equals(keyForArrayToModify, StringComparison.Ordinal)
                    ? JsonConvert.DeserializeObject(serializedModifiedArray)
                    : JsonConvert.DeserializeObject(property.Value.GetRawText())));

        // Write the updated JSON back to the file
        File.WriteAllText(jsonFilePath, updatedJson);
    }

    private static (string stdout, string stderr, int? exitCode) LaunchAndCaptureOutput(string? arguments)
    {
        var stdout = string.Empty;
        var stderr = string.Empty;
        int? exitCode = null;
        Process process = null;

        try
        {
            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = GetAppName(),
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Arguments = arguments ?? string.Empty,
                }
            };

            process.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    stdout += e.Data + Environment.NewLine;
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    stderr += e.Data + Environment.NewLine;
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.WaitForExit();
        }
        catch (Exception e)
        {
            Assert.Fail($"Caught the following Exception: {e}");
        }
        finally
        {
            if (process is not null)
            {
                if (!process.HasExited)
                {
                    process.Kill();
                }

                exitCode = process.ExitCode;
                process.Dispose();
            }
        }

        return (stdout, stderr, exitCode);
    }

    private static void Xcopy(string sourceDir, string targetDir)
    {
        foreach (var dirPath in Directory.GetDirectories(sourceDir, "*.*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(dirPath.Replace(sourceDir, targetDir));
        }

        foreach (var newPath in Directory.GetFiles(sourceDir, "*.*", SearchOption.AllDirectories))
        {
            File.Copy(newPath, newPath.Replace(sourceDir, targetDir), true);
        }
    }
}
