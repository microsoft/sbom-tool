// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Tools.Tests;

[TestClass]
public class IntegrationTests
{
    private const string ManifestRootFolderName = "_manifest";
    private const string ManifestFileName = "manifest.spdx.json";

    private static TestContext testContext;
    private static readonly string AppName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Microsoft.Sbom.Tool.exe" : "Microsoft.Sbom.Tool";

    [ClassInitialize]
    public static void SetUp(TestContext testContext)
    {
        IntegrationTests.testContext = testContext;
    }

    [TestMethod]
    public void E2E_NoParameters_DisplaysHelpMessage_ReturnsNonZeroExitCode()
    {
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
        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);
    }

    [TestMethod]
    public void E2E_GenerateAndValidateManifest_ValidationSucceeds_ReturnsZeroExitCode()
    {
        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var outputFile = Path.Combine(testContext.ResultsDirectory, testContext.TestName, "validation.json");
        var manifestRootFolderName = Path.Combine(testFolderPath, ManifestRootFolderName);
        var arguments = $"validate -m \"{manifestRootFolderName}\" -b . -o \"{outputFile}\" -mi spdx:2.2";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        Assert.AreEqual(0, exitCode.Value);
        Assert.IsTrue(File.Exists(outputFile), $"{outputFile} should have been created during validation");
        Assert.IsTrue(File.ReadAllText(outputFile).Contains("\"Result\":\"Success\"", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void E2E_GenerateAndRedactManifest_RedactedFileIsSmaller_ReturnsZeroExitCode()
    {
        var testFolderPath = CreateTestFolder();
        GenerateManifestAndValidateSuccess(testFolderPath);

        var outputFolder = Path.Combine(testContext.ResultsDirectory, testContext.TestName, "redacted");
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

    public void GenerateManifestAndValidateSuccess(string testFolderPath)
    {
        var arguments = $"generate -ps IntegrationTests -pn IntegrationTests -pv 1.2.3 -m \"{testFolderPath}\"  -b . -bc \"{GetSolutionFolderPath()}\"";

        var (stdout, stderr, exitCode) = LaunchAndCaptureOutput(arguments);

        Assert.AreEqual(stderr, string.Empty);
        var manifestFolderPath = AppendFullManifestFolderPath(testFolderPath);
        var jsonFilePath = Path.Combine(manifestFolderPath, ManifestFileName);
        var shaFilePath = Path.Combine(manifestFolderPath, "manifest.spdx.json.sha256");
        Assert.IsTrue(File.Exists(jsonFilePath));
        Assert.IsTrue(File.Exists(shaFilePath));
        Assert.AreEqual(0, exitCode.Value);
    }

    private string CreateTestFolder()
    {
        var testFolderPath = Path.GetFullPath(Path.Combine(testContext.ResultsDirectory, testContext.TestName));
        Directory.CreateDirectory(testFolderPath);
        return testFolderPath;
    }

    private static string AppendFullManifestFolderPath(string manifestDir)
    {
        return Path.Combine(manifestDir, ManifestRootFolderName, "spdx_2.2");
    }

    private static string GetSolutionFolderPath()
    {
        return Path.GetFullPath(Path.Combine(Assembly.GetExecutingAssembly().Location, "..", "..", ".."));
    }

    private static (string stdout, string stderr, int? exitCode) LaunchAndCaptureOutput(string? arguments)
    {
        var stdout = string.Empty;
        var stderr = string.Empty;
        int? exitCode = null;
        Process process = null;

        try
        {
            process = new Process();
            process.StartInfo.FileName = AppName;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            if (!string.IsNullOrEmpty(arguments))
            {
                process.StartInfo.Arguments = arguments;
            }

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
        catch (Exception ex)
        {
            // Handle any exceptions here
            Console.WriteLine("Error: " + ex.Message);
        }
        finally
        {
            if (process is not null)
            {
                if (process.HasExited)
                {
                    process.Kill();
                }

                exitCode = process.ExitCode;
            }
        }

        return (stdout, stderr, exitCode);
    }
}
