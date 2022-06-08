# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.
<#
.SYNOPSIS
Verifies that all the files in the target folder have the specified license header. Can optionally add the license header to files.

.PARAMETER Target
The target folder to search recursively.

.PARAMETER LicenseHeaderPath
The path to a text file that contains the license header text

.PARAMETER Extensions
The extensions of the files in the target folder that will be processed. Currently supports xaml, xml, cs, ps1 extensions

.PARAMETER AddIfAbsent
If a file with no license header is detected, whether a header should be added.

.Example Usage 
.\LicenseHeaderVerification.ps1 -Target '.\Powershell test\' -LicenseHeaderPath .\LicenseHeader.txt -Extensions *.xaml,*.xml,*.cs,*.ps1 -AddIfAbsent $false
#>

param(
    $Target,
    $LicenseHeaderPath,
    $Extensions,
    $AddIfAbsent=$false
)

$NewLine=([Environment]::NewLine)
$FailedFiles = @()
$SplitVanillaLicenseHeader=@()
$excludeList="(\\packages\\|\\bin\\|\\obj\\|Designer.cs)"

function Get-FileText($pathToFile){
   return Get-Content $pathToFile -Raw -Encoding UTF8
}

function Get-CopyrightHeader($extension){
    switch ( $extension )
    {
        {(($extension -eq '.xaml') -or ($extension -eq '.xml') -or ($extension -eq '.wxs'))}{
            return $XmlLicense;
        }
        .cs {
            return $CSharpLicense;
        }
        .ps1{
            return $PSLicense;
        }
        #Add more Extensions support here
        default{
            throw ("Extension not supported")
        }
    }
}

<# Function to generate line commented license header text. 
.PARAMETER SplitVanillaLicenseHeader
The header text split into lines

.PARAMETER lineComment
The character/s used to indicate a commented line
#>
function Get-LineCommentedHeader($SplitVanillaLicenseHeader, $lineComment){
    $licenseHeader=$null
    foreach($line in $SplitVanillaLicenseHeader){
        if(-not ([string]::IsNullOrWhiteSpace($line))){
            $licenseHeader = "$licenseHeader$lineComment $line$NewLine"
        }
    }
    return $licenseHeader; 
}

<# Function to generate line commented license header text. 
.PARAMETER SplitVanillaLicenseHeader
The header text split into lines

.PARAMETER blockCommentStart
The character/s used to indicate the start of a comment block

.PARAMETER blockCommentEnd
The character/s used to indicate the end of a comment block
#>
function Get-BlockCommentedHeader($SplitVanillaLicenseHeader, $blockCommentStart, $blockCommentEnd){
    if($SplitVanillaLicenseHeader.length -le 0){
        throw (" License missing ");
    }
    $licenseHeader = "$blockCommentStart " +  $SplitVanillaLicenseHeader[0] +$NewLine
    $spacing = " " * ($blockCommentStart.length + 1)
    
    if($SplitVanillaLicenseHeader.length -gt 1){
        for($lineNum=1; $lineNum -lt $SplitVanillaLicenseHeader.length; $lineNum++){
            if(-not ([string]::IsNullOrWhiteSpace($SplitVanillaLicenseHeader[$lineNum]))){
                $licenseHeader = "$licenseHeader$spacing" + $SplitVanillaLicenseHeader[$lineNum]
            }
        }
    }
    return $licenseHeader + $blockCommentEnd; 
}

$SplitVanillaLicenseHeader = (Get-FileText $LicenseHeaderPath).split($NewLine)
$XmlLicense = Get-BlockCommentedHeader $SplitVanillaLicenseHeader "<!--" "-->"
$CSharpLicense =  Get-LineCommentedHeader $SplitVanillaLicenseHeader "//"
$PSLicense= Get-LineCommentedHeader $SplitVanillaLicenseHeader "#"
#Add more Extensions support here

(Get-ChildItem $Target\* -Include $Extensions -Recurse) | Where {$_.FullName -notmatch $excludeList} | Foreach-Object {
    $path = $_.FullName
    $copyRightHeader=Get-CopyrightHeader $_.Extension
    $fileContent=Get-FileText $path
    if($fileContent -ne $Null -and $fileContent.Contains($copyRightHeader)){
        Write-Output "$path has copyright header"
    } else {
       $FailedFiles += $path
       if($AddIfAbsent){
           "$copyRightHeader" + $fileContent | Set-Content -NoNewLine $path -Encoding UTF8
           Write-Output "Added the header to $path"
        }
    }
}

if($FailedFiles -gt 0){
    Write-Output "$NewLine"
    $wording = ('do not','did not')[$AddIfAbsent]
    $message = "The following files " + $wording + " have a copyright header $NewLine" + ($FailedFiles -join $NewLine) + "$NewLine"
    if($AddIfAbsent){
        $message
    } else {
        Write-Output ($message)
        exit 1
    }
}