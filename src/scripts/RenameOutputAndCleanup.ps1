<#
#Get file v. for last build ManagedIdentityPermissionManager.exe file
$FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(".\bin\x64\ManagedIdentityPermissionManager.exe").FileVersion
#Rename file to v. and buildtime
Get-ChildItem ".\bin\x64\ManagedIdentityPermissionManager.exe" | ? {!$_.PSIsContainer -and $_.extension -eq '.exe'} | Rename-Item -NewName {"$($_.BaseName) v. $FileVersion - Build at $(Get-Date -format "ddMMyyyy-HHmmss")$($_.extension)"} -Force
#Delete old ManagedIdentityPermissionManager.exe file there not need to be used anymore
#Get-ChildItem ".\bin\x64" -Recurse -File | Where CreationTime -lt (Get-Date).AddSeconds(-2) | Remove-Item -Force
Get-ChildItem ".\bin\x64" -File | Where CreationTime -lt (Get-Date).AddSeconds(-5) | Remove-Item -Force
#>

#Folder for old builds
$FolderName = ".\bin\x64\Old\"
if (Get-Item -Path $FolderName -ErrorAction Ignore)
{
    Write-Host "Old folder for Release builds Exists: $FolderName"
    Write-Host "Moving old build files in format: ManagedIdentityPermissionManager v. x.x.x.x - Build at ddMMyyyy-HHmmss.exe to $FolderName"
    Get-ChildItem -Path ".\*ManagedIdentityPermissionManager*Build at*" -Recurse | Move-Item -Destination $FolderName
    Write-Host "Moved old build files in format: ManagedIdentityPermissionManager v. x.x.x.x - Build at ddMMyyyy-HHmmss.exe to $FolderName"
}
else
{
    Write-Host "Old folder for Release builds doesn't Exists - Creating it..."
    #PowerShell Create directory if not exists
    New-Item $FolderName -ItemType Directory
    Write-Host "Old folder for Release builds doesn't Exists - Created folder: $FolderName"
}

#Get file v. for last build ManagedIdentityPermissionManager.exe file
Write-Host "Getting File Version Info from output .\bin\x64\ManagedIdentityPermissionManager.exe"
$FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(".\bin\x64\ManagedIdentityPermissionManager.exe").FileVersion
Write-Host "Got File Version Info from output .\bin\x64\ManagedIdentityPermissionManager.exe"

#Delete old .exe file there not need to be used anymore 2 sec. old or more
Write-Host "Deleteing old files in output .\bin\x64\ManagedIdentityPermissionManager v. x.x.x.x - Build at ddMMyyyy-HHmmss.exe"
Get-ChildItem ".\bin\x64\*ManagedIdentityPermissionManager*Build at*" -File | Where-Object CreationTime -lt (Get-Date).AddSeconds(-2) | Remove-Item -Force
Write-Host "Removed old files in output .\bin\x64\ManagedIdentityPermissionManager v. x.x.x.x - Build at ddMMyyyy-HHmmss.exe"

#Rename file to v. and buildtime
Write-Host "Renaming output .\bin\x64\ManagedIdentityPermissionManager.exe to format ManagedIdentityPermissionManager v. x.x.x.x - Build at ddMMyyyy-HHmmss.exe"
# Copy the original file to the new name format instead of renaming it
Get-ChildItem ".\bin\x64\ManagedIdentityPermissionManager.exe" | Where-Object {!$_.PSIsContainer -and $_.extension -eq '.exe'} | Copy-Item -Destination {"$($_.DirectoryName)\$($_.BaseName) v. $FileVersion - Build at $(Get-Date -format "ddMMyyyy-HHmmss")$($_.extension)"} -Force
Write-Host "Copied output .\bin\x64\ManagedIdentityPermissionManager.exe to format ManagedIdentityPermissionManager v. $FileVersion - Build at $(Get-Date -format 'ddMMyyyy-HHmmss').exe"

#Show task is done
Write-Host "Build task done! Output file is:"

#Get filename for the new file
Get-ChildItem -Filter ".\bin\x64\*ManagedIdentityPermissionManager*Build at*" | ForEach-Object { Write-Host $_.Name }

# Create hash file for output
# Specify the path to the .exe file using Get-ChildItem
$exeFile = Get-ChildItem ".\bin\x64" -Filter "*ManagedIdentityPermissionManager*Build at*.exe" | Select-Object -First 1

if ($null -eq $exeFile)
{
    Write-Host "No matching .exe file found."
}
else
{
    # Generate the SHA-256 hash for the .exe file
    $hash = Get-FileHash -Path $exeFile.FullName -Algorithm SHA256

    # Create a dynamic name for the hash file
    $hashFileName = ".\bin\x64\{0}.sha256" -f $exeFile.BaseName, (Get-Date -format "ddMMyyyy-HHmmss")

    # Ensure that the directory exists
    $directory = [System.IO.Path]::GetDirectoryName($hashFileName)
    if (-not (Test-Path -Path $directory)) {
        New-Item -Path $directory -ItemType Directory
    }

    # Save the hash value to a .sha256 file
    $hashFileContent = "SHA-256 Hash:`r`n" + $hash.Hash
    $hashFileContent | Set-Content -Path $hashFileName

    Write-Host "SHA-256 hash file created: $hashFileName"
}