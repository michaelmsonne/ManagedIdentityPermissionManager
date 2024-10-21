# Specify the path to the .exe file using Get-ChildItem
$exeFile = Get-ChildItem "..\bin\x64" -Filter "*ManagedIdentityPermissionManager*Build at*.exe" # | Select-Object -First 1

if ($null -eq $exeFile) {
    Write-Host "No matching .exe file found."
} else {
    # Generate the SHA-256 hash for the .exe file
    $hash = Get-FileHash -Path $exeFile.FullName -Algorithm SHA256

    # Create a dynamic name for the hash file
    $hashFileName = "..\bin\x64\{0}.sha256" -f $exeFile.BaseName, (Get-Date -format "ddMMyyyy-HHmmss")

    # Save the hash value to a .sha256 file
    $hashFileContent = "SHA-256 Hash:`r`n" + $hash.Hash
    $hashFileContent | Set-Content -Path $hashFileName

    Write-Host "SHA-256 hash file created: $hashFileName"
}