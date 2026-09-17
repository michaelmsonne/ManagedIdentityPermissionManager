#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

$global:ConnectedState = $false # Default value
$global:managedIdentities
$global:clearExistingPermissions
$global:darkModeStateUI
$global:sortedManagedIdentities
$global:filteredManagedIdentities

$global:FormVersion = "1.2.0.0"
$global:Author = "Michael Morten Sonne"
$global:ToolName = "Managed Identity Permission Manager"
$global:AuthorEmail = ""
$global:AuthorCompany = "Sonne´s Cloud"

#Get username and domain for account running this tool
$global:UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Logfile path
$LogPath = "$Env:USERPROFILE\AppData\Local\$global:ToolName"

# Variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory

# Define a global hashtable to store service principal data
$global:ServicePrincipalData = @{ }

function StartAsAdmin
{
	# Check if the current process is running with elevated privileges
	$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	
	if (-not $isElevated)
	{
		# Restart the current process as administrator
		$processPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
		#$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$processPath`""
		
		Write-Log -Level INFO -Message "Restarting '$processPath' as administrator..."
		Start-Process $processPath -Verb RunAs
		
		# Exit the current process
		[System.Environment]::Exit(0)
	}
}

function Test-Administrator
{
	# Get the current Windows identity
	$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
	
	# Create a Windows principal object
	$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
	
	# Check if the current principal is in the Administrator role
	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CurrentExecutionFilename
{
	# Get the current execution location
	if ($PSCommandPath)
	{
		$exePath = $PSCommandPath
	}
	elseif ($MyInvocation.MyCommand.Path)
	{
		$exePath = $MyInvocation.MyCommand.Path
	}
	else
	{
		$exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
	}
	$hostname = [System.Net.Dns]::GetHostName()
	Write-Log -Level INFO -Message "Current execution location: '$exePath' on host '$hostname'"
}

# Checks the current execution policy for the process
function Test-ExecutionPolicy
{
	#StartAsAdmin
	
	if (Test-Administrator)
	{
		# TODO
	}
	
	try
	{
		Write-Log -Level INFO -Message "Getting PowerShell execution policy..."
		$executionPolicies = Get-ExecutionPolicy -List
		
		# Concatenate execution policies into a single string
		$policyString = ($executionPolicies | ForEach-Object { "$($_.Scope): $($_.ExecutionPolicy)" }) -join ", "
		Write-Log -Level INFO -Message "Execution policies: '$policyString'"
		
		$processPolicy = $executionPolicies | Where-Object { $_.Scope -eq 'Process' }
		$currentUserPolicy = $executionPolicies | Where-Object { $_.Scope -eq 'CurrentUser' }
		$effectivePolicy = $executionPolicies | Where-Object { $_.Scope -eq 'MachinePolicy' -or $_.Scope -eq 'UserPolicy' }
		
		if ($effectivePolicy.ExecutionPolicy -ne 'Undefined')
		{
			Write-Log -Level INFO -Message "Execution policy is set by Group Policy. Current effective policy is '$($effectivePolicy.ExecutionPolicy)'."
			return
		}
		
		if ($processPolicy.ExecutionPolicy -ne "Unrestricted" -and $processPolicy.ExecutionPolicy -ne "Bypass")
		{
			Write-Log -Level INFO -Message "Current process execution policy is '$($processPolicy.ExecutionPolicy)'."
			
			try
			{
				Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
				Write-Log -Level INFO -Message "Execution policy set to 'Bypass' for the current process."
			}
			catch
			{
				if ($_.Exception.Message -match "Security error")
				{
					Write-Log -Level WARNING -Message "Security error encountered. Attempting to set execution policy to 'RemoteSigned'..."
					try
					{
						Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
						Write-Log -Level INFO -Message "Execution policy set to 'RemoteSigned' for the current process."
					}
					catch
					{
						Write-Log -Level ERROR -Message "Failed to set execution policy to 'RemoteSigned': $($_.Exception.Message)"
						
						StartAsAdmin
					}
				}
				else
				{
					Write-Log -Level ERROR -Message "Failed to set execution policy: $($_.Exception.Message)"
				}
			}
		}
		else
		{
			Write-Log -Level INFO -Message "Current process execution policy is '$($processPolicy.ExecutionPolicy)'. No need to change."
		}
	}
	catch
	{
		Write-Log -Level ERROR -Message "An error occurred: $($_.Exception.Message)"
	}
}

# Get current Windows colour theme (dard or light)
function Test-WindowsInDarkMode
{
	# Path to the registry key
	$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
	$registryValueName = "AppsUseLightTheme"
	
	try
	{
		# Get the value of the registry key
		$useLightTheme = Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction Stop
		
		# Determine the theme mode based on the registry value
		if ($useLightTheme.$registryValueName -eq 0)
		{
			return $true # Dark mode
			
			Write-Log -Level INFO -Message "Detected Windows is running as Dark mode - setting application to this theme as default"
		}
		else
		{
			return $false # Light mode
			
			Write-Log -Level INFO -Message "Detected Windows is running as Light mode - setting application to this theme as default"
		}
	}
	catch
	{
		#Write-Error "Failed to determine Windows theme mode: $_"
		return $false
	}
}

#CheckLogPath function
Function CheckLogPath
{
<#
	.SYNOPSIS
		CheckLogPath returns the value if logfile path exits or not.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	try
	{
		$FolderName = $LogPath
		if (Test-Path $FolderName)
		{
			#Write to logfile if exists
			Write-Log -Level INFO -Message "The application log path exists: '$LogPath'"
		}
		else
		{
			#Create logfile of not exists
			New-Item $FolderName -ItemType Directory
			
			# Log
			Write-Log -Level INFO -Message "The application log path does not exists and is created: '$LogPath'"
		}
	}
	# Catch specific types of exceptions thrown by one of those commands
	catch [System.Exception]
	{
		# Log
		Write-Log -Level ERROR -Message $($Error[0].Exception.Message)
	}
	# Catch all other exceptions thrown by one of those commands
	catch
	{
		# Log
		Write-Log -Level ERROR -Message $($Error[0].Exception.Message)
	}
}

#Logfile write log function
Function Write-Log
{
<#
	.SYNOPSIS
		Save the information to specified logfile
	
	.DESCRIPTION
		A detailed description of the Write-Log function.
	
	.PARAMETER Level
		Set the information level in the logfile.
	
	.PARAMETER Message
		The message to be logged in the logfile
	
	.PARAMETER logfile
		The selected logfile to write to (there is a default logfile)
	
	.EXAMPLE
		PS C:\> Write-Log -Level INFO -Message 'value1'
	
	.NOTES
		Additional information about the function.
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $False)]
		[ValidateSet("INFO", "WARNING", "ERROR", "FATAL", "DEBUG")]
		[String]$Level = "INFO",
		[Parameter(Mandatory = $True)]
		[string]$Message,
		[Parameter(Mandatory = $False)]
		[string]$logfile = "$LogPath\$($ToolName)_Log_$($env:computername)" + "_" + (Get-Date -Format "dd-MM-yyyy") + ".log"
	)
	
	$Stamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss")
	$Line = "$Stamp : $Level : $UserName : $Message"
	If ($logfile)
	{
		Add-Content $logfile -Value $Line
	}
	
	# Update the log TextBox in the UI
	Update-Log -message $Message
	
	#HOW TO ADD A LOG ENTRY: Write-Log -Level INFO -Message "The application is started"
}

# Function to update the log textbox (UI)
function Update-Log
{
	param (
		[string]$message
	)
	#$textboxLog.Value.Text += "$message" + "´n"
	
	# Append the new log entry to the TextBox
	$timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
	$textboxLog.AppendText("[$timestamp] $message`r`n")
	
	# Ensure the TextBox scrolls to the latest entry
	$textboxLog.SelectionStart = $textboxLog.Text.Length
	$textboxLog.ScrollToCaret()
}

function Show-InputBox
{
	param
	(
		[string]$message = $(Throw "You must enter a prompt message"),
		[string]$title = "Input",
		[string]$default
	)
	
	[reflection.assembly]::loadwithpartialname("microsoft.visualbasic") | Out-Null
	[microsoft.visualbasic.interaction]::InputBox($message, $title, $default)
}

function Show-MsgBox
{
	[CmdletBinding()]
	param (
		# Define the message to be displayed in the message box.
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$Prompt,
		# Define the title for the message box (optional).
		[Parameter(Position = 1, Mandatory = $false)]
		[string]$Title = "",
		# Define the icon type for the message box (optional).
		[Parameter(Position = 2, Mandatory = $false)]
		[ValidateSet("Information", "Question", "Critical", "Exclamation")]
		[string]$Icon = "Information",
		# Define the type of buttons in the message box (optional).
		[Parameter(Position = 3, Mandatory = $false)]
		[ValidateSet("OKOnly", "OKCancel", "AbortRetryIgnore", "YesNoCancel", "YesNo", "RetryCancel")]
		[string]$BoxType = "OkOnly",
		# Define the default button for the message box (optional).
		[Parameter(Position = 4, Mandatory = $false)]
		[ValidateSet(1, 2, 3)]
		[int]$DefaultButton = 1
	)
	
	# Load the Microsoft.VisualBasic assembly for MessageBox handling.
	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic") | Out-Null
	
	# Map the provided $Icon to the corresponding VB.NET enum value.
	switch ($Icon)
	{
		"Question" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Question }
		"Critical" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Critical }
		"Exclamation" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Exclamation }
		"Information" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Information }
	}
	# Map the provided $BoxType to the corresponding VB.NET enum value.
	switch ($BoxType)
	{
		"OKOnly" { $vb_box = [microsoft.visualbasic.msgboxstyle]::OKOnly }
		"OKCancel" { $vb_box = [microsoft.visualbasic.msgboxstyle]::OkCancel }
		"AbortRetryIgnore" { $vb_box = [microsoft.visualbasic.msgboxstyle]::AbortRetryIgnore }
		"YesNoCancel" { $vb_box = [microsoft.visualbasic.msgboxstyle]::YesNoCancel }
		"YesNo" { $vb_box = [microsoft.visualbasic.msgboxstyle]::YesNo }
		"RetryCancel" { $vb_box = [microsoft.visualbasic.msgboxstyle]::RetryCancel }
	}
	# Map the provided $DefaultButton to the corresponding VB.NET enum value.
	switch ($Defaultbutton)
	{
		1 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton1 }
		2 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton2 }
		3 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton3 }
	}
	
	# Combine the icon, button type, and default button values to determine the message box style.
	$popuptype = $vb_icon -bor $vb_box -bor $vb_defaultbutton
	
	# Show the message box with the provided parameters and capture the user's response.
	$ans = [Microsoft.VisualBasic.Interaction]::MsgBox($prompt, $popuptype, $title)
	
	# Return the user's response.
	return $ans
}

#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

function Get-ManagedIdentityCount
{
	# Return the count from the already-fetched global data
	if ($global:managedIdentities)
	{
		return $global:managedIdentities.Count
	}
	else
	{
		return 0
	}
}

# Validate the current PowerShell modules required to execute this tool
function Test-Modules
{
	# Pinned to a pre-2.34.0 release so Connect-MgGraph always uses the classic browser popup,
	# not the OS WAM broker (which requires a parent window handle this WinForms host cannot provide).
	$requiredModules = @(
		@{ Name = "Microsoft.Graph.Authentication"; Version = "2.32.0" },
		@{ Name = "Microsoft.Graph.Applications"; Version = "2.32.0" }
	)
	
	# Log
	Write-Log -Level INFO -Message "Starting check for needed PowerShell Modules..."
	
	# Check for version consistency across all Microsoft.Graph modules
	Write-Log -Level INFO -Message "Checking for Microsoft.Graph module version consistency..."
	$allGraphModules = Get-Module -ListAvailable Microsoft.Graph.* | Group-Object Name
	$versionMismatches = @()
	
	foreach ($moduleGroup in $allGraphModules)
	{
		if ($moduleGroup.Count -gt 1)
		{
			$versions = $moduleGroup.Group | Select-Object -ExpandProperty Version -Unique
			if ($versions.Count -gt 1)
			{
				$versionMismatches += "$($moduleGroup.Name): $($versions -join ', ')"
			}
		}
	}
	
	if ($versionMismatches.Count -gt 0)
	{
		Write-Log -Level WARNING -Message "Multiple versions detected for some Microsoft.Graph modules:"
		foreach ($mismatch in $versionMismatches)
		{
			Write-Log -Level WARNING -Message "  $mismatch"
		}
		Write-Log -Level WARNING -Message "This tool pins an exact version below, so this is informational only."
	}
	
	$modulesToInstall = @()
	foreach ($module in $requiredModules)
	{
		Write-Log -Level INFO -Message "Checking module '$($module.Name)' for pinned version '$($module.Version)'..."
		$installedVersions = Get-Module -ListAvailable $module.Name
		
		# Check if Beta version of the module is installed
		$isBetaModule = $installedVersions | Where-Object { $_.Name -eq $module.Name -and ($_.Path -like "*Beta*" -or $_.Name -like "*Beta*") }
		if ($isBetaModule)
		{
			Write-Log -Level ERROR -Message "Beta version of module '$($module.Name)' is installed. Exiting to avoid conflicts."
			throw "Beta version of module '$($module.Name)' detected. Please uninstall the Beta module and re-run the script."
		}
		
		$hasPinnedVersion = $installedVersions | Where-Object { $_.Version -eq [version]$module.Version }
		if ($hasPinnedVersion)
		{
			# Import the exact pinned version so side-by-side newer versions can't be picked instead
			Import-Module -Name $module.Name -RequiredVersion $module.Version -Force -ErrorAction Stop
			Write-Log -Level INFO -Message "Imported pinned version '$($module.Version)' of module '$($module.Name)'."
		}
		else
		{
			Write-Log -Level INFO -Message "Pinned version '$($module.Version)' of module '$($module.Name)' is not installed."
			$modulesToInstall += $module
		}
	}
	
	if ($modulesToInstall.Count -gt 0)
	{
		Write-Log -Level INFO -Message "Missing required pinned PowerShell modules. Prompting for installation..."
		
		# Concatenate module names into a single string
		$modulesList = ($modulesToInstall | ForEach-Object { "$($_.Name) v$($_.Version)" }) -join ", "
				
		# Aks if the user will install needed modules
		$ConfirmInstallMissingPowerShellModule = Show-MsgBox -Prompt "The following required PowerShell module versions are missing:`r`n`r`n$modulesList.`r`n`r`nWould you like to install these now?" -Title "Missing required PowerShell modules" -Icon Question -BoxType YesNo -DefaultButton 2
		
		# Get confirmation
		If ($ConfirmInstallMissingPowerShellModule -eq "Yes")
		{
			# Log
			Write-Log -Level INFO -Message "Set to install needed PowerShell Modules - confirmed by user"
			
			Write-Log -Level INFO -Message "Installing modules..."
			foreach ($module in $modulesToInstall)
			{
				# A previous interrupted/failed install can leave an empty or partial version folder behind,
				# which makes PowerShellGet fail with "Could not find file '...\<Version>'" on every retry.
				# Check every user-scope module path from $env:PSModulePath (Desktop and Core layouts differ).
				$userModuleBasePaths = $env:PSModulePath -split ';' | Where-Object { $_ -like "$HOME*" }
				foreach ($basePath in $userModuleBasePaths)
				{
					$staleVersionPath = Join-Path -Path (Join-Path -Path $basePath -ChildPath $module.Name) -ChildPath $module.Version
					if (Test-Path -Path $staleVersionPath)
					{
						$manifestPath = Join-Path -Path $staleVersionPath -ChildPath "$($module.Name).psd1"
						if (-not (Test-Path -Path $manifestPath))
						{
							Write-Log -Level WARNING -Message "Found an incomplete module folder from a previous failed install: '$staleVersionPath'. Removing it before retrying."
							Remove-Item -Path $staleVersionPath -Recurse -Force -ErrorAction SilentlyContinue
						}
					}
				}

				Write-Log -Level INFO -Message "Installing module '$($module.Name)' version '$($module.Version)'. This can take a moment - no progress bar is shown in this host..."
				try
				{
					# PowerShellGet's progress/console UI calls can abort mid-extraction in this WinForms
					# host (no real console), leaving a broken version folder. Installing from a real
					# external PowerShell process avoids that entirely.
					$installCommand = "`$ProgressPreference = 'SilentlyContinue'; Install-Module -Name '$($module.Name)' -RequiredVersion '$($module.Version)' -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop"
					$installProcess = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoLogo", "-NoProfile", "-Command", $installCommand) -WindowStyle Hidden -PassThru -Wait
					if ($installProcess.ExitCode -ne 0)
					{
						throw "External install process exited with code '$($installProcess.ExitCode)'."
					}
					Write-Log -Level INFO -Message "Installed module '$($module.Name)' version '$($module.Version)'."
				}
				catch
				{
					Write-Log -Level ERROR -Message "Failed to install module '$($module.Name)' version '$($module.Version)': $($_.Exception.GetType().FullName) - $($_.Exception.Message)"
					throw
				}

				Write-Log -Level INFO -Message "Importing module '$($module.Name)' version '$($module.Version)'..."
				try
				{
					Import-Module -Name $module.Name -RequiredVersion $module.Version -Force -ErrorAction Stop
					Write-Log -Level INFO -Message "Imported module '$($module.Name)' version '$($module.Version)'."
				}
				catch
				{
					Write-Log -Level ERROR -Message "Failed to import module '$($module.Name)' version '$($module.Version)' after install: $($_.Exception.GetType().FullName) - $($_.Exception.Message)"
					throw
				}
			}
			Write-Log -Level INFO -Message "Modules installed."
		}
		else
		{
			# Log
			Write-Log -Level INFO -Message "Set to keep current state for reset existing permissions - confirmation to change is cancled by user"
			
			Write-Log -Level ERROR -Message "Exiting setup. Please install required modules and re-run the setup."
		}
	}
	
	# Log
	Write-Log -Level INFO -Message "Check for needed PowerShell Modules completed"
}

# Function to connect to Microsoft Graph
function ConnectToGraph
{
	param (
		[string]$TenantId
	)
	
	# Log
	Write-Log -Level INFO -Message "Starting to connect to Microsoft Graph..."
	$connectParams = @{
		NoWelcome = $true
		Scopes = 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All'
		ContextScope = 'Process'
		ErrorAction = 'Stop'
	}
	
	if (-not [string]::IsNullOrWhiteSpace($TenantId))
	{
		$connectParams.TenantId = $TenantId
		Write-Log -Level INFO -Message "Connecting to Microsoft Graph with Tenant ID: $TenantId"
	}
	else
	{
		Write-Log -Level INFO -Message "Connecting to Microsoft Graph without specific Tenant ID"
	}
	
	$context = $null
	$connected = $false
	
	try
	{
		Connect-MgGraph @connectParams | Out-Null
		$context = Get-MgContext
		if (($null -ne $context) -and ($null -ne $context.ClientId) -and ($null -ne $context.TenantId))
		{
			$connected = $true
		}
		else
		{
			Write-Log -Level WARNING -Message "Primary sign-in returned no usable Graph context. Trying device authentication fallback."
		}
	}
	catch
	{
		Write-Log -Level WARNING -Message "Primary sign-in failed: $($_.Exception.Message). Trying device authentication fallback."
	}
	
	if (-not $connected)
	{
		try
		{
			Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
			Connect-MgGraph @connectParams -UseDeviceAuthentication | Out-Null
			$context = Get-MgContext
			if (($null -ne $context) -and ($null -ne $context.ClientId) -and ($null -ne $context.TenantId))
			{
				$connected = $true
				Write-Log -Level INFO -Message "Device authentication fallback succeeded."
			}
		}
		catch
		{
			Write-Log -Level ERROR -Message "Device authentication fallback failed: $($_.Exception.Message)"
		}
	}
	
	if ($connected)
	{
		Write-Log -Level INFO -Message "Connected to Microsoft Graph as '$($context.Account)' (Tenant: '$($context.TenantId)', App: '$($context.AppName)', Auth: $($context.AuthType)/$($context.ContextScope), Token: '$($context.TokenCredentialType)')"
		if ($context.Scopes)
		{
			$scopesString = $context.Scopes -join ', '
			Write-Log -Level INFO -Message "Granted scopes: $scopesString"
		}
		else
		{
			Write-Log -Level WARNING -Message "No scopes information available in context."
		}
		if (-not [string]::IsNullOrWhiteSpace($TenantId) -and ($null -ne $context.TenantId) -and ($context.TenantId -ne $TenantId))
		{
			Write-Log -Level WARNING -Message "Connected tenant '$($context.TenantId)' is different from requested tenant '$TenantId'."
		}
		$global:ConnectedState = $true
		return
	}
	
	$contextInfo = if ($context) { "Context retrieved but missing required properties (ClientId: $($null -ne $context.ClientId), TenantId: $($null -ne $context.TenantId))" } else { "No context available" }
	Write-Log -Level ERROR -Message "Failed to connect to Microsoft Graph. Context is incomplete. $contextInfo"
	if (-not [string]::IsNullOrWhiteSpace($TenantId))
	{
		Write-Log -Level WARNING -Message "If sign-in logs show 'Device authentication failed', verify the user can sign in to tenant '$TenantId' and that Conditional Access allows this app/device flow."
	}
	$global:ConnectedState = $false
}

# Function to get current API assignments
function Get-CurrentAppRoleAssignments
{
	param (
		[string]$ManagedIdentityID,
		[string]$ManagedIdentityName
	)
	
	$result = ""
	try
	{
		# Retrieve the current app role assignments for the specified service principal
		
		# Log
		Write-Log -Level INFO -Message "Getting permissions for Managed Identity with Id: '$ManagedIdentityID' name '$ManagedIdentityName'"
		
		# Get current role assignments
		$currentAppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All -ErrorAction Stop
		
		# Of any roles assigned
		if ($currentAppRoles)
		{
			$result += "Current permissions assignments for Managed Identity ID '$ManagedIdentityID' with name '$ManagedIdentityName':`r`n"
			foreach ($appRole in $currentAppRoles)
			{
				# Resolve ResourceId to Service Principal Name
				$resource = Get-MgServicePrincipal -ServicePrincipalId $appRole.ResourceId -ErrorAction Stop
				$resourceName = $resource.DisplayName
				
				# Resolve AppRoleId to App Role Name and Value (Scope)
				$appRoleDetails = $resource.AppRoles | Where-Object { $_.Id -eq $appRole.AppRoleId }
				$appRoleName = $appRoleDetails.DisplayName
				$appRoleScope = $appRoleDetails.Value
				
				# PrincipalId: '$($appRole.PrincipalId)'
				# ResourceId: '$($appRole.ResourceId)'
				
				$appRoleInfo = @"

AppRoleAssignmentId: '$($appRole.Id)'
ResourceName: '$resourceName'
AppRoleId: '$($appRole.AppRoleId)'
AppRoleName: '$appRoleName'
AppRoleScope: '$appRoleScope'
"@
				$result += $appRoleInfo + "`r`n"
			}
			
			# Log
			Write-Log -Level INFO -Message "Got current assigned permissions for Managed Identity ID '$ManagedIdentityID' with name '$ManagedIdentityName'"
		}
		else
		{
			$result += "No AppRole assignments found for Managed Identity ID '$ManagedIdentityID' name '$ManagedIdentityName.`r`n"
			
			# Log
			Write-Log -Level INFO -Message "No AppRole assignments found for Managed Identity ID '$ManagedIdentityID' name '$ManagedIdentityName"
		}
	}
	catch
	{
		if ($_ -match "Cannot bind argument to parameter 'ServicePrincipalId' because it is an empty string.")
		{
			$result += "You need to select a Managed Identity in the dropdown list to get the assigned access scopes for. Try again.`r`n"
			Write-Log -Level ERROR -Message "You need to select a Managed Identity in the dropdown list to get the assigned access scopes for. Try again."
		}
		else
		{
			$result += "Error retrieving access scopes assignments for Managed Identity ID '$ManagedIdentityID': $($_.Exception.Message)`r`n"
			Write-Log -Level ERROR -Message "Error retrieving access scopes assignments for Managed Identity ID '$ManagedIdentityID': $($_.Exception.Message)"
		}
	}
	
	# Return data
	return $result
}

# Function to add API assignments
function Add-ServicePrincipalPermission
{
	param (
		[string]$ManagedIdentityID,
		[string]$Permissions,
		[string]$ServiceType,
		[bool]$clearExistingPermissions,
		[switch]$ReturnResults
	)

	$operationResults = New-Object 'System.Collections.Generic.List[object]'

	function Add-OperationResult
	{
		param (
			[string]$Scope,
			[string]$Status,
			[string]$Message
		)

		[void]$operationResults.Add([PSCustomObject]@{
			ManagedIdentityID = $ManagedIdentityID
			ServiceType		   = $ServiceType
			Scope			   = $Scope
			Status			   = $Status
			Message			   = $Message
		})
	}
	
	try
	{
		# Log
		Write-Log -Level INFO -Message "ManagedIdentityID: $ManagedIdentityID"
		Write-Log -Level INFO -Message "Received ServiceType: '$ServiceType'"
		Write-Log -Level INFO -Message "Received Permissions: '$Permissions'"
		
		if ($ServiceType -eq "All services")
		{
			Show-MsgBox -Title "Invalid Selection" -Prompt "Please select a specific service. Managing permissions for 'All services' is not possible." -Icon Critical -BoxType OKOnly
			Add-OperationResult -Scope "" -Status "Failed" -Message "Service selection 'All services' is not supported for assignment."
			if ($ReturnResults.IsPresent)
			{
				return @($operationResults)
			}
			return
		}
		
		# Get the service principal data from the global hashtable
		$servicePrincipal = $global:ServicePrincipalData[$ServiceType]
		
		# Check if service principal was found
		if ($null -eq $servicePrincipal)
		{
			Write-Log -Level INFO -Message "No service principal found for ServiceType '$ServiceType'."
			Add-OperationResult -Scope "" -Status "Failed" -Message "Service principal '$ServiceType' was not found in cache."
			if ($ReturnResults.IsPresent)
			{
				return @($operationResults)
			}
			return
		}
		
		# Ensure Permissions is not null or empty
		if (-not [string]::IsNullOrWhiteSpace($Permissions))
		{
			if ($clearExistingPermissions -eq $true)
			{
				# Debug logging to verify ManagedIdentityID
				Write-Log -Level INFO -Message "ManagedIdentityID: $ManagedIdentityID"
				
				# Log
				Write-Log -Level INFO -Message "Removing existing permissions because clear existing permissions is set"
				
				$AssignedPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All
				
				if ($AssignedPermissions.Count -eq 0)
				{
					# Log
					Write-Log -Level INFO -Message "No permissions assigned"
				}
				
				foreach ($permission in $AssignedPermissions)
				{
					$AppId = $permission.ResourceId
					$AllRoles = Get-MgServicePrincipal -Filter "Id eq '$AppId'"
					$AppDisplayname = $AllRoles.DisplayName
					$details = $AllRoles.AppRoles | Where-Object { $_.Id -eq $permission.AppRoleId }
					$permission | Add-Member -MemberType NoteProperty -Name AppDisplayName -Value $AppDisplayname
					$permission | Add-Member -MemberType NoteProperty -Name PermissionName -Value $details.Value
				}
				
				# Log
				Write-Log -Level INFO -Message "Current assigned permissions is:"
				for ($i = 0; $i -lt $AssignedPermissions.Count; $i++)
				{
					$AssignedPermission = @($AssignedPermissions)[$i]
					
					# Log
					Write-Log -Level INFO -Message "Permission $($i + 1): service: '$($AssignedPermission.AppDisplayName)' | '$($AssignedPermission.PermissionName)'"
				}
				
				foreach ($permission in $AssignedPermissions)
				{
					try
					{
						# Process
						Remove-MgServicePrincipalAppRoleAssignment -AppRoleAssignmentId $permission.Id -ServicePrincipalId $ManagedIdentityID -ErrorAction Stop
						
						# Log
						Write-Log -Level INFO -Message "Permission for service: '$($permission.AppDisplayName)' | '$($permission.PermissionName)' has been removed"
					}
					catch
					{
						# Log
						Write-Log -Level ERROR -Message "Failed to remove permission for service '$($permission.AppDisplayName)' | '$($permission.PermissionName)': $($_.Exception.Message)"
					}
				}
				#Update-Log -Message "Permissions have been removed"
			}
			if ($clearExistingPermissions -eq $false)
			{
				# Log
				Write-Log -Level INFO -Message "Set to keep existing permissions because clear existing permissions is not set"
			}
			
			# Split the permissions string into an array and trim each element
			$Perms = $Permissions.Split(",") | ForEach-Object { $_.Trim() }
			
			#Update-Log -Message "Split permissions: $($Perms -join ', ')"
			
			foreach ($Scope in $Perms)
			{
				if (-not [string]::IsNullOrWhiteSpace($Scope))
				{
					# Log
					Write-Log -Level INFO -Message "Processing permission '$Scope' for service '$ServiceType'"
					
					# Get data
					$AppRole = $servicePrincipal.AppRoles | Where-Object { $_.Value -eq $Scope }
					
					# If exists
					if ($AppRole)
					{
						$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All | Where-Object { $_.ResourceId -eq $servicePrincipal.Id -and $_.AppRoleId -eq $AppRole.Id }
						if ($existingAppRole)
						{
							# Log
							Write-Log -Level INFO -Message "The scope '$Scope' is already assigned for service '$ServiceType' - skipped"
							Add-OperationResult -Scope $Scope -Status "AlreadyAssigned" -Message "The scope is already assigned."
						}
						else
						{
							try
							{
								# Process
								$null = New-MgServicePrincipalAppRoleAssignment -PrincipalId $ManagedIdentityID -ServicePrincipalId $ManagedIdentityID -ResourceId $servicePrincipal.Id -AppRoleId $AppRole.Id -ErrorAction Stop
								
								# Validate
								$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All | Where-Object { $_.ResourceId -eq $servicePrincipal.Id -and $_.AppRoleId -eq $AppRole.Id }
								if ($existingAppRole)
								{
									# Log
									Write-Log -Level INFO -Message "The scope '$Scope' has been assigned to service '$ServiceType'"
									Add-OperationResult -Scope $Scope -Status "Added" -Message "The scope was assigned successfully."
								}
								else
								{
									# Log
									Write-Log -Level INFO -Message "The scope '$Scope' could not be assigned for service '$ServiceType': $($_.Exception.Message)"
									Add-OperationResult -Scope $Scope -Status "Failed" -Message "The scope could not be validated after assignment."
								}
							}
							catch
							{
								# Log
								Write-Log -Level ERROR -Message "Error assigning the scope '$Scope' for service '$ServiceType': $($_.Exception.Message)"
								Add-OperationResult -Scope $Scope -Status "Failed" -Message "Error assigning scope: $($_.Exception.Message)"
							}
						}
					}
					else
					{
						# Log
						Write-Log -Level WARNING -Message "No App Role found for scope '$Scope' to service '$ServiceType' - skipping"
						Add-OperationResult -Scope $Scope -Status "NotFound" -Message "No app role found for this scope in the selected service."
					}
				}
				else
				{
					# Log
					Write-Log -Level WARNING -Message "Skipping empty or whitespace permission"
					Add-OperationResult -Scope "" -Status "Skipped" -Message "Skipped empty or whitespace permission entry."
				}
			}
		}
		else
		{
			# Log
			Write-Log -Level INFO -Message "Permissions parameter is empty or null"
			Add-OperationResult -Scope "" -Status "Skipped" -Message "Permissions parameter was empty."
		}
	}
	catch
	{
		# Log
		Write-Log -Level ERROR -Message "Error adding service '$ServiceType' permission '$Permissions': $($_.Exception.Message)"
		Add-OperationResult -Scope "" -Status "Failed" -Message "Unhandled error while assigning permissions: $($_.Exception.Message)"
	}

	if ($ReturnResults.IsPresent)
	{
		return @($operationResults)
	}
}

# Function to remove API assignments
function Remove-ServicePrincipalPermission
{
	param (
		[string]$ManagedIdentityID,
		[string]$Permissions,
		[string]$ServiceType
	)
	
	try
	{
		# Log the received parameters
		Write-Log -Level INFO -Message "Managed Identity ObjectID: '$ManagedIdentityID'"
		Write-Log -Level INFO -Message "Service: '$ServiceType'"
		Write-Log -Level INFO -Message "Permissions: '$Permissions'"
		
		if ($ServiceType -eq "All services")
		{
			Show-MsgBox -Title "Invalid Selection" -Prompt "Please select a specific service. Managing permissions for 'All services' is not possible." -Icon Critical -BoxType OKOnly
			return
		}
		
		# Get the service principal data from the global hashtable
		$servicePrincipal = $global:ServicePrincipalData[$ServiceType]
				
		# Check if service principal was found
		if ($null -eq $servicePrincipal)
		{
			Write-Log -Level INFO -Message "No service principal found for ServiceType '$ServiceType'."
			
			Show-MsgBox -Title "Error" -Prompt "Service principal not found." -Icon Exclamation -BoxType OKOnly
			
			return
		}
		
		# Ensure Permissions is not null or empty
		if (-not [string]::IsNullOrWhiteSpace($Permissions))
		{
			# Split the permissions string into an array and trim each element
			$Perms = $Permissions.Split(",") | ForEach-Object { $_.Trim() }
			
			Write-Log -Level INFO -Message "Permissions to remove: $Perms"
			
			# Get the current API permissions assigned to the managed identity
			$currentPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All
			
			# Get all available permissions for the service principal
			$allPermissions = @{ }
			foreach ($appRole in $servicePrincipal.AppRoles)
			{
				$allPermissions[$appRole.Value] = $appRole.Id
				#Update-Log -Message "Available permission: $($appRole.Value) with ID: $($appRole.Id)"
			}
			
			# Remove the old permission assignments
			foreach ($permission in $Perms)
			{
				# Log
				Write-Log -Level INFO -Message "Trying to remove permission: '$permission'"
				
				if ($allPermissions.ContainsKey($permission.Trim()))
				{
					$appRoleId = $allPermissions[$permission.Trim()]
					$existingAppRole = $currentPermissions | Where-Object { $_.AppRoleId -eq $appRoleId }
					
					if ($existingAppRole.Count -eq 0)
					{
						# Log
						Write-Log -Level INFO -Message "No existing AppRole assignments found for permission: '$permission' for service '$ServiceType'"
					}
					
					foreach ($role in $existingAppRole)
					{
						try
						{
							# Log
							Write-Log -Level INFO -Message "Attempting to remove AppRoleAssignmentId: '$($role.Id)'"
							
							# Process
							Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -AppRoleAssignmentId $role.Id -ErrorAction Stop
							
							# Log
							Write-Log -Level INFO -Message "The scope '$permission' has been removed from service '$ServiceType'"
						}
						catch
						{
							# Log
							Write-Log -Level ERROR -Message "Error removing the scope '$permission' from service '$ServiceType': $($_.Exception.Message)"
						}
					}
				}
				else
				{
					# Log
					Write-Log -Level ERROR -Message "Permission '$permission' not found in available permissions for service '$ServiceType'"
				}
			}
			
			#[System.Windows.Forms.MessageBox]::Show("Permissions updated successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
		}
		else
		{
			# Log
			Write-Log -Level INFO -Message "Permissions parameter is empty or null"
		}
	}
	catch
	{
		# Log
		Write-Log -Level ERROR -Message "Error removing permission '$Permissions' from service '$ServiceType': $($_.Exception.Message)"
	}
}

# Function to reset all API assignments
function Remove-AllServicePrincipalPermissions
{
	param (
		[string]$ManagedIdentityID
	)
	
	#Update-Log -Message "ManagedIdentityID: $ManagedIdentityID"
	
	try
	{
		# Log the received parameters
		Write-Log -Level INFO -Message "Managed Identity ObjectID: '$ManagedIdentityID'"
		
		# Get the current API permissions assigned to the managed identity
		$currentPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All
		
		if ($currentPermissions.Count -eq 0)
		{
			Write-Log -Level INFO -Message "No permissions assigned to the managed identity."
			return
		}
		
		# Remove each assigned permission
		foreach ($permission in $currentPermissions)
		{
			try
			{
				# Get the service principal details
				$servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $permission.ResourceId
				$serviceName = $servicePrincipal.DisplayName
				$appRole = $servicePrincipal.AppRoles | Where-Object { $_.Id -eq $permission.AppRoleId }
				$permissionScope = $appRole.Value
				
				# Log
				Write-Log -Level INFO -Message "Attempting to remove AppRoleAssignmentId: $($permission.Id) for service: '$serviceName' with scope: '$permissionScope'"
				
				# Do
				Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -AppRoleAssignmentId $permission.Id -ErrorAction Stop
				
				# Log
				Write-Log -Level INFO -Message "Permission with AppRoleAssignmentId '$($permission.Id)' for service: '$serviceName' with scope: '$permissionScope' has been removed."
			}
			catch
			{
				# Log
				Write-Log -Level ERROR -Message "Error removing permission with AppRoleAssignmentId '$($permission.Id)' for service: '$serviceName' with scope: '$permissionScope': $($_.Exception.Message)"
			}
		}
		
		#[System.Windows.Forms.MessageBox]::Show("All permissions removed successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
	}
	catch
	{
		# Log
		Write-Log -Level ERROR -Message "Error removing all permissions for managed identity '$ManagedIdentityID': $($_.Exception.Message)"
	}
}

function Get-LatestReleaseFromGitHub
{
	$repo = "michaelmsonne/ManagedIdentityPermissionManager"
	$file = "ManagedIdentityPermissionManager.exe"
	$releasesUrl = "https://api.github.com/repos/$repo/releases"
	
	Write-Log -Level INFO -Message "Determining latest release..."
	$tag = (Invoke-WebRequest -Uri $releasesUrl -UseBasicParsing | ConvertFrom-Json)[0].tag_name
	
	$downloadUrl = "https://github.com/$repo/releases/download/$tag/$file"
	Write-Log -Level INFO -Message "Downloading latest release from GitHub API at: '$downloadUrl'"
	
	# Get the path
	$outputFile = Join-Path -Path $env:USERPROFILE\Downloads -ChildPath $file
	Invoke-WebRequest -Uri $downloadUrl -OutFile $outputFile
	
	# Ask user
	$ConfirmStartLAstDownloadedVFromGitHub = Show-MsgBox -Prompt "Latest release v. $tag on GitHub is downloaded successfully to the path:`r`n`r`n'$outputFile'.`r`n`r`nDo you want to restart the application with the new version?" -Title "Download Complete" -Icon Question -BoxType YesNo -DefaultButton 1
	
	# If user comfirmed
	If ($ConfirmStartLAstDownloadedVFromGitHub -eq "Yes")
	{
		# Log
		Write-Log -Level INFO -Message "Restarting application with the new version $tag ... - confirmed by user"
		
		# Start the new process and capture the process object
		$process = Start-Process -FilePath $outputFile -PassThru
		
		# Log the path of the started process
		Write-Log -Level INFO -Message "Started new process: $($process.Path) on host '$([System.Net.Dns]::GetHostName())'"
		
		# Wait briefly to ensure the new process starts
		Start-Sleep -Seconds 1
		
		# Close the current form and stop the current process
		$formManagedIdentityPermi.Close()
		Stop-Process -Id $PID
	}
	else
	{
		# Log
		Write-Log -Level INFO -Message "The new version $tag is downloaded to: $outputFile'"
		
		Show-MsgBox -Title "Download location" -Prompt "The new version '$tag' is downloaded to:`r`n`r`n'$outputFile'`r`n`r`nHere you can start it later when needed :)" -Icon Information -BoxType OKOnly
	}
}

function Get-TenantId
{
	param (
		[string]$LookupInputData
	)
	
	# Log the received parameters
	Write-Log -Level INFO -Message "Trying to get tenant data for: '$LookupInputData'"
	
	$trimmedLookupInput = $LookupInputData.Trim()
	
	# Check if the input is a tenant ID (GUID) or domain name (supports multi-label domains like *.onmicrosoft.com)
	if ($trimmedLookupInput -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
	{
		Write-Log -Level INFO -Message "Input '$trimmedLookupInput' is a tenant ID"
		
		# Input is a tenant ID
		$url = "https://login.microsoftonline.com/$trimmedLookupInput/v2.0/.well-known/openid-configuration"
	}
	elseif ($trimmedLookupInput -match '^(?=.{1,255}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
	{
		Write-Log -Level INFO -Message "Input '$trimmedLookupInput' is a domain"
		
		# Input is a domain name
		$url = "https://login.microsoftonline.com/$trimmedLookupInput/.well-known/openid-configuration"
	}
	else
	{
		Write-Log -Level WARNING -Message "Input '$trimmedLookupInput' is not recognized as a GUID tenant ID or domain. Trying lookup as provided."
		
		# Best-effort fallback
		$url = "https://login.microsoftonline.com/$trimmedLookupInput/v2.0/.well-known/openid-configuration"
	}
	
	Write-Log -Level INFO -Message "Sending GET request for '$trimmedLookupInput' - URL: '$url'"
	
	try
	{
		# Send GET request to get data needed
		$response = Invoke-RestMethod -Uri $url -Method Get
		
		# Log (debug data only)
		#Write-Log -Level INFO -Message "Response: $($response | Out-String)"
		
		# Extract the tenant ID from the issuer field
		$tenantId = $response.issuer -replace 'https://sts.windows.net/', '' -replace 'https://login.microsoftonline.com/', '' -replace '/v2.0', '' -replace '/', ''
		
		# Log
		Write-Log -Level INFO -Message "Extracted Tenant ID: '$tenantId' from GET response"
		
		# Return data
		return $tenantId
	}
	catch [System.Net.WebException] {
		# Log specific web exception
		Write-Log -Level ERROR -Message "WebException occurred: $($_.Exception.Message)"
		Write-Log -Level ERROR -Message "Status: $($_.Exception.Status)"
		if ($_.Exception.Response)
		{
			$responseStream = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($responseStream)
			$responseBody = $reader.ReadToEnd()
			Write-Log -Level ERROR -Message "Response Body: $responseBody"
		}
		return $null
	}
	catch [System.Exception] {
		# Log general exception
		Write-Log -Level ERROR -Message "Failed to retrieve tenant ID for input: $LookupInputData. Error: $($_.Exception.Message)"
		return $null
	}
}

function Export-ManagedIdentityPermissions
{
	param (
		[string]$ManagedIdentityID,
		[string]$ManagedIdentityName,
		[string]$ExportFilePath
	)
	
	try
	{
		# Get current role assignments
		$currentAppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All -ErrorAction Stop
		
		if ($currentAppRoles)
		{
			$permissions = @()
			foreach ($appRole in $currentAppRoles)
			{
				# Resolve ResourceId to Service Principal Name
				$resource = Get-MgServicePrincipal -ServicePrincipalId $appRole.ResourceId -ErrorAction Stop
				$resourceName = $resource.DisplayName
				
				# Resolve AppRoleId to App Role Name and Value (Scope)
				$appRoleDetails = $resource.AppRoles | Where-Object { $_.Id -eq $appRole.AppRoleId }
				$appRoleName = $appRoleDetails.DisplayName
				$appRoleScope = $appRoleDetails.Value
				
				$permissions += [PSCustomObject]@{
					ManagedIdentityID   = $ManagedIdentityID
					ManagedIdentityName = $ManagedIdentityName
					ResourceName	    = $resourceName
					AppRoleName		    = $appRoleName
					AppRoleScope	    = $appRoleScope
				}
			}
			
			# Export to CSV
			$permissions | Export-Csv -Path $ExportFilePath -NoTypeInformation
			Write-Log -Level INFO -Message "All assigned permissions exported to '$ExportFilePath'"
		}
		else
		{
			Write-Log -Level INFO -Message "No permissions assigned to the managed identity."
		}
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error exporting permissions: $($_.Exception.Message)"
	}
}

function Export-AllManagedIdentityPermissions
{
	param (
		[string]$ExportFilePath
	)
	
	try
	{
		$allPermissions = @()
		foreach ($managedIdentity in $global:managedIdentities)
		{
			$ManagedIdentityID = $managedIdentity.Id
			$ManagedIdentityName = $managedIdentity.DisplayName
			$currentAppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -All -ErrorAction Stop
			
			if ($currentAppRoles)
			{
				foreach ($appRole in $currentAppRoles)
				{
					# Resolve ResourceId to Service Principal Name
					$resource = Get-MgServicePrincipal -ServicePrincipalId $appRole.ResourceId -ErrorAction Stop
					$resourceName = $resource.DisplayName
					
					# Resolve AppRoleId to App Role Name and Value (Scope)
					$appRoleDetails = $resource.AppRoles | Where-Object { $_.Id -eq $appRole.AppRoleId }
					$appRoleName = $appRoleDetails.DisplayName
					$appRoleScope = $appRoleDetails.Value
					
					$allPermissions += [PSCustomObject]@{
						ManagedIdentityID   = $ManagedIdentityID
						ManagedIdentityName = $ManagedIdentityName
						ResourceName	    = $resourceName
						AppRoleName		    = $appRoleName
						AppRoleScope	    = $appRoleScope
					}
				}
			}
		}
		
		# Export to CSV
		$allPermissions | Export-Csv -Path $ExportFilePath -NoTypeInformation
		Write-Log -Level INFO -Message "All assigned permissions exported to '$ExportFilePath'"
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error exporting all permissions: $($_.Exception.Message)"
	}
}

function Import-ManagedIdentityPermissions
{
	param (
		[string]$ImportFilePath,
		[bool]$ClearExistingPermissions = $false
	)
	
	try
	{
		if (-not (Test-Path -Path $ImportFilePath -PathType Leaf))
		{
			throw "The selected import file was not found at '$ImportFilePath'."
		}
		
		$importRows = @(Import-Csv -Path $ImportFilePath)
		$rowsRead = @($importRows).Count
		if ($rowsRead -eq 0)
		{
			Write-Log -Level WARNING -Message "The import file '$ImportFilePath' does not contain any rows."
			return [PSCustomObject]@{
				RowsRead			 = 0
				RowsProcessed	     = 0
				IdentitiesProcessed  = 0
				ServicesProcessed    = 0
				PermissionsAttempted = 0
				SkippedRows		     = 0
				PermissionsAdded	 = 0
				PermissionsAlreadyAssigned = 0
				PermissionsFailed	 = 0
				PermissionResults	 = New-Object 'System.Collections.Generic.List[object]'
			}
		}
		
		$requiredColumns = @("ManagedIdentityID", "ManagedIdentityName", "ResourceName", "AppRoleScope")
		$availableColumns = @($importRows[0].PSObject.Properties.Name)
		$missingColumns = $requiredColumns | Where-Object { $_ -notin $availableColumns }
		if ($missingColumns.Count -gt 0)
		{
			throw "The import file is missing required columns: '$($missingColumns -join ", ")'."
		}
		
		$validRows = @($importRows | Where-Object {
				-not [string]::IsNullOrWhiteSpace($_.ManagedIdentityID) -and
				-not [string]::IsNullOrWhiteSpace($_.ResourceName) -and
				-not [string]::IsNullOrWhiteSpace($_.AppRoleScope)
			})
		
		$rowsProcessed = @($validRows).Count
		$permissionResults = @()
		$summary = [PSCustomObject]@{
			RowsRead			 = $rowsRead
			RowsProcessed	     = $rowsProcessed
			IdentitiesProcessed  = 0
			ServicesProcessed    = 0
			PermissionsAttempted = 0
			SkippedRows		     = [Math]::Max(0, ($rowsRead - $rowsProcessed))
			PermissionsAdded	 = 0
			PermissionsAlreadyAssigned = 0
			PermissionsFailed	 = 0
			PermissionResults	 = @()
		}
		
		if ($validRows.Count -eq 0)
		{
			$summary.PermissionResults = @($permissionResults)
			Write-Log -Level WARNING -Message "No valid import rows were found in '$ImportFilePath'."
			return $summary
		}
		
		$identityGroups = $validRows | Group-Object -Property ManagedIdentityID
		foreach ($identityGroup in $identityGroups)
		{
			$managedIdentityID = $identityGroup.Name.Trim()
			if ([string]::IsNullOrWhiteSpace($managedIdentityID))
			{
				continue
			}
			
			try
			{
				$null = Get-MgServicePrincipal -ServicePrincipalId $managedIdentityID -ErrorAction Stop
			}
			catch
			{
				Write-Log -Level WARNING -Message "Managed Identity '$managedIdentityID' does not exist or cannot be read in this tenant. Skipping import for this identity."
				continue
			}
			
			if ($ClearExistingPermissions -eq $true)
			{
				Write-Log -Level INFO -Message "Reset mode is enabled. Removing current assignments for Managed Identity '$managedIdentityID' before import."
				Remove-AllServicePrincipalPermissions -ManagedIdentityID $managedIdentityID
			}
			
			$summary.IdentitiesProcessed++
			
			$serviceGroups = $identityGroup.Group | Group-Object -Property ResourceName
			foreach ($serviceGroup in $serviceGroups)
			{
				$resourceName = $serviceGroup.Name.Trim()
				if ([string]::IsNullOrWhiteSpace($resourceName))
				{
					continue
				}
				
				$scopes = @(
					$serviceGroup.Group |
					ForEach-Object { $_.AppRoleScope } |
					Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
					ForEach-Object { $_.Trim() } |
					Sort-Object -Unique
				)
				
				if ($scopes.Count -eq 0)
				{
					continue
				}
				
				if (-not $global:ServicePrincipalData.ContainsKey($resourceName))
				{
					$escapedResourceName = $resourceName.Replace("'", "''")
					$servicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq '$escapedResourceName'" -Property "id,appId,displayName,appRoles,oauth2PermissionScopes,resourceSpecificApplicationPermissions" -ErrorAction Stop | Select-Object -First 1
					if ($null -eq $servicePrincipal)
					{
						Write-Log -Level WARNING -Message "Could not resolve service principal for resource '$resourceName'. Skipping these permissions for Managed Identity '$managedIdentityID'."
						foreach ($scope in $scopes)
						{
							[void]$permissionResults.Add([PSCustomObject]@{
								ManagedIdentityID = $managedIdentityID
								ServiceType		   = $resourceName
								Scope			   = $scope
								Status			   = "Failed"
								Message			   = "Service principal could not be resolved for this resource."
							})
							$summary.PermissionsFailed++
						}
						continue
					}
					
					$global:ServicePrincipalData[$resourceName] = $servicePrincipal
				}
				
				$permissionsToAssign = $scopes -join ", "
				Write-Log -Level INFO -Message "Importing permissions for Managed Identity '$managedIdentityID' on service '$resourceName': '$permissionsToAssign'"

				try
				{
					$servicePrincipal = $global:ServicePrincipalData[$resourceName]
					$scopeToRoleId = @{ }
					foreach ($appRole in @($servicePrincipal.AppRoles))
					{
						if (-not [string]::IsNullOrWhiteSpace($appRole.Value))
						{
							$scopeToRoleId[$appRole.Value] = [string]$appRole.Id
						}
					}

					$beforeAssignmentsRaw = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityID -All -ErrorAction Stop)
					$beforeRoleIds = @{ }
					foreach ($assignment in $beforeAssignmentsRaw)
					{
						if ([string]$assignment.ResourceId -eq [string]$servicePrincipal.Id)
						{
							$beforeRoleIds[[string]$assignment.AppRoleId] = $true
						}
					}

					# Execute assignment using the existing function, then verify final state directly.
					$null = Add-ServicePrincipalPermission -ManagedIdentityID $managedIdentityID -Permissions $permissionsToAssign -ServiceType $resourceName -clearExistingPermissions $false

					$afterAssignmentsRaw = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityID -All -ErrorAction Stop)
					$afterRoleIds = @{ }
					foreach ($assignment in $afterAssignmentsRaw)
					{
						if ([string]$assignment.ResourceId -eq [string]$servicePrincipal.Id)
						{
							$afterRoleIds[[string]$assignment.AppRoleId] = $true
						}
					}

					foreach ($scope in $scopes)
					{
						if (-not $scopeToRoleId.ContainsKey($scope))
						{
							$permissionResults += [PSCustomObject]@{
								ManagedIdentityID = $managedIdentityID
								ServiceType		   = $resourceName
								Scope			   = $scope
								Status			   = "Failed"
								Message			   = "No app role was found for this scope on the target service principal."
							}
							$summary.PermissionsFailed++
							continue
						}

						$roleId = $scopeToRoleId[$scope]
						$wasAssignedBefore = $beforeRoleIds.ContainsKey($roleId)
						$isAssignedAfter = $afterRoleIds.ContainsKey($roleId)

						if ($wasAssignedBefore)
						{
							$permissionResults += [PSCustomObject]@{
								ManagedIdentityID = $managedIdentityID
								ServiceType		   = $resourceName
								Scope			   = $scope
								Status			   = "AlreadyAssigned"
								Message			   = "Scope was already assigned before import for this service."
							}
							$summary.PermissionsAlreadyAssigned++
						}
						elseif ($isAssignedAfter)
						{
							$permissionResults += [PSCustomObject]@{
								ManagedIdentityID = $managedIdentityID
								ServiceType		   = $resourceName
								Scope			   = $scope
								Status			   = "Added"
								Message			   = "Scope was assigned successfully during import."
							}
							$summary.PermissionsAdded++
						}
						else
						{
							$permissionResults += [PSCustomObject]@{
								ManagedIdentityID = $managedIdentityID
								ServiceType		   = $resourceName
								Scope			   = $scope
								Status			   = "Failed"
								Message			   = "Scope was not present after import verification."
							}
							$summary.PermissionsFailed++
						}
					}
				}
				catch
				{
					Write-Log -Level ERROR -Message "Failed to process import results for Managed Identity '$managedIdentityID' on service '$resourceName': $($_.Exception.Message)"
					foreach ($scope in $scopes)
					{
						$permissionResults += [PSCustomObject]@{
							ManagedIdentityID = $managedIdentityID
							ServiceType		   = $resourceName
							Scope			   = $scope
							Status			   = "Failed"
							Message			   = "Result processing error: $($_.Exception.Message)"
						}
						$summary.PermissionsFailed++
					}
				}
				
				$summary.ServicesProcessed++
				$summary.PermissionsAttempted += $scopes.Count
			}
		}

		$summary.PermissionResults = @($permissionResults)
		
		Write-Log -Level INFO -Message "Completed import from '$ImportFilePath'. Rows read: '$($summary.RowsRead)', valid rows: '$($summary.RowsProcessed)', identities: '$($summary.IdentitiesProcessed)', services: '$($summary.ServicesProcessed)', permissions attempted: '$($summary.PermissionsAttempted)', added: '$($summary.PermissionsAdded)', already assigned: '$($summary.PermissionsAlreadyAssigned)', failed: '$($summary.PermissionsFailed)'."
		return $summary
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error importing managed identity permissions from '$ImportFilePath': $($_.Exception.Message)"
		throw
	}
}