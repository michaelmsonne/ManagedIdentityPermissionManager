#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

$global:ConnectedState
$global:managedIdentities
$global:clearExistingPermissions
$global:darkModeStateUI

$global:FormVersion = "1.0.0.0"
$global:Author = "Michael Morten Sonne"
$global:ToolName = "Managed Identity Permission Manager"
$global:AuthorEmail = ""
$global:AuthorCompany = "Sonne´s Cloud"

#Get username and domain for account running this tool
$global:UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Logfile path
$LogPath = "$Env:USERPROFILE\AppData\Local\$global:ToolName"

function Is-WindowsInDarkMode
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
		}
		else
		{
			return $false # Light mode
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
			Write-Log -Level INFO -Message "The application log path does not exists and is created: '$LogPath'"
		}
	}
	# Catch specific types of exceptions thrown by one of those commands
	catch [System.Exception]
	{
		Write-Log -Level ERROR -Message $($Error[0].Exception.Message)
	}
	# Catch all other exceptions thrown by one of those commands
	catch
	{
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
		[ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
		[String]$Level = "INFO",
		[Parameter(Mandatory = $True)]
		[string]$Message,
		[Parameter(Mandatory = $False)]
		[string]$logfile = "$LogPath\$($ToolName)_Log_$($env:computername)" + "_" + (Get-Date -Format "dd/MM/yyyy") + ".log"
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

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory

function Get-ManagedIdentityCount
{
	$global:managedIdentities = Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'"
	return $global:managedIdentities.Count
}

# Function to check PowerShell Modules
function Check-Modules
{
	$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
	
	Write-Log -Level INFO -Message "Starting check for needed PowerShell Modules..."
	
	foreach ($module in $requiredModules)
	{
		if (-not (Get-Module -Name $module))
		{
			try
			{
				Import-Module $module -ErrorAction Stop
				
				Write-Log -Level INFO -Message "Importing module '$module'..."
				
			}			
			catch
			{				
				Write-Log -Level INFO -Message "Module '$module' is not installed. Installing..."
				
				Install-Module -Name $module -Scope CurrentUser -Force:$true
				
				Write-Log -Level INFO -Message "Importing module '$module'..."
				
				Import-Module $module				
			}
		}
		else
		{			
			Write-Log -Level INFO -Message "Module '$module' is already imported."
		}
		
	}	
	Write-Log -Level INFO -Message "Check for needed PowerShell Modules complete"
}

# Function to connect to Microsoft Graph
function ConnectToGraph
{
	Write-Log -Level INFO -Message "Starting to connect to Microsoft Graph..."
	
	Connect-MgGraph -NoWelcome -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All'
	
	# Check if the connection is successful
	try
	{
		$context = Get-MgContext
		if ($context -and $context.ClientId -and $context.TenantId)
		{
			Write-Log -Level INFO -Message "Successfully connected to Microsoft Graph as '$($context.Account)'"
			$ConnectedState = $true
		}
		else
		{
			Write-Log -Level ERROR -Message "Failed to connect to Microsoft Graph. Context is incomplete."
			$ConnectedState = $false
		}
	}
	catch
	{
		Write-Log -Level ERROR -Message "Failed to connect to Microsoft Graph. Error: $_"
		$ConnectedState = $false
	}
}

# Function to get current API assignments
function Get-CurrentAppRoleAssignments
{
	param (
		[string]$ManagedIdentityID
	)
	
	$result = ""
	try
	{
		# Retrieve the current app role assignments for the specified service principal
		
		Write-Log -Level INFO -Message "Getting permissions for Managed Identity with Id: '$ManagedIdentityID'"
		
		$currentAppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID
		
		if ($currentAppRoles)
		{
			$result += "Current permissions assignments for Managed Identity ID '$ManagedIdentityID':`r`n"
			foreach ($appRole in $currentAppRoles)
			{
				# Resolve ResourceId to Service Principal Name
				$resource = Get-MgServicePrincipal -ServicePrincipalId $appRole.ResourceId
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
			
			Write-Log -Level INFO -Message "Got current assigned permissions for Managed Identity ID '$ManagedIdentityID'"
		}
		else
		{
			$result += "No AppRole assignments found for Managed Identity ID '$ManagedIdentityID'.`r`n"
			
			Write-Log -Level INFO -Message "No AppRole assignments found for Managed Identity ID '$ManagedIdentityID'"
		}
	}
	catch
	{
		$result += "Error retrieving access scopes assignments for Managed Identity ID '$ManagedIdentityID': $_`r`n"
		
		Write-Log -Level ERROR -Message "Error retrieving access scopes assignments for Managed Identity ID '$ManagedIdentityID': $_"
	}
	
	return $result
}

# Function to add API assignments
function Add-ServicePrincipalPermission
{
	param (
		[string]$ManagedIdentityID,
		[string]$Permissions,
		[string]$ServiceType,
		[bool]$clearExistingPermissions
	)
	
	#Write-Log -Level INFO -Message "ManagedIdentityID: $ManagedIdentityID"
	
	try
	{
		#Update-Log -Message "Received ServiceType: '$ServiceType'"
		#Update-Log -Message "Received Permissions: '$Permissions'"
		
		switch ($ServiceType)
		{
			"Microsoft Graph" {
				$appId = '00000003-0000-0000-c000-000000000000'
			}
			"Exchange Online" {
				$appId = '00000002-0000-0ff1-ce00-000000000000'
			}
			"SharePoint" {
				$appId = '00000003-0000-0ff1-ce00-000000000000'
			}
			default {
				Write-Log -Level INFO -Message "Invalid ServiceType specified. Valid values are 'Microsoft Graph', 'Exchange Online', 'SharePoint'."
				return
			}
		}
		
		$AppGraph = Get-MgServicePrincipal -Filter "AppId eq '$appId'"
		
		# Ensure Permissions is not null or empty
		if (-not [string]::IsNullOrWhiteSpace($Permissions))
		{			
			if ($clearExistingPermissions -eq $true)
			{
				# Debug logging to verify ManagedIdentityID
				Write-Log -Level INFO -Message "ManagedIdentityID: $ManagedIdentityID"
				
				Write-Log -Level INFO -Message "Removing existing permissions because clear existing permissions is set"
				
				$AssignedPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID
				
				if ($AssignedPermissions.Count -eq 0)
				{
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
				
				Write-Log -Level INFO -Message "Current assigned permissions is:"
				for ($i = 0; $i -lt $AssignedPermissions.Count; $i++)
				{
					$AssignedPermission = @($AssignedPermissions)[$i]
					Write-Log -Level INFO -Message "Permission $($i + 1): service: '$($AssignedPermission.AppDisplayName)' | '$($AssignedPermission.PermissionName)'"
				}
				
				foreach ($permission in $AssignedPermissions)
				{
					try
					{
						Remove-MgServicePrincipalAppRoleAssignment -AppRoleAssignmentId $permission.Id -ServicePrincipalId $ManagedIdentityID
						Write-Log -Level INFO -Message "Permission for service: '$($permission.AppDisplayName)' | '$($permission.PermissionName)' has been removed"
					}
					catch
					{
						Write-Log -Level ERROR -Message "Failed to remove permission for service '$($permission.AppDisplayName)' | '$($permission.PermissionName)': $_"
					}
				}
				#Update-Log -Message "Permissions have been removed"
			}
			if ($clearExistingPermissions -eq $false)
			{
				Write-Log -Level INFO -Message "Set to keep existing permissions because clear existing permissions is not set"
			}			
			
			# Split the permissions string into an array and trim each element
			$Perms = $Permissions.Split(",") | ForEach-Object { $_.Trim() }
			
			#Update-Log -Message "Split permissions: $($Perms -join ', ')"
			
			foreach ($Scope in $Perms)
			{
				if (-not [string]::IsNullOrWhiteSpace($Scope))
				{
					Write-Log -Level INFO -Message "Processing permission '$Scope' for service '$ServiceType'"
					$AppRole = $AppGraph.AppRoles | Where-Object { $_.Value -eq $Scope }
					
					if ($AppRole)
					{
						$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID | Where-Object { $_.ResourceId -eq $AppGraph.Id -and $_.AppRoleId -eq $AppRole.Id }
						if ($existingAppRole)
						{
							Write-Log -Level INFO -Message "The scope '$Scope' is already assigned for service '$ServiceType'"
						}
						else
						{
							try
							{
								New-MgServicePrincipalAppRoleAssignment -PrincipalId $ManagedIdentityID -ServicePrincipalId $ManagedIdentityID -ResourceId $AppGraph.Id -AppRoleId $AppRole.Id > $null
								$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID | Where-Object { $_.ResourceId -eq $AppGraph.Id -and $_.AppRoleId -eq $AppRole.Id }
								if ($existingAppRole)
								{
									Write-Log -Level INFO -Message "The scope '$Scope' has been assigned to service '$ServiceType'"
								}
								else
								{
									Write-Log -Level INFO -Message "The scope '$Scope' could not be assigned for service '$ServiceType' - error: $_"
								}
							}
							catch
							{
								Write-Log -Level ERROR -Message "Error assigning the scope '$Scope' for service '$ServiceType': $_"
							}
						}
					}
					else
					{
						Write-Log -Level WARN -Message "No App Role found for scope '$Scope' to service '$ServiceType' - skipping"
					}
				}
				else
				{
					Write-Log -Level WARN -Message "Skipping empty or whitespace permission"
				}
			}
		}
		else
		{
			Write-Log -Level INFO -Message "Permissions parameter is empty or null"
		}
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error adding service '$ServiceType' permission '$Permissions': $_"
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
	
	#Write-Host "ManagedIdentityID: $ManagedIdentityID"
	
	try
	{
		# Log the received parameters
		Write-Log -Level INFO -Message "Managed Identity ObjectID: '$ManagedIdentityID'"
		Write-Log -Level INFO -Message "Service: '$ServiceType'"
		Write-Log -Level INFO -Message "Permissions: '$Permissions'"
		
		switch ($ServiceType)
		{
			"Microsoft Graph" {
				$appId = '00000003-0000-0000-c000-000000000000'
			}
			"Exchange Online" {
				$appId = '00000002-0000-0ff1-ce00-000000000000'
			}
			"SharePoint" {
				$appId = '00000003-0000-0ff1-ce00-000000000000'
			}
			default {
				Write-Log -Level INFO -Message "Invalid ServiceType specified. Valid values are 'Microsoft Graph', 'Exchange Online', 'SharePoint'."
				return
			}
		}
		
		$AppScopes = Get-MgServicePrincipal -Filter "AppId eq '$appId'"
		
		if ($null -eq $AppScopes)
		{
			[System.Windows.Forms.MessageBox]::Show("Service principal not found.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
			return
		}
		
		# Ensure Permissions is not null or empty
		if (-not [string]::IsNullOrWhiteSpace($Permissions))
		{
			# Split the permissions string into an array and trim each element
			$Perms = $Permissions.Split(",") | ForEach-Object { $_.Trim() }
			
			Write-Log -Level INFO -Message "Permissions to remove: $Perms"
			
			# Get the current API permissions assigned to the managed identity
			$currentPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID
			
			# Get all available permissions for the service principal
			$allPermissions = @{ }
			foreach ($appRole in $AppScopes.AppRoles)
			{
				$allPermissions[$appRole.Value] = $appRole.Id
				#Update-Log -Message "Available permission: $($appRole.Value) with ID: $($appRole.Id)"
			}
			
			# Remove the old permission assignments
			foreach ($permission in $Perms)
			{
				Write-Log -Level INFO -Message "Permission to be removed: $permission"
				
				if ($allPermissions.ContainsKey($permission.Trim()))
				{
					$appRoleId = $allPermissions[$permission.Trim()]
					$existingAppRole = $currentPermissions | Where-Object { $_.AppRoleId -eq $appRoleId }
					foreach ($role in $existingAppRole)
					{
						try
						{
							Write-Log -Level INFO -Message "Attempting to remove AppRoleAssignmentId: $($role.Id)"
							
							Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -AppRoleAssignmentId $role.Id
							
							Write-Log -Level INFO -Message "The scope '$permission' has been removed from service '$ServiceType'"
						}
						catch
						{
							Write-Log -Level ERROR -Message "Error removing the scope '$permission' from service '$ServiceType': $_"
						}
					}
				}
				else
				{
					Write-Log -Level ERROR -Message "Permission '$permission' not found in available permissions for service '$ServiceType'"
				}
			}
			
			#[System.Windows.Forms.MessageBox]::Show("Permissions updated successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
		}
		else
		{
			Write-Log -Level INFO -Message "Permissions parameter is empty or null"
		}
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error removing service '$ServiceType' permission '$Permissions': $_"
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
		$currentPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID
		
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
				
				Write-Log -Level INFO -Message "Attempting to remove AppRoleAssignmentId: $($permission.Id) for service: '$serviceName' with scope: '$permissionScope'"
				
				Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID -AppRoleAssignmentId $permission.Id
				
				Write-Log -Level INFO -Message "Permission with AppRoleAssignmentId '$($permission.Id)' for service: '$serviceName' with scope: '$permissionScope' has been removed."
			}
			catch
			{
				Write-Log -Level ERROR -Message "Error removing permission with AppRoleAssignmentId '$($permission.Id)' for service: '$serviceName' with scope: '$permissionScope': $_"
			}
		}
		
		#[System.Windows.Forms.MessageBox]::Show("All permissions removed successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error removing all permissions for managed identity '$ManagedIdentityID': $_"
	}
}