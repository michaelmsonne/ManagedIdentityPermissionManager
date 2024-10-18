#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

$global:ConnectedState
$global:managedIdentities
$global:clearExistingPermissions

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

# Function to update the log textbox
function Update-Log {
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

function Check-Modules
{
	$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
	
	Update-Log -Message "Starting check for needed PowerShell Modules..."
	
	foreach ($module in $requiredModules)
	{
		if (!(Get-InstalledModule -Name $module -ErrorAction SilentlyContinue))
		{
			Update-Log -Message "Module '$module' is not installed. Installing..."
			Install-Module -Name $module -Scope CurrentUser -Force
			Update-Log -Message "Importing module '$module'..."
			Import-Module $module
		}
		else
		{
			if (!(Get-Module -Name $module))
			{
				Update-Log -Message "Importing module '$module'..."
				Import-Module $module
			}
			else
			{
				Update-Log -Message "Module '$module' is already imported."
			}
		}
	}
	
	Update-Log -Message "Check for needed PowerShell Modules complete"
}

function ConnectToGraph
{
	Update-Log -Message "Starting to connect to Microsoft Graph..."
	
	Connect-MgGraph -NoWelcome -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All'
	
	# Check if the connection is successful
	try
	{
		$context = Get-MgContext
		if ($context -and $context.ClientId -and $context.TenantId)
		{
			Update-Log -message "Successfully connected to Microsoft Graph as '$($context.Account)'"
			$ConnectedState = $true
		}
		else
		{
			Update-Log -message "Failed to connect to Microsoft Graph. Context is incomplete."
			$ConnectedState = $false
		}
	}
	catch
	{
		Update-Log -message "Failed to connect to Microsoft Graph. Error: $_"
		$ConnectedState = $false
	}
}

function Get-CurrentAppRoleAssignments
{
	param (
		[string]$ManagedIdentityID
	)
	
	$result = ""
	try
	{
		# Retrieve the current app role assignments for the specified service principal
		
		Update-Log -Message "Getting permissions for '$ManagedIdentityID'"
		
		$currentAppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID
		
		if ($currentAppRoles)
		{
			$result += "Current AppRole assignments for Managed Identity ID '$ManagedIdentityID':`r`n"
			foreach ($appRole in $currentAppRoles)
			{
				# Resolve ResourceId to Service Principal Name
				$resource = Get-MgServicePrincipal -ServicePrincipalId $appRole.ResourceId
				$resourceName = $resource.DisplayName
				
				# Resolve AppRoleId to App Role Name and Value (Scope)
				$appRoleDetails = $resource.AppRoles | Where-Object { $_.Id -eq $appRole.AppRoleId }
				$appRoleName = $appRoleDetails.DisplayName
				$appRoleScope = $appRoleDetails.Value
				
				$appRoleInfo = @"

AppRoleAssignmentId: '$($appRole.Id)'
PrincipalId: '$($appRole.PrincipalId)'
ResourceId: '$($appRole.ResourceId)'
ResourceName: '$resourceName'
AppRoleId: '$($appRole.AppRoleId)'
AppRoleName: '$appRoleName'
AppRoleScope: '$appRoleScope'
"@
				$result += $appRoleInfo + "`r`n"
			}
			
			Update-Log -Message "Got permissions for '$ManagedIdentityID'"
		}
		else
		{
			$result += "No AppRole assignments found for Managed Identity ID '$ManagedIdentityID'.`r`n"
			
			Update-Log -Message "No AppRole assignments found for Managed Identity ID '$ManagedIdentityID'"
		}
	}
	catch
	{
		$result += "Error retrieving AppRole assignments for Managed Identity ID '$ManagedIdentityID': $_`r`n"
		
		Update-Log -Message "Error retrieving AppRole assignments for Managed Identity ID '$ManagedIdentityID': $_"
	}
	
	return $result
}

function Add-ServicePrincipalPermission
{
	param (
		[string]$ManagedIdentityID,
		[string]$Permissions,
		[string]$ServiceType,
		[bool]$clearExistingPermissions
	)
	
	Write-Host "ManagedIdentityID: $ManagedIdentityID"
	
	try
	{
		#Update-Log -Message "Received ServiceType: '$ServiceType'"
		#Update-Log -Message "Received Permissions: '$Permissions'"
		
		switch ($ServiceType)
		{
			"MicrosoftGraph" {
				$appId = '00000003-0000-0000-c000-000000000000'
			}
			"ExchangeOnline" {
				$appId = '00000002-0000-0ff1-ce00-000000000000'
			}
			"SharePoint" {
				$appId = '00000003-0000-0ff1-ce00-000000000000'
			}
			default {
				Update-Log -Message "Invalid ServiceType specified. Valid values are 'MicrosoftGraph', 'ExchangeOnline', 'SharePoint'."
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
				Update-Log -Message "ManagedIdentityID: $ManagedIdentityID"
								
				Update-Log -Message "Removing existing permissions because clear existing permissions is set"
				
				$AssignedPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID
				
				if ($AssignedPermissions.Count -eq 0)
				{
					Update-Log -Message "No permissions assigned"
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
				
				Update-Log -Message "Current assigned permissions is:"
				for ($i = 0; $i -lt $AssignedPermissions.Count; $i++)
				{
					$AssignedPermission = @($AssignedPermissions)[$i]
					Update-Log -Message "Permission $($i + 1): service: '$($AssignedPermission.AppDisplayName)' | '$($AssignedPermission.PermissionName)'"
				}
				
				foreach ($permission in $AssignedPermissions)
				{
					try
					{
						Remove-MgServicePrincipalAppRoleAssignment -AppRoleAssignmentId $permission.Id -ServicePrincipalId $ManagedIdentityID
						Update-Log -Message "Permission for service: '$($permission.AppDisplayName)' | '$($permission.PermissionName)' has been removed"
					}
					catch
					{
						Update-Log -Message "Failed to remove permission for service '$($permission.AppDisplayName)' | '$($permission.PermissionName)': $_"
					}
				}
				#Update-Log -Message "Permissions have been removed"
			}
			if ($clearExistingPermissions -eq $false)
			{
				Update-Log -Message "Set to keep existing permissions because clear existing permissions is not set"
			}			
			
			# Split the permissions string into an array and trim each element
			$Perms = $Permissions.Split(",") | ForEach-Object { $_.Trim() }
			
			#Update-Log -Message "Split permissions: $($Perms -join ', ')"
			
			foreach ($Scope in $Perms)
			{
				if (-not [string]::IsNullOrWhiteSpace($Scope))
				{
					Update-Log -Message "Processing permission '$Scope' for service '$ServiceType'"
					$AppRole = $AppGraph.AppRoles | Where-Object { $_.Value -eq $Scope }
					
					if ($AppRole)
					{
						$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID | Where-Object { $_.ResourceId -eq $AppGraph.Id -and $_.AppRoleId -eq $AppRole.Id }
						if ($existingAppRole)
						{
							Update-Log -Message "The scope '$Scope' is already assigned for service '$ServiceType'"
						}
						else
						{
							try
							{
								New-MgServicePrincipalAppRoleAssignment -PrincipalId $ManagedIdentityID -ServicePrincipalId $ManagedIdentityID -ResourceId $AppGraph.Id -AppRoleId $AppRole.Id > $null
								$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID | Where-Object { $_.ResourceId -eq $AppGraph.Id -and $_.AppRoleId -eq $AppRole.Id }
								if ($existingAppRole)
								{
									Update-Log -Message "The scope '$Scope' has been assigned to service '$ServiceType'"
								}
								else
								{
									Update-Log -Message "The scope '$Scope' could not be assigned for service '$ServiceType'"
								}
							}
							catch
							{
								Update-Log -Message "Error assigning the scope '$Scope' for service '$ServiceType': $_"
							}
						}
					}
					else
					{
						Update-Log -Message "No App Role found for scope '$Scope' to service '$ServiceType' - skipping"
					}
				}
				else
				{
					Update-Log -Message "Skipping empty or whitespace permission"
				}
			}
		}
		else
		{
			Update-Log -Message "Permissions parameter is empty or null"
		}
	}
	catch
	{
		Update-Log -Message "Error adding service '$ServiceType' permission '$Permissions': $_"
	}
}


