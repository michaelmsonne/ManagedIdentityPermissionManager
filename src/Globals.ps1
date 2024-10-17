﻿#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

$global:ConnectedState = $false

$global:managedIdentities

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
}

function ConnectToGraph
{
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




function Add-ServicePrincipalPermission
{
	param (
		[string]$ManagedIdentityID,
		[string]$Permissions,
		[string]$ServiceType
	)
	
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
			# Split the permissions string into an array and trim each element
			$Perms = $Permissions.Split(",") | ForEach-Object { $_.Trim() }
			
			#Update-Log -Message "Split permissions: $($Perms -join ', ')"
			
			foreach ($Scope in $Perms)
			{
				if (-not [string]::IsNullOrWhiteSpace($Scope))
				{
					Update-Log -Message "Processing permission '$Scope'"
					$AppRole = $AppGraph.AppRoles | Where-Object { $_.Value -eq $Scope }
					
					if ($AppRole)
					{
						$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID | Where-Object { $_.ResourceId -eq $AppGraph.Id -and $_.AppRoleId -eq $AppRole.Id }
						if ($existingAppRole)
						{
							Update-Log -Message "The scope '$Scope' is already assigned"
						}
						else
						{
							try
							{
								New-MgServicePrincipalAppRoleAssignment -PrincipalId $ManagedIdentityID -ServicePrincipalId $ManagedIdentityID -ResourceId $AppGraph.Id -AppRoleId $AppRole.Id > $null
								$existingAppRole = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityID | Where-Object { $_.ResourceId -eq $AppGraph.Id -and $_.AppRoleId -eq $AppRole.Id }
								if ($existingAppRole)
								{
									Update-Log -Message "The scope '$Scope' has been assigned"
								}
								else
								{
									Update-Log -Message "The scope '$Scope' could not be assigned"
								}
							}
							catch
							{
								Update-Log -Message "Error assigning the scope '$Scope': $_"
							}
						}
					}
					else
					{
						Update-Log -Message "No App Role found for scope '$Scope'"
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
		Update-Log -Message "Error adding $ServiceType permission '$Permissions': $_"
	}
}


