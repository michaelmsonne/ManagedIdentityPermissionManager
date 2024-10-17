#--------------------------------------------
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

# Define the functions from your script
function Add-MicrosoftGraphPermission
{
	param (
		[string]$ObjectID,
		[psobject[]]$roleName
	)
	try
	{
		$msgraph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
		foreach ($role in $roleName)
		{
			Write-Host $role
			$Approle = $msgraph.AppRoles | Where-Object { $_.Value -eq $role }
			if ($Approle -eq $null)
			{
				throw "App role '$role' not found."
			}
			New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ObjectID -PrincipalId $ObjectID -ResourceId $msgraph.Id -AppRoleId $Approle.Id
			Update-Log -Message "Added Microsoft Graph permission '$role' to service principal '$ObjectID'."
		}
	}
	catch
	{
		Update-Log -Message "Error adding Microsoft Graph permission: $_"
	}
}

function Add-ExchangeOnlinePermission
{
	param (
		[string]$ObjectID,
		[psobject[]]$roleName
	)
	try
	{
		$spoApp = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'"
		foreach ($role in $roleName)
		{
			Write-Host $role
			$appRole = $spoApp.AppRoles | Where-Object { $_.Value -eq $role }
			if ($appRole -eq $null)
			{
				throw "App role '$role' not found."
			}
			New-MgServicePrincipalAppRoleAssignment -PrincipalId $ObjectID -ServicePrincipalId $ObjectID -ResourceId $spoApp.Id -AppRoleId $appRole.Id
			Update-Log -Message "Added Exchange Online permission '$role' to service principal '$ObjectID'."
		}
	}
	catch
	{
		Update-Log -Message "Error adding Exchange Online permission: $_"
	}
}

function Add-SharePointPermission
{
	param (
		[string]$ObjectID,
		[psobject[]]$roleName
	)
	try
	{
		$spoApp = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0ff1-ce00-000000000000'"
		foreach ($role in $roleName)
		{
			Write-Host $role
			$appRole = $spoApp.AppRoles | Where-Object { $_.Value -eq $role }
			if ($appRole -eq $null)
			{
				throw "App role '$role' not found."
			}
			New-MgServicePrincipalAppRoleAssignment -PrincipalId $ObjectID -ServicePrincipalId $ObjectID -ResourceId $spoApp.Id -AppRoleId $appRole.Id
			Update-Log -Message "Added SharePoint permission '$role' to service principal '$ObjectID'."
		}
	}
	catch
	{
		Update-Log -Message "Error adding SharePoint permission: $_"
	}
}