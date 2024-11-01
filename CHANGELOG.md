## [1.0.0.2] 01/11/2024

Added:
- Added an option to search for Managed Identityes in the list from tenant to manage (much better view also!)
- Check for if the tool is running as administrator or not
- Now logging current execution location of the tool

Fixed:
- Added some better logic for PowerShell execution policy

## [1.0.0.1] - 27/10/2024

Fixed:
- Added check for PowerShell execution policy (to support load of Microsoft.Graph.Authentication.psm1 when error 'cannot be loaded because running scripts is disabled on this system')
- Optimized the PowerShell Module check/install process to be more user friendly
- Fixed login functions, so if not logged in after press on 'Connect to Microsoft Graph' (via timeout or incomplete Context) the tool will not try to get Managed Identityes from tenant (as you are not logged, and therefor the tool will show '0').


## [1.0.0.0] - 25-10-2024

Initial release

Features for this release:

- Get a list of all Managed Identityes in connected tenant (Entra ID)
- Get corrent assigned permission for selected Managed Identityes
- Support one or many access scopes (for one API service at a time like Microsoft Graph)
- Add permission to selected Managed Identity (keep current assigned permisisons)
- Add permission to selected Managed Identity (reset current assigned permisisons so set to what set in the tool)
- Remove permission on selected Managed Identity
- Remove ALL permission on selected Managed Identity
- Get a list of access scopes (with filter options) to get the access scope you need to add/edit
- For user trust and confirmation, there is messages to comfirm for hight riks tasks
- Full logs for actions performed in the tool and for changes in assigned permissions (add or removal)
- And some more...