## [1.1.0.1] 05/04/2025

### Small enhancements & fixes

Fixed:
- Fix Windows Display Scaling issue when not properly handling high DPI settings, ensuring the UI scales correctly on all resolutions (but remember then the UI can looks bigger then your screen is...).
- Updated module detection logic to support scenarios where both Beta and GA versions of Microsoft Graph modules (e.g., `Microsoft.Graph.Authentication` and `Microsoft.Graph.Applications`) are installed, ensuring compatibility and avoiding unnecessary conflicts.

## [1.1.0.0] 06/02/2025

### Major enhancements & features! 🙌

Added:
- Service Principal filtering: Added functionality to filter and display service principals based on the selected service type and the APIs used in the connected tenant.
- Added an 'All Services' entry to the list of service principals and APIs used in the tenant connection, allowing users to view and manage permissions for all service principals.
- Most Used Services: Ensured that the most used services is on top in the service to manage.
    Microsoft Graph, Office 365 Exchange Online, Office 365 Information Protection, Office 365 SharePoint Online, WindowsDefenderATP, Microsoft Cloud App Security appear at the top of the list in the specified order for now (feedback are welcome).
- Detailed input validation: Enhanced input validation to provide detailed feedback on missing fields, ensuring users are informed about which specific input data is missing and other areas of the tools UI.
- Selected scopes validation: Added validation to check if any scopes are selected in the list of access scopes to manage or not, and log appropriate messages.

Changed:
- Improved logging: Enhanced logging to provide more detailed information about the operations being performed, including the retrieval and filtering of service principals and the addition of permission scopes.
- Global Data Storage: Updated the code to store service principal data in a global hashtable for reuse, reducing redundant API calls and improving efficiency for most of the code.
- Some small UI tweaks.

Fixed:
- Fixed the logging function to properly write to the logfile.

## [1.0.0.4] 24/01/2025

Added:
- Export feature for Managed Identity permissions assigned to a specific Managed Identity or all Managed Identities in tenant to a .csv file.

Changed:
- Some cleanup of the GUI and order in the menu
- Updated Set-ControlTheme function to ensure that controls tagged with 'DangerZone' have their ForeColor set to red, regardless of the theme.

Fixed:
- Improved code readability and maintainability by adding comments and structuring the code.
- Some small types/log text for better understanding

## [1.0.0.3] 23/12/2024

Added:
- Added option to download the lastest v. of the tool direct from a GitHub release!
- Added the ability to connect to Microsoft Graph using a specific tenant ID. Users can now enter a domain name or tenant ID in 'Tenant to connect' to connect to a specific tenant. If the input is left empty, the connection will proceed without specifying a tenant ID and use the last in the current users PowerShell. Thanks #14 !

Fixed:
- Some more logging added to functions
- Fixed some typos in logging, to give a better understanding

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