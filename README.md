# BARK

![BARK Logo](https://i.imgur.com/skPLO7U.jpg)

BARK stands for BloodHound Attack Research Kit. It is a PowerShell script built to assist the BloodHound Enterprise team with researching and continuously validating abuse primitives. BARK currently focuses on Microsoft's Azure suite of products and services.

BARK requires no third party dependencies. BARK's functions are designed to be as simple and maintainable as possible. Most functions are very simple wrappers for making requests to various REST API endpoints. BARK's basic functions do not even require each other - you can pull almost any BARK function out of BARK and it will work perfectly as a standalone function in your own scripts.

Author and Contributors
-----------------------

Primary author:
Andy Robbins [@_wald0](https://twitter.com/@_wald0)

Contributors:
Jonas Bülow Knudsen [@Jonas_B_K](https://twitter.com/Jonas_B_K)
Fabian Bader [@fabian_bader](https://twitter.com/fabian_bader)
CravateRouge [@CravateRouge](@https://github.com/CravateRouge)
g60ocR [@g60ocR](https://github.com/g60ocR)

Getting Started
---------------

There are [many ways](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) to import a PowerShell script. Here's one way:

First, download BARK.ps1 by cloning this repo or simply copy/pasting its raw contents from GitHub.

    git clone https://github.com/BloodHoundAD/BARK
    
Now, cd into the directory where the PS1 is:

    cd BARK
    
Finally, you can dot import the PS1 like this:

    . .\BARK.ps1
    
Hit enter, and your PowerShell instance will now have access to all of BARK's functions.

Running your first BARK commands
--------------------------------

With very few exceptions, Azure API endpoints require authentication to interact with. BARK comes with a few functions that will help you acquire the necessary tokens for interacting with the MS Graph and Azure REST APIs. Any BARK function that interacts with an Azure API that requires authentication will require you to supply a token.

Let's say you want to list all of the users in an Azure Active Directory tenant. You first need to get a token scoped for MS Graph. There are many ways to get this token:

If you have a username/password combination for an AzureAD user in that tenant, you can first acquire a refresh token for the user using BARK's ``Get-AZRefreshTokenWithUsernamePassword`` function:

    $MyRefreshTokenRequest = Get-AZRefreshTokenWithUsernamePassword -username "arobbins@contoso.onmicrosoft.com" -password "MyVeryCoolPassword" -TenantID "contoso.onmicrosoft.com"
    
The resulting object you just created, `$MyRefreshTokenRequest`, will have as part of it a refresh token for your user. You can now request an MS Graph-scoped token using this refresh token:

    $MyMSGraphToken = Get-MSGraphTokenWithRefreshToken -RefreshToken $MyRefreshTokenRequest.refresh_token -TenantID "contoso.onmicrosoft.com"
    
Now this new object, `$MyMSGraphToken`, will have as one of its property values an MS Graph-scoped JWT for your user. You are now ready to use this token to list all the users in the AzureAD tenant:

    $MyAADUsers = Get-AllAzureADUsers -Token $MyMSGraphToken.access_token -ShowProgress
    
Once finished, the `$MyAADUsers` variable will be populated by objects representing all of the users in your AzureAD tenant.

Token Management and Manipulation Functions
-------------------------------------------

* ``Parse-JWTToken`` will take a Base64 encoded JWT as input and parse it for you. Useful for verifying correct token audience and claims.
* ``Get-AZRefreshTokenWithUsernamePassword`` requests a collection of tokens, including a refresh token, from login.microsoftonline.com with a user-supplied username and password. This will fail if the user has Multi-Factor Authentication requirements or is affected by a Conditional Access Policy.
* ``Get-MSGraphTokenWithClientCredentials`` requests an MS Graph-scoped JWT with a client ID and secret. Useful for authenticating as an AzureAD service principal.
* ``Get-MSGraphTokenWithRefreshToken`` requests an MS Graph-scoped JWT with a user-supplied refresh token.
* ``Get-MSGraphTokenWithPortalAuthRefreshToken`` requests an MS Graph-scoped JWT with a user-supplied Azure Portal Auth Refresh token.
* ``Get-AzureRMTokenWithClientCredentials`` requests an AzureRM-scoped JWT with a client ID and secret. Useful for authenticating as an AzureAD service principal.
* ``Get-ARMTokenWithPortalAuthRefreshToken`` requests an AzureRM-scoped JWT with a user-supplied Azure Portal Auth Refresh token.
* ``Get-ARMTokenWithRefreshToken`` requests an AzureRM-scoped JWT with a user-supplied refresh token.
* ``Get-AzurePortalTokenWithRefreshToken`` requests an Azure Portal Auth Refresh token with a user-supplied refresh token.

The refresh token-based functions in BARK are based on functions in [https://github.com/rvrsh3ll/TokenTactics](TokenTactics) by [https://twitter.com/424f424f](Steve Borosh)

Abuse Functions
---------------
* ``Set-AZUserPassword`` will attempt to set the password of another user to a new user-provided value.
* ``Reset-AZUserPassword`` will attempt to reset the password of another user. If successful, the output will contain the new, Azure-generated password of the user
* ``New-AzureRMRoleAssignment`` will attempt to grant a user-specified AzureRM role assignment to a particular principal over a certain scope.
* ``New-AppRegSecret`` will attempt to create a new secret for an existing AzureAD app registration.
* ``New-ServicePrincipalSecret`` will attempt to create a new secret for an existing AzureAD service principal.
* ``New-AppRoleAssignment`` will attempt to grant an app role to a service principal. For example, you can use this to grant a service principal the RoleManagement.ReadWrite.Directory app role.

Enumeration Functions
---------------------
* ``Get-AzureRMRoleDefinitions`` collects all role definitions described at a subscription scope, including custom roles.
* ``Get-MGAppRoles`` collects the app roles made available by the MS Graph service principal.
* ``Get-AllAzureADApps`` collects all AzureAD application registration objects.
* ``Get-AllAzureADServicePrincipals`` collects all AzureAD service principal objects.
* ``Get-AllAzureADUsers`` collects all AzureAD users.
* ``Get-AllAzureADGroups`` collects all AzureAD groups.
* ``Get-AllAzureRMSubscriptions`` collects all AzureRM subscriptions.

Meta Functions
--------------
* ``Test-AzureRMAddSelfToAzureRMRole`` used in abuse validation testing to determine whether a service principal with certain rights can grant itself the User Access Admin role over a subscription.
* ``Test-AzureRMCreateFunction`` used in abuse validation testing to test if a service principal can add a new function to an existing function app.
* ``Invoke-AllAzureRMAbuseTests`` performs all AzureRM abuse validation tests and outputs a resulting object that describes which AzureRM roles granted the ability to perform each abuse.
* ``Remove-AbuseTestAzureRMRoles`` is a clean-up function for removing AzureRM admin roles created during testing.
* ``Remove-AbuseTestServicePrincipals`` cleans up abuse tests by removing the serivce principals that were created during testing.
* ``New-TestAppReg`` creates an application registration object for the explicit purpose of abuse validation testing.
* ``New-TestSP`` creates a new service principal and associates it with the app created by the above function.
* ``Test-MGAddSelfAsOwnerOfApp`` is used in abuse validation testing to determine whether a service principal with a particular privilege can grant itself ownership of an existing AzureAD app.
* ``Test-MGAddSelfAsOwnerOfSP`` is used in abuse validation testing to determine whether a service principal with a particular privilege can grant itself ownership of an existing AzureAD service principal.
* ``Test-MGAddSelfToAADRole`` is used in abuse validation testing to determine whether a service principal with a particular privilege can add itself to an AzureAD admin role - Global Admin, for example.
* ``Test-MGAddSelfToMGAppRole``is used in abuse validation testing to determine whether a service principal with a particular privilege can grant itself a particular MS Graph app role without admin consent.
* ``Test-MGAddOwnerToRoleEligibleGroup`` is used to test whether a service principal can grant itself explicit ownership of a role assignable group.
* ``Test-MGAddMemberToRoleEligibleGroup`` is used to test whether the service principal can add itself to a role assignable group.
* ``Test-MGAddSecretToSP`` is used to test whether the service principal can add a new secret to an existing service principal.
* ``Test-MGAddSecretToApp`` is used to test whether the service principal can add a new secret to an existing app.
* ``Invoke-AllAzureMGAbuseTests`` performs all abuse validation tests that can be executed by holding an MS Graph app role. Returns an object describing which privileges were successful at performing each abuse test.
* ``Invoke-AllAzureADAbuseTests`` performs all abuse validation tests that can be executed by principals granted AzureAD admin roles. Returns an object describing which privileges were successful at performing each abuse test.
* ``ConvertTo-Markdown`` is used for massaging output from the Invoke-<type>Tests functions for usage in another platform.
