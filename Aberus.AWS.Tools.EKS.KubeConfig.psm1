
function Update-EKSKubeConfig {
    <#
        .SYNOPSIS
        Updates the kubeconfig file for an EKS cluster.

        .DESCRIPTION
        This function updates the kubeconfig file for an Amazon EKS cluster, allowing users to interact with the cluster using kubectl.

        .PARAMETER Name
        The name of the EKS cluster to update the kubeconfig for.

        .PARAMETER KubeConfigPath
        The path to the kubeconfig file. If not specified, defaults to `$HOME\.kube\config`.

        .PARAMETER RoleArn
        The ARN of the IAM role to assume for accessing the EKS cluster.

        .PARAMETER Alias
        An alias for the context in the kubeconfig file. If not specified, defaults to the cluster ARN.

        .PARAMETER UserAlias
        An alias for the user in the kubeconfig file. If not specified, defaults to the cluster ARN.

        .PARAMETER EndpointUrl
        The endpoint to make the call against.
        <b>Note:</b> This parameter is primarily for internal AWS use and is not required/should not be specified for normal usage. The cmdlets normally determine which endpoint to call based on the region specified to the -Region parameter or set as default in the shell (via Set-DefaultAWSRegion). Only specify this parameter if you must direct the call to a specific custom endpoint.

        .PARAMETER Region
        The system name of an AWS region or an AWSRegion instance. This governs the endpoint that will be used when calling service operations. Note that the AWS resources referenced in a call are usually region-specific.

        .PARAMETER AccessKey
        The AWS access key for the user account. This can be a temporary access key if the corresponding session token is supplied to the -SessionToken parameter.

        .PARAMETER SecretKey
        The AWS secret key for the user account. This can be a temporary secret key if the corresponding session token is supplied to the -SessionToken parameter.

        .PARAMETER SessionToken
        The session token if the access and secret keys are temporary session-based credentials.

        .PARAMETER ProfileName
        The user-defined name of an AWS credentials or SAML-based role profile containing credential information. The profile is expected to be found in the secure credential file shared with the AWS SDK for .NET and AWS Toolkit for Visual Studio. You can also specify the name of a profile stored in the .ini-format credential file used with the AWS CLI and other AWS SDKs.

        .PARAMETER ProfileLocation
        Used to specify the name and location of the ini-format credential file (shared with the AWS CLI and other AWS SDKs)
        If this optional parameter is omitted this cmdlet will search the encrypted credential file used by the AWS SDK for .NET and AWS Toolkit for Visual Studio for the 'default' and 'AWS PS Default' profiles. If the profiles are not found then the cmdlet will search in the ini-format credential file at the default location: (user's home directory)\.aws\credentials.
        If this parameter is specified then this cmdlet will only search the ini-format credential file at the location given.
        As the current folder can vary in a shell or during script execution it is advised that you use specify a fully qualified path instead of a relative path.

        .PARAMETER Credential
        An AWSCredentials object instance containing access and secret key information, and optionally a token for session-based credentials.

        .PARAMETER NetworkCredential
        Used with SAML-based authentication when ProfileName references a SAML role profile. Contains the network credentials to be supplied during authentication with the  configured identity provider's endpoint. This parameter is not required if the user's default network identity can or should be used during authentication.

        .EXAMPLE
        Update-EKSKubeConfig -Name my-eks-cluster -KubeConfigPath "C:\path\to\config" -RoleArn "arn:aws:iam::123456789012:role/EKS-Role" -Alias my-cluster-alias -UserAlias my-user-alias -Region us-west-2

        Updated context my-cluster-alias in C:\path\to\config

        Context          Path
        -------          ----
        my-cluster-alias C:\path\to\config

        .EXAMPLE
        Update-EKSKubeConfig -Region eu-west-1 -Name my-eks-cluster -ProfileName user1

        Updated context arn:aws:eks:us-west-2:012345678910:cluster/example in /Users/ericn/.kube/config

        Context                                            Path
        -------                                            ----
        arn:aws:eks:us-west-2:012345678910:cluster/example /Users/ericn/.kube/config
    #>

    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$KubeConfigPath,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$RoleArn,

        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $false)]
        [string]$Alias = $null,

        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $false)]
        [string]$UserAlias = $null,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Amazon.EKS.AmazonEKSConfig]$ClientConfig,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$EndpointUrl,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ArgumentCompleter(
            {
                param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

                $regionHash = @{ }
                $regions = [Amazon.RegionEndpoint]::EnumerableAllRegions
                foreach ($r in $regions) {
                    $regionHash.Add($r.SystemName, $r.DisplayName)
                }

                $regionHash.Keys |
                Sort-Object |
                Where-Object { $_ -like "$wordToComplete*" } |
                ForEach-Object {
                    New-Object System.Management.Automation.CompletionResult $_, $_, 'ParameterValue', $regionHash[$_]
                }
            }
        )]
        [Alias("RegionToCall")]
        [object]$Region,

        [Alias("AK")]
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$AccessKey,

        [Alias("SK", "SecretAccessKey")]
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$SecretKey,

        [Alias("ST")]
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$SessionToken,

        [ArgumentCompleter(
            {
                param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

                # Allow for new user with no profiles set up yet
                $profiles = Get-AWSCredentials -ListProfileDetail | Select-Object -ExpandProperty ProfileName
                if ($profiles) {
                    $profiles |
                    Sort-Object |
                    Where-Object { $_ -like "$wordToComplete*" } |
                    ForEach-Object {
                        New-Object System.Management.Automation.CompletionResult $_, $_, 'ParameterValue', $_
                    }
                }
            }
        )]
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias("StoredCredentials", "AWSProfileName")]
        [string]$ProfileName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias("AWSProfilesLocation", "ProfilesLocation")]
        [string]$ProfileLocation,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Amazon.Runtime.AWSCredentials]$Credential,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Management.Automation.PSCredential]$NetworkCredential
    )

    # Build parameter hashtable for Get-EksCluster
    $eksClusterParams = @{
        Name = $Name
    }
    if ($AccessKey) { $eksClusterParams.Add("AccessKey", $AccessKey) }
    if ($SecretKey) { $eksClusterParams.Add("SecretKey", $SecretKey) }
    if ($SessionToken) { $eksClusterParams.Add("SessionToken", $SessionToken) }
    if ($ClientConfig) { $eksClusterParams.Add("ClientConfig", $ClientConfig) }
    if ($Credential) { $eksClusterParams.Add("Credential", $Credential) }
    if ($EndpointUrl) { $eksClusterParams.Add("EndpointUrl", $EndpointUrl) }
    if ($NetworkCredential) { $eksClusterParams.Add("NetworkCredential", $NetworkCredential) }
    if ($ProfileLocation) { $eksClusterParams.Add("ProfileLocation", $ProfileLocation) }
    if ($ProfileName) { $eksClusterParams.Add("ProfileName", $ProfileName) }
    if ($Region) { $eksClusterParams.Add("Region", $Region) }

    # Get EKS Cluster information
    try {
        $eksCluster = Get-EksCluster @eksClusterParams
    }
    catch {
        Write-Error -Exception $_.Exception -Category $_.CategoryInfo.Category -TargetObject $_.TargetObject
        return
    }

    if ($null -eq $eksCluster) {
        Write-Error "EKS Cluster with name '$Name' not found."
        return
    }

    if (-not $KubeConfigPath) {
        $KubeConfigPath = Join-Path -Path "$HOME" -ChildPath "\.kube\config" 
    }

    if (-not (Test-Path -PathType Leaf $KubeConfigPath)) {
        New-Item -ItemType File -Path $KubeConfigPath -Force
    }

    # Load existing kubeconfig; create new if not exists
    if (ValidateKubeConfigFile $kubeConfigPath) {
        $kubeConfig = ConvertFrom-Yaml (Get-Content $kubeConfigPath -Raw) -Ordered

        if (-not $kubeConfig.clusters) {
            Write-Verbose "The 'clusters' field is missing in the KubeConfig file."
            $kubeConfig.clusters = New-Object 'Collections.Generic.List[System.Object]'
        }

        if (-not $kubeConfig.contexts) {
            Write-Verbose "The 'contexts' field is missing in the KubeConfig file."
            $kubeConfig.contexts = New-Object 'Collections.Generic.List[System.Object]'
        }

        if (-not $kubeConfig.users) {
            Write-Verbose "The 'users' field is missing in the KubeConfig file."
            $kubeConfig.users = New-Object 'Collections.Generic.List[System.Object]'
        }

        if (-not $kubeConfig.'current-context') {
            Write-Verbose "The 'current-context' field is missing in the KubeConfig file."
        }
    }
    else {
        $kubeConfig = [ordered]@{
            apiVersion        = 'v1'
            clusters          = New-Object 'Collections.Generic.List[System.Object]'
            contexts          = New-Object 'Collections.Generic.List[System.Object]' 
            'current-context' = ''
            kind              = 'Config'
            preferences       = @{}
            users             = New-Object 'Collections.Generic.List[System.Object]' 
        }
    }

    if ($Alias) {
        $contextName = $Alias
    }
    else {
        $contextName = $EksCluster.Arn
    }

    if ($UserAlias) {
        $userName = $UserAlias
    }
    else {
        $userName = $EksCluster.Arn
    }

    # Update or add cluster
    UpdateCluster -EksCluster $EksCluster -KubeConfig ([ref]$kubeConfig)

    # Update or add user
    UpdateUser -EksCluster $EksCluster -UserName $userName -KubeConfig ([ref]$kubeConfig) -ProfileName $ProfileName

    # Update or add context
    UpdateContext -ClusterName $EksCluster.Arn -ContexName $contextName -UserName $userName -KubeConfig ([ref]$kubeConfig)

    # Update the current context (optional)
    $kubeConfig.'current-context' = $contextName

    # Save updated kubeconfig
    $kubeConfig | ConvertTo-Yaml | Set-Content $kubeConfigPath

    Write-Host "Updated context $contextName in $kubeConfigPath"

    [PSCustomObject]@{
        Context  = $contextName
        Path     = $kubeConfigPath
    }
}

function ValidateKubeConfigFile([string]$kubeConfigPath) {
    # Check if the kubeconfig file exists
    if (-not (Test-Path $kubeConfigPath)) {
        Write-Verbose "KubeConfig file does not exist at path: $kubeConfigPath"
        return $false
    }

    # Check if the kubeconfig file is not empty
    if ((Get-Item $kubeConfigPath).Length -eq 0) {
        Write-Verbose "KubeConfig file is empty: $kubeConfigPath"
        return $false
    }

    try {
        # Attempt to parse the kubeconfig file as YAML
        Get-Content $kubeConfigPath -Raw | ConvertFrom-Yaml | Out-Null
    } catch {
        Write-Verbose "Failed to parse KubeConfig file as YAML: $_"
        return $false
    }
    # If all checks pass
    return $true
}

function UpdateCluster([PSCustomObject]$EksCluster, [ref]$KubeConfig) {
    # Extract cluster details
    $clusterName = $EksCluster.Arn
    $endpoint = $EksCluster.Endpoint
    $certificateAuthorityData = $EksCluster.CertificateAuthority.Data

    # Check if the cluster already exists in kubeconfig
    $clusterIndex = $KubeConfig.Value.clusters.FindIndex({ $args.name -eq $clusterName })

    $clusterEntry = [ordered]@{
        cluster = [ordered]@{
            'certificate-authority-data' = $certificateAuthorityData
            server                       = $endpoint
        }
        name = $clusterName
    }

    if ($clusterIndex -ge 0) {
        # Update existing cluster entry
        $KubeConfig.Value.clusters[$clusterIndex] = $clusterEntry
    }
    else {
        # Add new cluster entry
        $KubeConfig.Value.clusters += $clusterEntry
    }
}

function UpdateUser([PSCustomObject]$EksCluster, [ref]$KubeConfig, [string]$ProfileName, [string]$UserName) {
    $outpostConfig = $EksCluster.OutpostConfig
    $region = $EksCluster.Arn.Split(":")[3]

    if ($outpostConfig) {
        #$clusterIdentificationParameter = "--cluster-id"
        $clusterIdentificationValue = $EksCluster.Id
    }
    else {
        #$clusterIdentificationParameter = "--cluster-name"
        $clusterIdentificationValue = $EksCluster.Name
    }

    # Check if user entry exists and update if necessary
    $userIndex = $KubeConfig.Value.users.FindIndex({ $args.name -eq $UserName })

    # Add new user entry
    $userEntry = [ordered]@{
        name = $userName
        user = [ordered]@{
            exec = [ordered]@{
                apiVersion         = 'client.authentication.k8s.io/v1beta1'
                args               = @(
                    '-command',
                    "&{ &'Get-EKSToken' -ClusterNameOrId $($clusterIdentificationValue) -ProfileName $($ProfileName) -Region $($region)}"
                )
                command            = 'pwsh'
                interactiveMode    = 'IfAvailable'
                provideClusterInfo = $False
            }
        }
    }

    if ($ProfileName) {
        $userEntry.user.exec.env = @(
            [ordered]@{
                name  = 'AWS_PROFILE'
                value = $ProfileName
            }
        )
    }

    if ($userIndex -ge 0) {
        $KubeConfig.Value.users[$userIndex] = $userEntry
    }
    else {
        # Add new user entry
        $KubeConfig.Value.users += $userEntry
    }
}

function UpdateContext([string]$ClusterName, [string]$ContexName, [ref]$KubeConfig, [string]$UserName) {
    # Check if context entry exists and update if necessary
    $contextIndex = $KubeConfig.Value.contexts.FindIndex({ $args.name -eq $ContexName })

    $contextEntry = [ordered]@{
        context = [ordered]@{
            cluster = $ClusterName
            user    = $UserName
        }
        name    = $ContexName
    }

    if ($contextIndex -ge 0) {
        # Update context configuration if needed
        $KubeConfig.Value.contexts[$contextIndex] = $contextEntry
    }
    else {
        # Add new context entry
        $KubeConfig.Value.contexts += $contextEntry
    }
}

function Get-EKSToken {
    param(
    [Parameter(Mandatory = $true)]
    [string]$ClusterNameOrId,
   
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
    [ArgumentCompleter(
        {
            param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

            $regionHash = @{ }
            $regions = [Amazon.RegionEndpoint]::EnumerableAllRegions
            foreach ($r in $regions) {
                $regionHash.Add($r.SystemName, $r.DisplayName)
            }

            $regionHash.Keys |
            Sort-Object |
            Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object {
                New-Object System.Management.Automation.CompletionResult $_, $_, 'ParameterValue', $regionHash[$_]
            }
        }
    )]
    [Alias("RegionToCall")]
    [object]$Region,

    [ArgumentCompleter(
        {
            param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

            # Allow for new user with no profiles set up yet
            $profiles = Get-AWSCredentials -ListProfileDetail | Select-Object -ExpandProperty ProfileName
            if ($profiles) {
                $profiles |
                Sort-Object |
                Where-Object { $_ -like "$wordToComplete*" } |
                ForEach-Object {
                    New-Object System.Management.Automation.CompletionResult $_, $_, 'ParameterValue', $_
                }
            }
        }
    )]
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [Alias("StoredCredentials", "AWSProfileName")]
    [string]$ProfileName,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [Alias("AWSProfilesLocation", "ProfilesLocation")]
    [string]$ProfileLocation
)

    $regionArgs = New-Object Amazon.PowerShell.Common.StandaloneRegionArguments
    $regionArgs.Region = $Region
    $regionArgs.ProfileLocation = $ProfileLocation

    $regionEndpoint = [Amazon.PowerShell.Common.IAWSRegionArgumentsMethods]::GetRegion($regionArgs, $true, $ExecutionContext.SessionState)
    if (-not $regionEndpoint) {
        Write-Error -Message "No region specified or obtained from persisted/shell defaults." -Category InvalidOperation
        return
    }

    $credentials = Get-AwsCredential -ProfileName $ProfileName

    # Create the STS client configuration
    $config = New-Object Amazon.SecurityToken.AmazonSecurityTokenServiceConfig
    $config.RegionEndpoint = $regionEndpoint

    # Create the GetCallerIdentity request
    $getCallerIdentityRequest = [Amazon.SecurityToken.Model.GetCallerIdentityRequest]::new()
    $marshaller = [Amazon.SecurityToken.Model.Internal.MarshallTransformations.GetCallerIdentityRequestMarshaller]::new()
    $request = $marshaller.Marshall($getCallerIdentityRequest)
    # $request = [Amazon.Runtime.Internal.DefaultRequest]::new($getCallerIdentityRequest, $config.AuthenticationServiceName)
    # $request.Parameters.Add("Action", "GetCallerIdentity")
    # $request.Parameters.Add("Version", "2011-06-15")
    $request.UseQueryString = $true
    $request.HttpMethod = "GET"
    $request.Endpoint = [Uri]::new($config.DetermineServiceOperationEndpoint($getCallerIdentityRequest).URL)

    $expirationTime = New-TimeSpan -Seconds 60
    $request.Parameters["X-Amz-Expires"] = [int]$expirationTime.TotalSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)

    # Get credentials (assuming credentials is defined)
    $immutableCredentials = $credentials.GetCredentials()
    if ($immutableCredentials.UseToken) {
        $request.Parameters["X-Amz-Security-Token"] = $immutableCredentials.Token
    }

    $request.Headers["x-k8s-aws-id"] = $ClusterNameOrId

    # Sign the request
    $signingResult = [Amazon.Runtime.Internal.Auth.AWS4PreSignedUrlSigner]::SignRequest(
        $request,
        $config,
        [Amazon.Runtime.Internal.Util.RequestMetrics]::new(),
        $immutableCredentials.AccessKey,
        $immutableCredentials.SecretKey,
        $config.AuthenticationServiceName,
        $config.RegionEndpoint.SystemName
    )

    # Calculate token expiration
    $tokenExpiration = $signingResult.DateTime.AddMinutes(14)

    # Compose the URL
    $authorization = "&" + $signingResult.ForQueryParameters
    $url = [Amazon.Runtime.AmazonServiceClient]::ComposeUrl($request).AbsoluteUri + $authorization

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($url)
    $encodedText = [Convert]::ToBase64String($bytes)

    $expirationTimestamp = [DateTime]::new($tokenExpiration.Year, $tokenExpiration.Month, $tokenExpiration.Day, $tokenExpiration.Hour, $tokenExpiration.Minute, $tokenExpiration.Second, $tokenExpiration.Kind)

    $json = [PSCustomObject]@{
        kind       = 'ExecCredential'
        apiVersion = 'client.authentication.k8s.io/v1'
        spec       = @{}
        status     = @{
            expirationTimestamp = $expirationTimestamp # "2024-08-22T12:09:49Z"
            token               = 'k8s-aws-v1.' + $encodedText.Replace("=", "")
        }
    }

    ConvertTo-Json $json
}