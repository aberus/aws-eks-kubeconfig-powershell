#
# Module manifest for module 'Aberus.AWS.Tools.EKS.KubeConfig'
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'Aberus.AWS.Tools.EKS.KubeConfig.psm1'

    # Version number of this module.
    ModuleVersion = '5.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Core', 'Desktop')

    # ID used to uniquely identify this module
    GUID = '29e6d3d9-dd1f-4a95-a5d0-8bb630fa6612'

    # Author of this module
    Author = 'Aleksander Berus'

    # Company or vendor of this module
    CompanyName = 'aberus.com'

    # Copyright statement for this module
    Copyright = 'Copyright Aleksander Berus. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'An extension of the AWS Tools for PowerShell EKS module that adds a cmdlet to update the kubeconfig file.
It returns the configured current-context and the path to the updated file, simplifying EKS cluster access from PowerShell.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the PowerShell host required by this module
    PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    DotNetFrameworkVersion = '4.7.2'

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{
            ModuleName = 'AWS.Tools.EKS';
            ModuleVersion  = '5.0.0';
            Guid = 'ee261d25-1f71-432f-848f-345d225b4f18' },
        @{
            ModuleName = 'powershell-yaml';
            ModuleVersion  = '0.4.12';
            Guid = '6a75a662-7f53-425a-9777-ee61284407da' }
    )

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Get-EKSToken',
        'Update-EKSKubeConfig'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # List of all modules packaged with this module
    ModuleList = @()

    # List of all files packaged with this module
    FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{
            Tags = @('AWS', 'cloud', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core', 'Linux', 'MacOS', 'Mac')
            LicenseUri = 'https://github.com/aberus/aws-eks-kubeconfig-powershell/blob/main/LICENSE'
            ProjectUri = 'https://github.com/aberus/aws-eks-kubeconfig-powershell'
            IconUri = 'https://sdk-for-net.amazonwebservices.com/images/AWSLogo128x128.png'
        }

    } 
}