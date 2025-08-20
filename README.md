# AWS EKS KubeConfig for PowerShell

## Description
This cmdlet returns an object containing the configured current-context and the path of the updated kubeconfig file. 
It provides similar functionality to AWS CLI Command `aws eks update-kubeconfig`. It wraps around `Get-EKSCluster` cmdlet to 
get the information about cluster and depends on [powershell-yaml](https://www.powershellgallery.com/packages/powershell-yaml).


```powershell
Update-EKSKubeConfig
    -Name <String>
    -KubeConfigPath <String>
    -RoleArn <String>
    -Alias <String>
    -UserAlias <String>
    -ClientConfig <AmazonEKSConfig>
```

#### Example
```powershell
PS C:> Update-EKSKubeConfig -Name example -Region us-west-1
Updated context arn:aws:eks:us-west-2:012345678910:cluster/example in /Users/ericn/.kube/config

Context                                            Path
-------                                            ----
arn:aws:eks:us-west-2:012345678910:cluster/example /Users/ericn/.kube/config
```


## Install

To install the module you can run in a PowerShell following command:

```PowerShell
Install-Module -Name Aberus.AWS.Tools.EKS.KubeConfig
```

To install the module using the PowerShellGet v3:

```powershell
Install-PSResource -Name Aberus.AWS.Tools.EKS.KubeConfig
```

Or download this module from PowerShell Gallery:
https://www.powershellgallery.com/packages/Aberus.AWS.Tools.EKS.KubeConfig/


## License

The content of this repository is licensed under the Apache 2.0 License.