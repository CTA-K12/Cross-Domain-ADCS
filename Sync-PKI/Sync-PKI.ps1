<#
	.SYNOPSIS
		Script to copy or delete PKI objects (default is copy).
	
	.DESCRIPTION
		This script allows updating PKI objects in Active Directory for the
		cross-forest certificate enrollment.
	
	.PARAMETER SourceForestName
		DNS of the forest to process object from.
	
	.PARAMETER TargetForestName
		DNS of the forest to process object to.
	
	.PARAMETER SourceDC
		DNS of the DC in the source forest to process object from.
	
	.PARAMETER TargetDC
		DNS of the DC in the target forest to process object to.
	
	.PARAMETER ObjectType
		Type of object to process, if omitted then all object types are processed.
		ES			Process Enrollment Serverices Container object(s).
		Template	Process Template Container object(s).
		OID			Process Object Identifier Container object(s).
		ALL			Process All Containers.
		CA			Process Certificate Authorities Container object(s).
		AIA			Process AIA Container Object(s).
		NTAuth		Process NTAuthCertifcates object.
	
	.PARAMETER ObjectCN
		Common name of the object to process, do not include the cn= (ie "User" and not "CN=User"').
		This option is only valid if -ObjectType <> is also specified.
	
	.PARAMETER WhatIf
		Display what object(s) will be processed without processing.
	
	.PARAMETER DeleteOnly
		Will delete object in the target forest if it exists.
	
	.PARAMETER Force
		Force Force of existing objects when copying. Ignored when deleting.
	
	.EXAMPLE
		Copy
		PS C:\> .\PKISync.ps1 -SourceForestName <SourceForestFQDN> -TargetForestName <TargetForestFQDN> [-SourceDC <SourceDCFQDN>] [-TargetDC <TargetDCFQDN>] [-ObjectType <ES|Template|OID|CA|NTAuth> [-ObjectCN <ObjectCN>]] [-Force] [-WhatIf]"
	
	.EXAMPLE
		Delete
		PS C:\> .\PKISync.ps1 --TargetForestName <TargetForestFQDN> [-TargetDC <TargetDCFQDN>] [-ObjectType <ES|Template|OID|CA|NTAuth> [-ObjectCN <ObjectCN>]] [-DeleteOnly] [-WhatIf]"
	
	.NOTES
		This sample script is not supported under any Microsoft standard support
		program or service. This sample script is provided AS IS without warranty
		of any kind. Microsoft further disclaims all implied warranties including,
		without limitation, any implied warranties of merchantability or of fitness
		for a particular purpose. The entire risk arising out of the use or performance
		of the sample scripts and documentation remains with you. In no event shall
		Microsoft, its authors, or anyone else involved in the creation, production,
		or delivery of the scripts be liable for any damages whatsoever (including,
		without limitation, damages for loss of business profits, business interruption,
		loss of business information, or other pecuniary loss) arising out of the
		use of or inability to use this sample script or documentation, even if
		Microsoft has been advised of the possibil.
	
	.NOTES
		===========================================================================
		Created on:   	10/09/2017 1:38 PM
		Original by:  	Microsoft Corporation
		Created by:   	Eden Nelson
		Organization: 	Cascade Technology Alliance
		Filename:     	PKISync.ps1
		Version:      	1.5
		===========================================================================
	
	.LINK
		https://technet.microsoft.com/en-us/library/ff955845.aspx
	
	.LINK
		https://technet.microsoft.com/en-us/library/ff961506.aspx
#>
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true,
			   ValueFromPipelineByPropertyName = $true)]
	[Alias('SourceForest')]
	[System.String]$SourceForestName,
	[Parameter(Mandatory = $true,
			   ValueFromPipelineByPropertyName = $true)]
	[Alias('TargetForest')]
	[System.String]$TargetForestName,
	[Parameter(Mandatory = $true,
			   ValueFromPipelineByPropertyName = $true)]
	[System.String]$SourceDC,
	[Parameter(Mandatory = $true,
			   ValueFromPipelineByPropertyName = $true)]
	[System.String]$TargetDC,
	[Parameter(Mandatory = $true,
			   ValueFromPipelineByPropertyName = $true)]
	[Alias('Type')]
	[System.String]$ObjectType,
	[Parameter(Mandatory = $false,
			   ValueFromPipelineByPropertyName = $true)]
	[Alias('CN')]
	[System.String]$ObjectCN,
	[Parameter(Mandatory = $false,
			   ValueFromPipelineByPropertyName = $true)]
	[Alias('DryRun')]
	[System.Management.Automation.SwitchParameter]$WhatIf,
	[Parameter(Mandatory = $false,
			   ValueFromPipelineByPropertyName = $true)]
	[System.Management.Automation.SwitchParameter]$DeleteOnly,
	[Parameter(Mandatory = $false,
			   ValueFromPipelineByPropertyName = $true)]
	[Alias('OverWrite', 'F')]
	[System.Management.Automation.SwitchParameter]$Force
)

Begin {
	Write-Verbose "Begin $($MyInvocation.MyCommand)"
	Write-Verbose "SourceForestName: $SourceForestName"
	Write-Verbose "TargetForestName: $TargetForestName"
	Write-Verbose "SourceDC: $SourceDC"
	Write-Verbose "TargetDC: $TargetDC"
	Write-Verbose "ObjectType: $ObjectType"
	Write-Verbose "ObjectCN: $ObjectCN"
	Write-Verbose "WhatIf: $WhatIf"
	Write-Verbose "DeleteOnly: $DeleteOnly"
	Write-Verbose "Force: $Force"
}
Process {
	#region FunctionCode
	function Get-PKIServicesContainer {
<#
	.SYNOPSIS
		Get parent container for all PKI objects in the AD
	
	.DESCRIPTION
		A detailed description of the Get-PKIServicesContainer function.
	
	.PARAMETER ForestContext
		A description of the ForestContext parameter.
	
	.PARAMETER DomainControllerName
		A description of the DomainControllerName parameter.
	
	.EXAMPLE
		PS C:\> Get-PKIServicesContainer
	
	.NOTES
		Additional information about the function.
#>
		
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			[System.DirectoryServices.ActiveDirectory.DirectoryContext]$ForestContext,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			[Alias('DCName')]
			[System.String]$DomainControllerName
		)
		
		Begin {
			Write-Verbose "`n"
			Write-Verbose "Begin $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
			Write-Verbose "ForestContext.Name: $($ForestContext.Name)"
			Write-Verbose "ForestContext.ContextType: $($ForestContext.ContextType)"
			Write-Verbose "DomainControllerName: $DomainControllerName"
		}
		Process {
			$ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
			Write-Verbose "ForestObject Name: $($ForestObject.Name)"
			Write-Verbose "ForestObject Sites: $($ForestObject.Sites)"
			Write-Verbose "ForestObject Domains: $($ForestObject.Domains)"
			Write-Verbose "ForestObject Global Catalogs: $($ForestObject.GlobalCatalogs)"
			Write-Verbose "ForestObject Application Partitions: $($ForestObject.ApplicationPartitions)"
			Write-Verbose "ForestObject Forest Mode Level: $($ForestObject.ForestModeLevel)"
			Write-Verbose "ForestObject Forest Mode: $($ForestObject.ForestMode)"
			Write-Verbose "ForestObject Root Domain: $($ForestObject.RootDomain)"
			Write-Verbose "ForestObject Schema: $($ForestObject.Schema)"
			Write-Verbose "ForestObject Schema Role Owner: $($ForestObject.SchemaRoleOwner)"
			Write-Verbose "ForestObject Naming Role Owner: $($ForestObject.NamingRoleOwner)"
			$DirectoryEntry = $ForestObject.RootDomain.GetDirectoryEntry()
			Write-Verbose "Directory Entry: $DirectoryEntry"
			
			if ($DomainControllerName -ne '') {
				$NewPath = [System.Text.RegularExpressions.Regex]::Replace($DirectoryEntry.psbase.Path, "LDAP://\S*/", "LDAP://" + $DomainControllerName + "/")
				Write-Verbose "New Path: $NewPath"
				$DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry $NewPath
				Write-Verbose "Directory Entry: $DirectoryEntry"
			}
			
			$PKIServicesContainer = $DirectoryEntry.psbase.get_Children().find("CN=Public Key Services,CN=Services,CN=Configuration")
			return $PKIServicesContainer
		}
		End {
			Write-Verbose "retrun PKI Services Container Distinguished Name: $($PKIServicesContainer.distinguishedName)"
			Write-Verbose "retrun PKI Services Container Path: $($PKIServicesContainer.Path)"
			Write-Verbose "`n"
			Write-Verbose "End $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
		}
	}
	function Get-SchemaSystemMayContain {
<#
	.SYNOPSIS
		Build a list of attributes to copy for some object type
	
	.DESCRIPTION
		A detailed description of the Get-SchemaSystemMayContain function.
	
	.PARAMETER SourceForestContext
		A description of the SourceForestContext parameter.
	
	.PARAMETER SchemaClassName
		A description of the SchemaClassName parameter.
	
	.EXAMPLE
		PS C:\> Get-SchemaSystemMayContain
	
	.NOTES
		Additional information about the function.
#>
		
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$SourceForestContext,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$SchemaClassName
		)
		
		Begin {
			Write-Verbose "`n"
			Write-Verbose "Begin $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
			Write-Verbose "SourceForestContext.Name: $($SourceForestContext.Name)"
			Write-Verbose "SourceForestContext.ContextType: $($SourceForestContext.ContextType)"
			Write-Verbose "SchemaClassName: $SchemaClassName"
			
			
		}
		Process {
			# first get all attributes that are part of systemMayContain list
			$SchemaDE = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]::FindByName($SourceForestContext, $SchemaClassName).GetDirectoryEntry()
			$SystemMayContain = $SchemaDE.systemMayContain
			# if schema was upgraded with adprep.exe, we need to check mayContain list as well
			if ($SchemaDE.mayContain -ne $null) {
				$MayContain = $SchemaDE.mayContain
				foreach ($attr in $MayContain) {
					$SystemMayContain.Add($attr)
				}
			}
			# 
			# special case some of the inherited attributes
			if ($SchemaClassName.Contains('certificationAuthority')) {
				$SystemMayContain = $SchemaDE.systemMustContain
			} else {
				if ($SystemMayContain.IndexOf("displayName" -eq -1)) {
					$SystemMayContain.Add("displayName")
				}
				if ($SystemMayContain.IndexOf("flags") -eq -1) {
					$SystemMayContain.Add("flags")
				}
				if ($SchemaClassName.ToLower().Contains("template") -and -1 -eq $SystemMayContain.IndexOf("revision")) {
					$SystemMayContain.Add("revision")
				}
			}
			return $SystemMayContain
		}
		End {
			Write-Verbose "return SystemMayContain $SystemMayContain"
			Write-Verbose "`n"
			Write-Verbose "End $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
		}
	}
	function Process-AllObjects {
<#
	.SYNOPSIS
		Copy or delete all objects of some type.
	
	.DESCRIPTION
		A detailed description of the Process-AllObjects function.
	
	.PARAMETER SourcePKIServicesDE
		A description of the SourcePKIServicesDE parameter.
	
	.PARAMETER TargetPKIServicesDE
		A description of the TargetPKIServicesDE parameter.
	
	.PARAMETER RelativeDN
		A description of the RelativeDN parameter.
	
	.PARAMETER ObjectCN
		A description of the ObjectCN parameter.
	
	.PARAMETER SourceForestContext
		A description of the SourceForestContext parameter.
	
	.EXAMPLE
		PS C:\> Process-AllObjects
	
	.NOTES
		Additional information about the function.
#>
		
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$SourcePKIServicesDE,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$TargetPKIServicesDE,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$RelativeDN,
			[Parameter(Mandatory = $false,
					   ValueFromPipelineByPropertyName = $true)]
			$ObjectCN,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$SourceForestContext
		)
		
		Begin {
			Write-Verbose "`n"
			Write-Verbose "Begin $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
			
		}
		Process {
			$SourceObjectsDE = $SourcePKIServicesDE.psbase.Children.find($RelativeDN)
			$ObjectCN = $null
			
			foreach ($ChildNode in $SourceObjectsDE.psbase.get_Children()) {
				# If some object failed, we will try to continue with the rest
				trap {
					# CN maybe null here, but its ok. Doing best effort. 
					write-warning ("Error while coping an object. CN=" + $ObjectCN)
					write-warning $_
					write-warning $_.InvocationInfo.PositionMessage
					continue
				}
				$ObjectCN = $ChildNode.psbase.Properties["cn"]
				Process-Object -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN $RelativeDN -ObjectCN $ObjectCN -SourceForestContext $SourceForestContext
				$ObjectCN = $null
			}
		}
		End {
			Write-Verbose "`n"
			Write-Verbose "End $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
		}
	}
	function Process-Object {
<#
	.SYNOPSIS
		Copy or delete an object.
	
	.DESCRIPTION
		A detailed description of the Process-Object function.
	
	.PARAMETER SourcePKIServicesDE
		A description of the SourcePKIServicesDE parameter.
	
	.PARAMETER TargetPKIServicesDE
		A description of the TargetPKIServicesDE parameter.
	
	.PARAMETER RelativeDN
		A description of the RelativeDN parameter.
	
	.PARAMETER ObjectCN
		A description of the ObjectCN parameter.
	
	.PARAMETER SourceForestContext
		A description of the SourceForestContext parameter.
	
	.EXAMPLE
		PS C:\> Process-Object
	
	.NOTES
		Additional information about the function.
#>
		
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$SourcePKIServicesDE,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$TargetPKIServicesDE,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$RelativeDN,
			[Parameter(Mandatory = $false,
					   ValueFromPipelineByPropertyName = $true)]
			$ObjectCN,
			[Parameter(Mandatory = $true,
					   ValueFromPipelineByPropertyName = $true)]
			$SourceForestContext
		)
		
		Begin {
			Write-Verbose "`n"
			Write-Verbose "Begin $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
			Write-Verbose "Source PKI Services Directory Entry: $SourcePKIServicesDE"
			Write-Verbose "Target PKI Services Directory Entry: $TargetPKIServicesDE"
			Write-Verbose "Relative DN: $RelativeDN"
			Write-Verbose "Object CN: $ObjectCN"
			Write-Verbose "What If: $script:WhatIf"
			Write-Verbose "Delete Only: $script:DeleteOnly"
			Write-Verbose "Force: $script:Force"
		}
		Process {
			$SourceObjectContainerDE = $SourcePKIServicesDE.psbase.get_Children().find($RelativeDN)
			Write-Verbose "Source Object Container Directory Entry: $SourceObjectContainerDE"
			$TargetObjectContainerDE = $TargetPKIServicesDE.psbase.get_Children().find($RelativeDN)
			Write-Verbose "TargetObjectContainerDE: $TargetObjectContainerDE"
			
			if ($ObjectCN -eq 'NTAuthCertificates') {
				$SourceObjectCertArray = $SourceObjectContainerDE.psbase.Properties['cACertificate']
				$TargetObjectCertArray = $TargetObjectContainerDE.psbase.Properties['cACertificate']
				$MissingCertArray = Compare-Object -ReferenceObject $SourceObjectCertArray -DifferenceObject $TargetObjectCertArray -PassThru
				if (($MissingCertArray -is [Object[]]) -and ($MissingCertArray.Count -gt 0)) {
					foreach ($Certificate in $MissingCertArray) {
						$TargetObjectContainerDE.psbase.Properties['cACertificate'].Add($Certificate)
					}
				} elseif ($MissingCertArray -is [Byte[]]) {
					[Byte[]]$MissingCertArray = Compare-Object -ReferenceObject $SourceObjectCertArray -DifferenceObject $TargetObjectCertArray -PassThru
					$TargetObjectContainerDE.psbase.Properties['cACertificate'].Add($MissingCertArray)
				}
				$TargetObjectContainerDE.psbase.CommitChanges()
			} else {
				# when copying make sure there is an object to copy
				if ($script:DeleteOnly -eq $false) {
					$DSSearcher = [System.DirectoryServices.DirectorySearcher]$SourceObjectContainerDE
					$DSSearcher.Filter = "(cn=" + $ObjectCN + ")"
					$SearchResult = $DSSearcher.FindAll()
					if ($SearchResult.Count -eq 0) {
						Write-Verbose ("Source object does not exist: CN=" + $ObjectCN + "," + $RelativeDN)
						return
					}
					$SourceObjectDE = $SourceObjectContainerDE.psbase.get_Children().find("CN=" + $ObjectCN)
				}
				
				# Check to see if the target object exists, if it does delete if -Force is enabled.
				# Also delete is this a deletion only operation.
				$DSSearcher = [System.DirectoryServices.DirectorySearcher]$TargetObjectContainerDE
				$DSSearcher.Filter = "(cn=" + $ObjectCN + ")"
				$SearchResult = $DSSearcher.FindAll()
				if ($SearchResult.Count -gt 0) {
					$TargetObjectDE = $TargetObjectContainerDE.psbase.get_Children().find("CN=" + $ObjectCN)
					
					if ($script:DeleteOnly) {
						Write-Verbose ("Deleting: " + $TargetObjectDE.DistinguishedName)
						if ($script:WhatIf -eq $false) {
							$TargetObjectContainerDE.psbase.get_Children().Remove($TargetObjectDE)
						}
						return
					} elseif ($script:Force) {
						Write-Verbose ("OverWriting: " + $TargetObjectDE.DistinguishedName)
						if ($script:WhatIf -eq $false) {
							$TargetObjectContainerDE.psbase.get_Children().Remove($TargetObjectDE)
						}
					} else {
						if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
							write-warning ("Object exists, use -Force to overwrite existing. Object: " + $TargetObjectDE.DistinguishedName)
						}
						return
					}
				} else {
					if ($script:WhatIf) {
						write-warning ("Can't delete object. Object doesn't exist. Object: " + $ObjectCN + ", " + $TargetObjectContainerDE.DistinguishedName)
						return
					} else {
						Write-Verbose ("Copying Object: " + $SourceObjectDE.DistinguishedName)
					}
				}
				
				# Only update the object if this is not a dry run
				if (($script:WhatIf -eq $false) -and ($script:DeleteOnly -eq $false)) {
					#Create new AD object   
					$NewDE = $TargetObjectContainerDE.psbase.get_Children().Add("CN=" + $ObjectCN, $SourceObjectDE.psbase.SchemaClassName)
					
					#Obtain systemMayContain for the object type from the AD schema
					$ObjectMayContain = Get-SchemaSystemMayContain -SourceForestContext $SourceForestContext -SchemaClassName $SourceObjectDE.psbase.SchemaClassName
					
					#Copy attributes defined in the systemMayContain for the object type.
					foreach ($Attribute in $ObjectMayContain) {
						if ($null -eq $SourceObjectDE.psbase.Properties[$Attribute].Value) {
							continue
						} elseif ($SourceObjectDE.psbase.Properties[$Attribute].Value -is [Byte[]]) {
							[Byte[]]$AttributeValue = $SourceObjectDE.psbase.Properties[$Attribute].Value
						} else {
							$AttributeValue = $SourceObjectDE.psbase.Properties[$Attribute].Value
						}
						$NewDE.psbase.Properties[$Attribute].Value = $AttributeValue
						Remove-Variable -Name AttributeValue
					}
					$NewDE.psbase.CommitChanges()
					#Copy secuirty descriptor to new object. Only DACL is copied. 
					$BinarySecurityDescriptor = $SourceObjectDE.psbase.ObjectSecurity.GetSecurityDescriptorBinaryForm()
					$NewDE.psbase.ObjectSecurity.SetSecurityDescriptorBinaryForm($BinarySecurityDescriptor, [System.Security.AccessControl.AccessControlSections]::Access)
					$NewDE.psbase.CommitChanges()
				}
			}
		}
		End {
			Write-Verbose "`n"
			Write-Verbose "End $($MyInvocation.MyCommand)"
			Write-Verbose "`n"
		}
	}
	#endregion FunctionCode
	#region MainScriptCode
	
	# All errors are fatal by default unless there is another 'trap' with 'continue'
	trap {
		write-error "The script has encoutnered a fatal error. Terminating script."
		break
	}
	
	# Get a hold of the containers in each forest
	Write-Verbose "TargetForest: $($TargetForestName.ToUpper())"
	$TargetForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext Forest, $TargetForestName
	Write-Verbose "TargetForestContext.Name: $($TargetForestContext.Name)"
	Write-Verbose "TargetForestContext.ContextType: $($TargetForestContext.ContextType)"
	$TargetPKIServicesDE = Get-PKIServicesContainer -ForestContext $TargetForestContext -DomainControllerName $TargetDC
	Write-Verbose "TargetPKIServicesDE.DistinguishedName: $($TargetPKIServicesDE.distinguishedName)"
	Write-Verbose "TargetPKIServicesDE.Path: $($TargetPKIServicesDE.Path)"
	
	# Only need source forest when copying
	if ($script:DeleteOnly -eq $false) {
		Write-Verbose ("SourceForestName: " + $SourceForestName.ToUpper())
		$SourceForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext Forest, $SourceForestName
		Write-Verbose "SourceForestContext.Name: $($SourceForestContext.Name)"
		Write-Verbose "SourceForestContext.ContextType: $($SourceForestContext.ContextType)"
		$SourcePKIServicesDE = Get-PKIServicesContainer -ForestContext $SourceForestContext -DomainControllerName $SourceDC
		Write-Verbose "SourcePKIServicesDE.DistinguishedName: $($SourcePKIServicesDE.distinguishedName)"
		Write-Verbose "SourcePKIServicesDE.Path: $($SourcePKIServicesDE.Path)"
	} else {
		$SourcePKIServicesDE = $TargetPKIServicesDE
		Write-Verbose "TargetPKIServicesDE.DistinguishedName: $($TargetPKIServicesDE.distinguishedName)"
		Write-Verbose "TargetPKIServicesDE.Path: $($TargetPKIServicesDE.Path)"
		
	}
	
	if ($ObjectType -ne '') { Write-Verbose "Object Category to process: $($ObjectType.ToUpper)" }
	
	# Process the command
	switch ($ObjectType.ToUpper()) {
		ALL
		{
			Write-Verbose -Message ("All Container")
			Write-Verbose -Message ("Certificate Authorities Container")
			Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=Certification Authorities'
			Write-Verbose -Message ("AIA Container")
			Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=AIA'
			Write-Verbose -Message ("Enrollment Serverices Container")
			Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN "CN=Enrollment Services"
			Write-Verbose -Message ("Certificate Templates Container")
			Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN "CN=Certificate Templates"
			Write-Verbose -Message ("Object ID Container")
			Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN "CN=OID"
			Write-Verbose -Message ("NTAuthCertificates Object")
			Process-Object -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=NTAuthCertificates' -ObjectCN NTAuthCertificates
		}
		ES
		{
			Write-Verbose -Message ("Enrollment Serverices Container")
			if ($ObjectCN -eq '') {
				Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN "CN=Enrollment Services"
			} else {
				Process-Object -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN "CN=Enrollment Services" -ObjectCN $ObjectCN
			}
		}
		OID
		{
			Write-Verbose -Message ("Object ID Container")
			if ($ObjectCN -eq '') {
				Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=OID'
			} else {
				Process-Object -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=OID' -ObjectCN $ObjectCN
			}
		}
		TEMPLATE
		{
			Write-Verbose -Message ("Certificate Templates Container")
			if ($ObjectCN -eq '') {
				Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=Certificate Templates'
			} else {
				Process-Object -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=Certificate Templates' -ObjectCN $ObjectCN
			}
		}
		CA
		{
			Write-Verbose -Message ("Certificate Authorities Container")
			if ($ObjectCN -eq '') {
				Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=Certification Authorities'
			} else {
				Process-Object -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=Certification Authorities' -ObjectCN $ObjectCN
			}
		}
		AIA
		{
			Write-Verbose -Message ("AIA Container")
			if ($ObjectCN -eq '') {
				Process-AllObjects -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=AIA'
			} else {
				Process-Object -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=AIA' -ObjectCN $ObjectCN
			}
		}
		NTAuth
		{
			Write-Verbose -Message ("NTAuthCertificates Object")
			Process-Object -SourceForestContext $SourceForestContext -SourcePKIServicesDE $SourcePKIServicesDE -TargetPKIServicesDE $TargetPKIServicesDE -RelativeDN 'CN=NTAuthCertificates' -ObjectCN NTAuthCertificates
		}
		default {
			write-warning ("Unknown object type: " + $ObjectType.ToLower())
			exit 87
		}
	}
	#endregion MainScriptCode
}
End { Write-Verbose "End $($MyInvocation.MyCommand)" }


# SIG # Begin signature block
# MIIQrgYJKoZIhvcNAQcCoIIQnzCCEJsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUN3I1dp11xJOmba5DtJdQo3Kl
# 6zSgggvFMIIDBjCCAe6gAwIBAgIQL5tLI0kB95tC0nRJzV7uKjANBgkqhkiG9w0B
# AQUFADAWMRQwEgYDVQQDDAtFZGVuIE5lbHNvbjAeFw0xNzA5MDgyMjI2NTFaFw0z
# NzA5MDgyMjM2NTFaMBYxFDASBgNVBAMMC0VkZW4gTmVsc29uMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5TChlY9pEZX/3fWVpiaKiwxvoapE4Wkvkxf
# Loj8LJxZCBJI4yWjKCyFfuZpNTkL2cR2o7S4Ikp1VxJAlHa0moH27A4Cd6WDxAPF
# ksfyENY+aFpfZSMCLql8kQg9bzMDxyW+5Lr4r2tOX3Mx03HeCLo9l3ax3GnFJ7Ur
# FEMRFviaZMxDlFT4cUmHQfL2WaFviP6bfRT3+jLs3KJWyuEVgrsgg4fZAEiTo/nu
# C2RdfT00gsqVTzrg1FyPdnE43MTcojHEiRJ14GRRFEU/CX8PntGKvUf+qAlp2GYD
# Bg/YmBEJLtFxvCo1Vja7oDubKncPPWUKmA85WXtDUsHE5YohkQIDAQABo1AwTjAO
# BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0G
# A1UdDgQWBBQQmjQ9M/4E7vwm7Jt1MUCG4f43uzANBgkqhkiG9w0BAQUFAAOCAQEA
# CHkEawdt83WaQ8pqAxOdhjdr/TeVLt3IJFM/ZO/PJ9y37kJ4QXQ0hl4tmYVF9pF8
# mrPxdLRNLhGMVm+jQ8APKmAUpewFi/oRANppG2uw496eikcipB7IjwGNAUru4Wcq
# WfKAtfWNrl2HFEMpnyeI4NrGZKXxC+CTOV102SqVq2O2xiKrvFSR+NI9xCYNXXBt
# ErEw7cqGMaHPdtc0TM7coGHvbS8muoJdM8tULayji7vkPKR7D/HXEnrLe0DS/MRG
# HRPdqgGuyz8M8IVUlNevC6GEYruuBQ/D/NGThwETeVNyakIw6rMeRSXmPV3RQ17S
# k1OeaULzyA/Vo5+g9jC6NzCCBBQwggL8oAMCAQICCwQAAAAAAS9O4VLXMA0GCSqG
# SIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52
# LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxTaWduIFJvb3Qg
# Q0EwHhcNMTEwNDEzMTAwMDAwWhcNMjgwMTI4MTIwMDAwWjBSMQswCQYDVQQGEwJC
# RTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UEAxMfR2xvYmFsU2ln
# biBUaW1lc3RhbXBpbmcgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAJTvZfi1V5+gUw00BusJH7dHGGrL8Fvk/yelNNH3iRq/nrHNEkFuZtSB
# oIWLZFpGL5mgjXex4rxc3SLXamfQu+jKdN6LTw2wUuWQW+tHDvHnn5wLkGU+F5Yw
# RXJtOaEXNsq5oIwbTwgZ9oExrWEWpGLmtECew/z7lfb7tS6VgZjg78Xr2AJZeHf3
# quNSa1CRKcX8982TZdJgYSLyBvsy3RZR+g79ijDwFwmnu/MErquQ52zfeqn078Ri
# J19vmW04dKoRi9rfxxRM6YWy7MJ9SiaP51a6puDPklOAdPQD7GiyYLyEIACDG6Hu
# tHQFwSmOYtBHsfrwU8wY+S47+XB+tCUCAwEAAaOB5TCB4jAOBgNVHQ8BAf8EBAMC
# AQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQURtg+/9zjvv+D5vSFm7Dd
# atYUqcEwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMDMGA1UdHwQsMCowKKAmoCSG
# Imh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvcm9vdC5jcmwwHwYDVR0jBBgwFoAU
# YHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEFBQADggEBAE5eVpAeRrTZ
# STHzuxc5KBvCFt39QdwJBQSbb7KimtaZLkCZAFW16j+lIHbThjTUF8xVOseC7u+o
# urzYBp8VUN/NFntSOgLXGRr9r/B4XOBLxRjfOiQe2qy4qVgEAgcw27ASXv4xvvAE
# SPTwcPg6XlaDzz37Dbz0xe2XnbnU26UnhOM4m4unNYZEIKQ7baRqC6GD/Sjr2u8o
# 9syIXfsKOwCr4CHr4i81bA+ONEWX66L3mTM1fsuairtFTec/n8LZivplsm7HfmX/
# 6JLhLDGi97AnNkiPJm877k12H3nD5X+WNbwtDswBsI5//1GAgKeS1LNERmSMh08W
# YwcxS2Ow3/MwggSfMIIDh6ADAgECAhIRIdaZp2SXPvH4Qn7pGcxTQRQwDQYJKoZI
# hvcNAQEFBQAwUjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYt
# c2ExKDAmBgNVBAMTH0dsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gRzIwHhcN
# MTYwNTI0MDAwMDAwWhcNMjcwNjI0MDAwMDAwWjBgMQswCQYDVQQGEwJTRzEfMB0G
# A1UEChMWR01PIEdsb2JhbFNpZ24gUHRlIEx0ZDEwMC4GA1UEAxMnR2xvYmFsU2ln
# biBUU0EgZm9yIE1TIEF1dGhlbnRpY29kZSAtIEcyMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAsBeuotO2BDBWHlgPse1VpNZUy9j2czrsXV6rJf02pfqE
# w2FAxUa1WVI7QqIuXxNiEKlb5nPWkiWxfSPjBrOHOg5D8NcAiVOiETFSKG5dQHI8
# 8gl3p0mSl9RskKB2p/243LOd8gdgLE9YmABr0xVU4Prd/4AsXximmP/Uq+yhRVmy
# Lm9iXeDZGayLV5yoJivZF6UQ0kcIGnAsM4t/aIAqtaFda92NAgIpA6p8N7u7KU49
# U5OzpvqP0liTFUy5LauAo6Ml+6/3CGSwekQPXBDXX2E3qk5r09JTJZ2Cc/os+XKw
# qRk5KlD6qdA8OsroW+/1X1H0+QrZlzXeaoXmIwRCrwIDAQABo4IBXzCCAVswDgYD
# VR0PAQH/BAQDAgeAMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUH
# AgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAkGA1Ud
# EwQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4Yx
# aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9ncy9nc3RpbWVzdGFtcGluZ2cyLmNy
# bDBUBggrBgEFBQcBAQRIMEYwRAYIKwYBBQUHMAKGOGh0dHA6Ly9zZWN1cmUuZ2xv
# YmFsc2lnbi5jb20vY2FjZXJ0L2dzdGltZXN0YW1waW5nZzIuY3J0MB0GA1UdDgQW
# BBTUooRKOFoYf7pPMFC9ndV6h9YJ9zAfBgNVHSMEGDAWgBRG2D7/3OO+/4Pm9IWb
# sN1q1hSpwTANBgkqhkiG9w0BAQUFAAOCAQEAj6kakW0EpjcgDoOW3iPTa24fbt1k
# PWghIrX4RzZpjuGlRcckoiK3KQnMVFquxrzNY46zPVBI5bTMrs2SjZ4oixNKEaq9
# o+/Tsjb8tKFyv22XY3mMRLxwL37zvN2CU6sa9uv6HJe8tjecpBwwvKu8LUc235Ig
# A+hxxlj2dQWaNPALWVqCRDSqgOQvhPZHXZbJtsrKnbemuuRQ09Q3uLogDtDTkipb
# xFm7oW3bPM5EncE4Kq3jjb3NCXcaEL5nCgI2ZIi5sxsm7ueeYMRGqLxhM2zPTrmc
# uWrwnzf+tT1PmtNN/94gjk6Xpv2fCbxNyhh2ybBNhVDygNIdBvVYBAexGDGCBFMw
# ggRPAgEBMCowFjEUMBIGA1UEAwwLRWRlbiBOZWxzb24CEC+bSyNJAfebQtJ0Sc1e
# 7iowCQYFKw4DAhoFAKBaMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwIwYJKoZIhvcNAQkEMRYEFPk8BG4eI5BOqPlL
# nnbCB0OV5AsUMA0GCSqGSIb3DQEBAQUABIIBALIMS8kZpNGKMcuQDDk2X5B0vNh6
# kZVk3z7D7Dk+MFeXp/iHhXM+rOZ2j9A4321fLMW2qNePrUhRPvT6J9Qzoy5XUSEE
# rTxvV94RaPsSrmgLlvuMCi3Jjajj4c2Q3Dvv4TBhld7z8vo9El1xeyhsAITJ/6p3
# N4kU4pju0Ct6L4meS5rsQNBwhJqgmi0wb1jxTLk6iz7XQ6uncXHMv1ZZL79MCQaI
# r9zjrwsDEOCHwuKnBMpeRodrhck9cOU2TyBuGo+u/QnZQf7cFBE6HqubxJZEuVj8
# n73OVPsvQ5Pl8yzCkxA1f1Flye/w9rF9xY8YICGgKsMKs9zrMt0bTNdLBhqhggKi
# MIICngYJKoZIhvcNAQkGMYICjzCCAosCAQEwaDBSMQswCQYDVQQGEwJCRTEZMBcG
# A1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBUaW1l
# c3RhbXBpbmcgQ0EgLSBHMgISESHWmadklz7x+EJ+6RnMU0EUMAkGBSsOAwIaBQCg
# gf0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcx
# MDE2MTgxODQ0WjAjBgkqhkiG9w0BCQQxFgQUqXANNSux8MiXw/2rdjNb7UR6xaYw
# gZ0GCyqGSIb3DQEJEAIMMYGNMIGKMIGHMIGEBBRjuC+rYfWDkJaVBQsAJJxQKTPs
# eTBsMFakVDBSMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1z
# YTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMgISESHW
# madklz7x+EJ+6RnMU0EUMA0GCSqGSIb3DQEBAQUABIIBAB/UoBB9TrfWCVser+rz
# EhFuDRfzXFKepjiTW3NIyL4xA0WRlU3C3YKh/eIft9DFxMS3O/DGOcHXsJ3Gd82W
# b4T7bTNdiJ7CIatu29z9zGiX+LYFnwYTbeVsVGCs3AE0/862vuo6C/RK6s45xfh/
# +MjL6UKAeHnB6EdZUluUyuwF7CnF5QavSqrEPyG7KUyqR18VRdjB4CJtEwNyTE3w
# surDR3GgzTXiD6tLouxQVg7rBPQApLtiUu1tz4HZmXdthXtnQ6cJlzk5o2su8d9Q
# bUK1c0K/RY+DHGaox+9PdTVQP7RGXLSR2FqsGxiaqJsXwhPoW9o15Na4v8qh25kb
# Hzk=
# SIG # End signature block
