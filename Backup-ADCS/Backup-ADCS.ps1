<#
	.SYNOPSIS
		This script dumps certificate template/CA information using ldifde.exe
	
	.DESCRIPTION
		A description of the file.
	
	.NOTES
		===========================================================================
		Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2017 v5.4.144
		Created on:   	10/9/2017 1:42 PM
		Created by:   	Eden Nelson
		Organization: 	Cascade Technology Alliance
		Filename:
		===========================================================================
#>


#
# This script dumps certificate template/CA information using ldifde.exe
#

#
# Command line arguments
#
$ForestName = ""
$DCName = ""
$ObjectType = ""
$ObjectName = ""
$OutFile = ""

function ParseCommandLine() {
	if (10 -gt $Script:args.Count) {
		write-warning "Not enough arguments"
		Usage
		exit 87
	}
	
	for ($i = 0; $i -lt $Script:args.Count; $i++) {
		switch ($Script:args[$i].ToLower()) {
			-forest
			{
				$i++
				$Script:ForestName = $Script:args[$i]
			}
			-dc
			{
				$i++
				$Script:DCName = $Script:args[$i]
			}
			-type
			{
				$i++
				$Script:ObjectType = $Script:args[$i]
			}
			-cn
			{
				$i++
				$Script:ObjectName = $Script:args[$i]
			}
			-file
			{
				$i++
				$Script:OutFile = $Script:args[$i]
			}
			default {
				write-warning ("Unknown parameter: " + $Script:args[$i])
				Usage
				exit 87
			}
		}
	}
}

function Usage() {
	write-host ""
	write-host "Script to display attribute values of certificate template or CA object in AD"
	write-host ""
	write-host "dumpadobj.ps1 -forest <DNS name> -dc <DC name> -type <template|CA> -cn <Name> -file <output file>"
	write-host ""
	write-host "-forest           -- DNS of the forest to process object from"
	write-host "-dc               -- DNS or NetBios name of the DC to target"
	write-host "-type             -- Template or CA"
	write-host "-cn               -- Template or CA name"
	write-host "-file             -- Output file"
	write-host ""
}

#########################################################
# Main script code
#########################################################

#
# All errors are fatal by default unless there is anoter 'trap' with 'continue'
#
trap {
	write-error "The script has encountered a fatal error. Terminating script."
	break
}

ParseCommandLine

write-host ""
write-host "Effective settings:"
write-host ""
write-host "  Forest: $ForestName"
write-host "      DC: $DCName"
write-host "    Type: $ObjectType"
write-host "    Name: $ObjectName"
write-host "    File: $OutFile"
write-host ""

#
# Set type specific variables
#
switch ($ObjectType.ToLower()) {
	"template"
	{
		$ObjectContainerCN = ",CN=Certificate Templates"
		$ObjectSchema = "pKICertificateTemplate"
	}
	"ca"
	{
		$ObjectContainerCN = ",CN=Enrollment Services"
		$ObjectSchema = "pKIEnrollmentService"
	}
	default {
		write-warning ("Unknown object type: " + $ObjectType)
		Usage
		exit 87
	}
}

#
# Build full DN for the object
#
$ForestDN = "DC=" + $ForestName.Replace(".", ",DC=")
$ObjectFullDN = "CN=" + $ObjectName + $ObjectContainerCN + ",CN=Public Key Services,CN=Services,CN=Configuration," + $ForestDN

#
# Build list of attributes to display
#
$ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext Forest, $ForestName
$SchemaDE = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]::FindByName($ForestContext, $ObjectSchema).GetDirectoryEntry()
$AttrList = $SchemaDE.systemMayContain

if ($null -ne $SchemaDE.mayContain) {
	$MayContain = $SchemaDE.mayContain
	foreach ($attr in $MayContain) {
		[void]$AttrList.Add($attr)
	}
}

if (-1 -eq $AttrList.IndexOf("displayName")) {
	[void]$AttrList.Add("displayName")
}

if (-1 -eq $AttrList.IndexOf("flags")) {
	[void]$AttrList.Add("flags")
}

if ($ObjectType.ToLower().Equals("template") -and -1 -eq $AttrList.IndexOf("revision")) {
	[void]$AttrList.Add("revision")
}

$SB = New-Object System.Text.StringBuilder
for ($i = 0; $i -lt $AttrList.Count; $i++) {
	[void]$SB.Append($AttrList[$i])
	if ($i -lt ($AttrList.Count - 1)) {
		[void]$SB.Append(",")
	}
}
$AttrListString = $SB.ToString()

#
# Build command line and execute
#
$CommandLine = "-d """ + $ObjectFullDN + """ -p Base -l """ + $AttrListString + """ -f """ + $OutFile + """ -s " + $DCName
Invoke-Expression "ldifde.exe $CommandLine" > ldifde.out.txt
Get-Content "$OutFile"


# SIG # Begin signature block
# MIIQrgYJKoZIhvcNAQcCoIIQnzCCEJsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0OjTkYCG+fbMt0aXRA60teAz
# qdqgggvFMIIDBjCCAe6gAwIBAgIQL5tLI0kB95tC0nRJzV7uKjANBgkqhkiG9w0B
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
# hvcNAQkDMQwGCisGAQQBgjcCAQQwIwYJKoZIhvcNAQkEMRYEFLACipKWufjNLO9P
# N5Be4s1FVA1YMA0GCSqGSIb3DQEBAQUABIIBAAoAKG/L74yYFtDTtX7cCpIOo3JL
# VN1GXIa7yigNdnb5/jrSA4D93fHq+onfUxO4zW/Gcz2fd+LQBFVJDXtpj66LiQfX
# oJUJYmR7+hxGYzo4pXgYTgWF4X4e3ZykqLXJ1HkNJhI0to2mVqtMZQFucIjCoeXq
# /xhWH4bGYUOO5ZHqaYma0IlcZHjsTWpew6caf/OKtOwXnsa/SeZu0jMFkhKQnN0u
# 7hXmVgCmZNrtza1ZeSztU2/9x5hwPoI8lMM8oIm3ZwNz3Xo9wPkdN1eeWGsCZStG
# rf+dHQIlhmndcE12QRPeAixTni4QvSyfXqoQq3kycVOFVFoHdmYjaPAWtLehggKi
# MIICngYJKoZIhvcNAQkGMYICjzCCAosCAQEwaDBSMQswCQYDVQQGEwJCRTEZMBcG
# A1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBUaW1l
# c3RhbXBpbmcgQ0EgLSBHMgISESHWmadklz7x+EJ+6RnMU0EUMAkGBSsOAwIaBQCg
# gf0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcx
# MDA5MjA1OTE1WjAjBgkqhkiG9w0BCQQxFgQUaxK0YkspyIrneJplfYt9cKu2Pukw
# gZ0GCyqGSIb3DQEJEAIMMYGNMIGKMIGHMIGEBBRjuC+rYfWDkJaVBQsAJJxQKTPs
# eTBsMFakVDBSMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1z
# YTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMgISESHW
# madklz7x+EJ+6RnMU0EUMA0GCSqGSIb3DQEBAQUABIIBAJ1mcJYEAZsPD+oVpfQy
# ubZ3gN4HEE9WvRbfMvtXdKm8F4jVx00W6h9raHpshsLuqar3TFkFWA89ZGyLEgfJ
# Z4wtzHU2yf0ekZwBgpehDoDIN/gBYClWYnDJPLvs5YioFK8T8TEdBbxUnSt65rRS
# wqEqK1+Tnl4ELHara+iwINmXWTf6WGawGOQr6HzNtXTs+NvHdnDCzRNy0lgFYvjW
# szd3FQ0DgqdkXV6uKlOWEcJY8NrdbU0IZG5HlK+bCmAFBNr44ILGgTEbNyk+HI07
# Y0Xv2TjYcLKqkB3rMsIbSnKUycIEZCMCxD229R43fPhlGuoOce4KM2O95MeR4hC7
# A1M=
# SIG # End signature block
