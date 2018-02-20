<#
	.SYNOPSIS
		Copy CRL files from Active Directory Certificate Services Servers/Systems.
	
	.DESCRIPTION
		Check if Certificate Services Servers are online and share is accessible, Copy any missing or changed CRL files to from online CAs to local system. 
	
	.NOTES
		===========================================================================
		Created on:   	9/29/2017 8:42 AM
		Created by:   	Eden Nelson
		Organization: 	Cascade Technology Alliance
		Filename:     	Get-CRLFiles.ps1
		Version:      	1.0
		===========================================================================
#>
[CmdletBinding()]
param ()
Import-Module Storage
Import-Module NetTCPIP

$LocalCertEnrollPath= 'C:\Windows\System32\certsrv\CertEnroll'

$CAs = @(
	'CTA-CA-01.intra.cascadetech.org',
	'CTA-CA-02.intra.cascadetech.org'
)

foreach ($CA in $CAs) {
	Write-Verbose "Checking $CA..."
	if ((Test-NetConnection -InformationLevel Quiet -ComputerName $CA) -and (Test-Path -PathType Leaf -Path ('\\', $CA, '\CertEnroll\CTA*CA*.crl' -join ''))) {
		Write-Verbose "$CA is up!"
		$CRLFiles = (Get-ChildItem -Recurse -File -Include *.crl -Path ('\\', $CA, '\', 'CertEnroll' -join ''))
		$CRLFiles += (Get-ChildItem -Recurse -File -Include *.crt -Path ('\\', $CA, '\', 'CertEnroll' -join ''))
		foreach ($CRLFile in $CRLFiles) {
			Write-Verbose "Checking CRL file $CRLFile..."
			if (((Get-FileHash -Path $CRLFile -ErrorAction SilentlyContinue).Hash) -ne (Get-FileHash -Path ($LocalCertEnrollPath, '\', $CRLFile.Name -join '') -ErrorAction SilentlyContinue).Hash) {
				Write-Verbose "$CRLFile is missing or out of date. Attempting to copy it!"
				try {
					Copy-Item -Path $CRLFile -Destination $LocalCertEnrollPath -Force -ErrorAction Stop
				} catch {
					Write-Error ("Error: {0}" -f $_.Exception.Message)
				} # End of Try Catch
			} # End of needs to be copied if
		} # End of $CRLFile foreach
	} # End of test network and path if 
} # End of CA foreach


# SIG # Begin signature block
# MIIUVQYJKoZIhvcNAQcCoIIURjCCFEICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8UHbe4c7G0W6g8+RnTvhaCvz
# xh2ggg8hMIIEFDCCAvygAwIBAgILBAAAAAABL07hUtcwDQYJKoZIhvcNAQEFBQAw
# VzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNV
# BAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0
# MTMxMDAwMDBaFw0yODAxMjgxMjAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBDQSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO9l
# +LVXn6BTDTQG6wkft0cYasvwW+T/J6U00feJGr+esc0SQW5m1IGghYtkWkYvmaCN
# d7HivFzdItdqZ9C76Mp03otPDbBS5ZBb60cO8eefnAuQZT4XljBFcm05oRc2yrmg
# jBtPCBn2gTGtYRakYua0QJ7D/PuV9vu1LpWBmODvxevYAll4d/eq41JrUJEpxfz3
# zZNl0mBhIvIG+zLdFlH6Dv2KMPAXCae78wSuq5DnbN96qfTvxGInX2+ZbTh0qhGL
# 2t/HFEzphbLswn1KJo/nVrqm4M+SU4B09APsaLJgvIQgAIMboe60dAXBKY5i0Eex
# +vBTzBj5Ljv5cH60JQIDAQABo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBRG2D7/3OO+/4Pm9IWbsN1q1hSpwTBHBgNV
# HSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLm5ldC9yb290LmNybDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQ
# L30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEATl5WkB5GtNlJMfO7FzkoG8IW
# 3f1B3AkFBJtvsqKa1pkuQJkAVbXqP6UgdtOGNNQXzFU6x4Lu76i6vNgGnxVQ380W
# e1I6AtcZGv2v8Hhc4EvFGN86JB7arLipWAQCBzDbsBJe/jG+8ARI9PBw+DpeVoPP
# PfsNvPTF7ZedudTbpSeE4zibi6c1hkQgpDttpGoLoYP9KOva7yj2zIhd+wo7AKvg
# IeviLzVsD440RZfroveZMzV+y5qKu0VN5z+fwtmK+mWybsd+Zf/okuEsMaL3sCc2
# SI8mbzvuTXYfecPlf5Y1vC0OzAGwjn//UYCAp5LUs0RGZIyHTxZjBzFLY7Df8zCC
# BJ8wggOHoAMCAQICEhEh1pmnZJc+8fhCfukZzFNBFDANBgkqhkiG9w0BAQUFADBS
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
# AxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMjAeFw0xNjA1MjQwMDAw
# MDBaFw0yNzA2MjQwMDAwMDBaMGAxCzAJBgNVBAYTAlNHMR8wHQYDVQQKExZHTU8g
# R2xvYmFsU2lnbiBQdGUgTHRkMTAwLgYDVQQDEydHbG9iYWxTaWduIFRTQSBmb3Ig
# TVMgQXV0aGVudGljb2RlIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCwF66i07YEMFYeWA+x7VWk1lTL2PZzOuxdXqsl/Tal+oTDYUDFRrVZUjtC
# oi5fE2IQqVvmc9aSJbF9I+MGs4c6DkPw1wCJU6IRMVIobl1AcjzyCXenSZKX1GyQ
# oHan/bjcs53yB2AsT1iYAGvTFVTg+t3/gCxfGKaY/9Sr7KFFWbIub2Jd4NkZrItX
# nKgmK9kXpRDSRwgacCwzi39ogCq1oV1r3Y0CAikDqnw3u7spTj1Tk7Om+o/SWJMV
# TLktq4CjoyX7r/cIZLB6RA9cENdfYTeqTmvT0lMlnYJz+iz5crCpGTkqUPqp0Dw6
# yuhb7/VfUfT5CtmXNd5qheYjBEKvAgMBAAGjggFfMIIBWzAOBgNVHQ8BAf8EBAMC
# B4AwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6
# Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCQYDVR0TBAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL2dzL2dzdGltZXN0YW1waW5nZzIuY3JsMFQGCCsGAQUF
# BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNv
# bS9jYWNlcnQvZ3N0aW1lc3RhbXBpbmdnMi5jcnQwHQYDVR0OBBYEFNSihEo4Whh/
# uk8wUL2d1XqH1gn3MB8GA1UdIwQYMBaAFEbYPv/c477/g+b0hZuw3WrWFKnBMA0G
# CSqGSIb3DQEBBQUAA4IBAQCPqRqRbQSmNyAOg5beI9Nrbh9u3WQ9aCEitfhHNmmO
# 4aVFxySiIrcpCcxUWq7GvM1jjrM9UEjltMyuzZKNniiLE0oRqr2j79OyNvy0oXK/
# bZdjeYxEvHAvfvO83YJTqxr26/ocl7y2N5ykHDC8q7wtRzbfkiAD6HHGWPZ1BZo0
# 8AtZWoJENKqA5C+E9kddlsm2ysqdt6a65FDT1De4uiAO0NOSKlvEWbuhbds8zkSd
# wTgqreONvc0JdxoQvmcKAjZkiLmzGybu555gxEaovGEzbM9OuZy5avCfN/61PU+a
# 003/3iCOTpem/Z8JvE3KGHbJsE2FUPKA0h0G9VgEB7EYMIIGYjCCBUqgAwIBAgIT
# TQAACNTm6lyP5isnXwAAAAAI1DANBgkqhkiG9w0BAQsFADBeMRMwEQYKCZImiZPy
# LGQBGRYDb3JnMRswGQYKCZImiZPyLGQBGRYLY2FzY2FkZXRlY2gxFTATBgoJkiaJ
# k/IsZAEZFgVpbnRyYTETMBEGA1UEAxMKQ1RBLUlOVC1DQTAeFw0xODAxMjEyMjE5
# MjJaFw0xOTAxMjEyMjE5MjJaMIGaMRMwEQYKCZImiZPyLGQBGRYDb3JnMRswGQYK
# CZImiZPyLGQBGRYLY2FzY2FkZXRlY2gxFTATBgoJkiaJk/IsZAEZFgVpbnRyYTEN
# MAsGA1UECxMETUVTRDEUMBIGA1UEAxMLRWRlbiBOZWxzb24xKjAoBgkqhkiG9w0B
# CQEWG2VkZW4ubmVsc29uQGNhc2NhZGV0ZWNoLm9yZzCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBALkQFRlY5uvISFbe6fUGi3nj805Vwr/LahJVsURbNK+K
# d7Pu7Mh9x9CAhiq2tEjfVzaMh6tG4ByYM/DGchHwPqoco1kqak9Wh7KdVdoNROoz
# bcfe9PFrYLCMbbi1x/LBRaQwh26o4jt3AGHpNnqnDuN1DwlKQAI67TyiGa9zq4Rq
# xv+1txLaR/spVpcWRJwBwRx7I4UlucuVObBnGGia0ysfn3iMy1r3C17b8T84tSjS
# 2q3uNuWV3ZnpvpzYaMI0MK7cQt3/OpjZlHWxx8juzCeN3xVjQnAA0HX98IUI+MIh
# jun8sJq482VDN+7M7N7iISXV7xyJVEX8FjSKeAUgkWECAwEAAaOCAtowggLWMBcG
# CSsGAQQBgjcUAgQKHggAVQBzAGUAcjApBgNVHSUEIjAgBgorBgEEAYI3CgMEBggr
# BgEFBQcDBAYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgWgMEQGCSqGSIb3DQEJDwQ3
# MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMCBzAKBggq
# hkiG9w0DBzAdBgNVHQ4EFgQU20Y/FbHR+bpIsRwiJxRcmuFP99EwHwYDVR0jBBgw
# FoAUZr3YMozA57IZHo9WJOsKMQaoIXwwgdcGA1UdHwSBzzCBzDCByaCBxqCBw4aB
# wGxkYXA6Ly8vQ049Q1RBLUlOVC1DQSxDTj1DVEEtQ0EtMDIsQ049Q0RQLENOPVB1
# YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRp
# b24sREM9aW50cmEsREM9Y2FzY2FkZXRlY2gsREM9b3JnP2NlcnRpZmljYXRlUmV2
# b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
# dDCByQYIKwYBBQUHAQEEgbwwgbkwgbYGCCsGAQUFBzAChoGpbGRhcDovLy9DTj1D
# VEEtSU5ULUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
# ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWludHJhLERDPWNhc2NhZGV0ZWNo
# LERDPW9yZz9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
# dGlvbkF1dGhvcml0eTBUBgNVHREETTBLoCwGCisGAQQBgjcUAgOgHgwcbmVsc29u
# QGludHJhLmNhc2NhZGV0ZWNoLm9yZ4EbZWRlbi5uZWxzb25AY2FzY2FkZXRlY2gu
# b3JnMA0GCSqGSIb3DQEBCwUAA4IBAQCbdFYwSLZQnXftd/4H6im6gtKTGi6yZ7e0
# kju+u9GQ/NSnGuHXta49Ayyltyh1N0GC7Yke1Q9cf96wiyCyqoEgcas4La6nLdbL
# 3Hv/Y1CLm0coPEPmMnTaC24HFJe2kaHEo8euiRCLohjNjifnKx5gx3KwlRShCjvD
# 75zF3G0TH2gBAjUWZVaKpxrnqbWdS4+4g4tbjiGqnrBGe0aItCTPGspkPCrrzvoR
# jHiTBAwD5cfABdBSeajq9Qt387JxKDbkyo/xPVyUhuE/jh6nB9SED4nASvuxJwG4
# 0LO/KBnjQqlS91QR3akz0lzrmBxFsuuj7Qd/1GwBpA291YzWj2b+MYIEnjCCBJoC
# AQEwdTBeMRMwEQYKCZImiZPyLGQBGRYDb3JnMRswGQYKCZImiZPyLGQBGRYLY2Fz
# Y2FkZXRlY2gxFTATBgoJkiaJk/IsZAEZFgVpbnRyYTETMBEGA1UEAxMKQ1RBLUlO
# VC1DQQITTQAACNTm6lyP5isnXwAAAAAI1DAJBgUrDgMCGgUAoFowGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAjBgkq
# hkiG9w0BCQQxFgQUyzYOyqDnK5tdlYUXSDzfstwb4EQwDQYJKoZIhvcNAQEBBQAE
# ggEAswegkjbWkDWWXvv6cP9OmTquJHbzWSpj4wJlzFg5g/UVdHN59ko6ViHWR4b/
# 25FUbahLARP+EhVvfZwJxH4CHhAJaAu4N24lpb+IjD5C7gbtW1jwVlGCeN3tBxuy
# pcAEFyGpslf2jOLoc7mU0euoEg7GZngVr+YUdDCL2HuuHX6xosih1POXRZGmRO4v
# X6GtjQgedYQiMyMIKsqPoQnuBn6PQ00rdArgjiMH47BImwYe6fS3+ZXLkZlHF4XO
# v/5x7V3MoFvCN5xoQt/s7LudJVz9orqF4398X1ZmIU5ztdp1eMHRpsmcB59d8zbr
# 8bppjTe7eX5NtfjCUXYQEr7BOqGCAqIwggKeBgkqhkiG9w0BCQYxggKPMIICiwIB
# ATBoMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgw
# JgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIEcyAhIRIdaZp2SX
# PvH4Qn7pGcxTQRQwCQYFKw4DAhoFAKCB/TAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0xODAyMTUxOTAwMDJaMCMGCSqGSIb3DQEJBDEW
# BBTrXH09NtQ4DdP4QIEatqsStNBwhDCBnQYLKoZIhvcNAQkQAgwxgY0wgYowgYcw
# gYQEFGO4L6th9YOQlpUFCwAknFApM+x5MGwwVqRUMFIxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRp
# bWVzdGFtcGluZyBDQSAtIEcyAhIRIdaZp2SXPvH4Qn7pGcxTQRQwDQYJKoZIhvcN
# AQEBBQAEggEAgeEqBvDBnnwn8lKwpE3BFPccR4w1kmH1lq862LugEZS1Z7UHzTLs
# JZs1fYJYxsI7l1rih6vGGtMGzWbrvHB/OhfWfHPAFhgxXMQI903k/ECvHFC7z6Yn
# Wdmck1muKO1zRCMVVasA3OOj5TbG6XqP6himhyR5KnGeNeiuyY7cCE5hYPj0y1Ru
# 473ZYcx9Sp1nVEcsPeR0SGnxCWxXJm4+HdHPGxFlJ/vhfMBkfKfEqSqq+wq2pC3o
# 7zdkgFruWOKpksnA6U2DbXmbYeArE7wEaHXQyItPi7qDMRivT3C9NeAxCDjUqZ9y
# Q6NMv+YKjAewtlm2Y0me54cw+X4PdNrSyg==
# SIG # End signature block
