<#
.DESCRIPTION
The script gets infos from CAs, Templates and Requests and exports them in CLIXML format to $OutPath

Some infos (like the key lengths) are taken from BSI
https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-4.pdf?__blob=publicationFile&v=2
#>

Import-Module .\PSPKI\3.7.2\PSPKI.psm1

$CertMaxLifetimeBasic = @{User=3;Computer=3}
$CertMaxLifetimeIssuing = @{Computer=5}
$CertMaxLifetimeRoot = @{Computer=6}
$SubCABasicConstraint = '2.5.29.19'
$EnterpriseCAs = Get-CA -Enterprise
$AllTemplatesAvailableOnCAs = @{}
$AllCAsInfo = New-Object System.Collections.ArrayList
$McertMinKeySizeCA = @{RSA=4096}
$OutPath = "C:\PKIAudit"
$AllIssuedRequests = New-Object System.Collections.ArrayList
If (-not (Test-Path $OutPath)) {
    mkdir $OutPath | Out-Null
}

#region Update CA and template infos
Foreach ($CA in $EnterpriseCAs) {
    Write-Host "[+] Getting infos for '$($ca.Name)'"
    # check the lifetime of the CA's current certificate
    $CALifeTimeYears = [int]((New-TimeSpan -Start ($CA.Certificate.NotBefore) -End ($CA.Certificate.NotAfter)).Days / 365)
    Add-Member -InputObject $CA -MemberType NoteProperty -Name LifetimeToHigh -Value $false -Force
    Add-Member -InputObject $CA -MemberType NoteProperty -Name HasPathLengthConstraint -Value (($ca.Certificate.Extensions | ?{$_.Oid.value -eq '2.5.29.19'}).HasPathLengthConstraint) -Force
    Add-Member -InputObject $CA -MemberType NoteProperty -Name PublicKeyTooShort -Value $false -Force

    if ($ca.Certificate.PublicKey.key.KeyExchangeAlgorithm -like 'RSA*' -and ([int]$ca.Certificate.PublicKey.key.KeySize -lt $McertMinKeySizeCA['RSA'])) {
        $ca.PublicKeyTooShort = $true
    }

    if ($ca.IsRoot -eq $false -and $CALifeTimeYears -gt $CertMaxLifetimeIssuing['Computer']) {
        $ca.LifetimeToHigh = $true
    }
    if ($ca.IsRoot -eq $true -and $CALifeTimeYears -gt $CertMaxLifetimeRoot['Computer']) {
        $ca.LifetimeToHigh = $true
    }
    [void]$AllCAsInfo.Add($CA)
    Write-Host "[+] Getting all issued requests. This might take a while"
    foreach ($r in (Get-IssuedRequest -CertificationAuthority $ca -Property upn,dns)) {
        [void]$AllIssuedRequests.Add($r)
    }

    Write-Host "[+] Getting infos about all certificates available on '$($ca.Name)'"
    $CATemplates = Get-CATemplate -CertificationAuthority $CA
    
    $EAP = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    Foreach ($t in $CATemplates.Templates) {
        Add-Member -InputObject $t -Name ACL -MemberType NoteProperty -Value (Get-CertificateTemplateAcl -Template $t) -Force
        $AllTemplatesAvailableOnCAs.Add($t.Name,$t)
    }
    $ErrorActionPreference = $EAP
}

Foreach ($t in $AllTemplatesAvailableOnCAs.Values) {
    Add-Member -InputObject $t -MemberType NoteProperty -Name LifetimeToHigh -Value $false -Force
    Add-Member -InputObject $t -MemberType NoteProperty -Name isSubCA -Value $false -Force
    if ($t.Settings.CriticalExtensions.value -contains $SubCABasicConstraint) {
        $t.isSubCA = $true
        if (([int]$t.Settings.ValidityPeriod.Split(' ')[0]) -gt $CertMaxLifetimeIssuing["Computer"]) {
            $t.LifetimeToHigh = $true
        }
    } else {
        if (([int]$t.Settings.ValidityPeriod.Split(' ')[0]) -gt $CertMaxLifetimeBasic["$($t.Settings.SubjectType)"]) {
            $t.LifetimeToHigh = $true
        }
    }
    
}
#endregion Update CA and template infos

Write-Host "[+] Exporting template infos"
Export-Clixml -InputObject $AllTemplatesAvailableOnCAs -Path $OutPath\AllTemplatesAvailableOnCAs.clixml -Force
Write-Host "[+] Exporting CA infos"
Export-Clixml -InputObject $AllCAsInfo -Path $OutPath\AllCAsInfo.clixml -Force
Write-Host "[+] Exporting issued request infos. This might take a while"
Export-Clixml -InputObject $AllIssuedRequests -Path $OutPath\AllIssuedRequests.clixml -Force
Write-Host "[+] Compressing files"
Compress-Archive -Path $OutPath -DestinationPath $OutPath\Allinfos.zip -Force -CompressionLevel Fastest
Write-Host "[+] Finished. Output is available here: '$($OutPath)\Allinfos.zip'" -ForegroundColor Green
<#
Foreach ($t in $AllTemplatesAvailableOnCAs.Values) {
    if ($t.LifetimeToHigh) {
        "$($t.name) -> $($t.Settings.ValidityPeriod)"
    }
}

Foreach ($c in $AllCAsInfo) {
    if ($c.LifetimeToHigh) {
        "$($c.Name) -> $(Get-date $c.Certificate.NotBefore -Format "dd.MM.yyyy") to $(Get-date $c.Certificate.NotAfter -Format "dd.MM.yyyy")"
    }
}
#>
