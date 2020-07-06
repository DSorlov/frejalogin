Param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Current upn?")]
    [String]$upn,
    [Parameter(Mandatory=$true, Position=1, HelpMessage="Immutable Id (email)?")]
    [String]$newname,
    [Parameter(HelpMessage="Change UPN to the new name (for faux-federated domains)")]
    [Switch]$fixdomain
)

function MSOLConnected {
    Get-MsolDomain -ErrorAction SilentlyContinue | out-null
    $result = $?
    return $result
}

if (-not (MSOLConnected)) {
    Connect-MsolService
}

Set-MsolUser -UserPrincipalName $upn -ImmutableId $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($newname)))

if ($fixdomain) {
    Set-MsolUserPrincipalName -UserPrincipalName $upn -NewUserPrincipalName $newname
}
