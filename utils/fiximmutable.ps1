Param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Current upn?")]
    [String]$upn,
    [Parameter(Mandatory=$true, Position=0, HelpMessage="New upn?")]
    [String]$newname
)

function MSOLConnected {
    Get-MsolDomain -ErrorAction SilentlyContinue | out-null
    $result = $?
    return $result
}

if (-not (MSOLConnected)) {
    Connect-MsolService
}

Set-MsolUserPrincipalName -UserPrincipalName $upn -NewUserPrincipalName $newname
Set-MsolUser -UserPrincipalName $newname -ImmutableId $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($newname)))
