$Domains = 'Domain1','Domain2','Domain3','Domain4','Domain5','Domain6'
$ReportFile = "C:\Temp\Audit\AuditUserss$(Get-Date -Format 'yyyyMMdd').xlsx"
$Today = Get-Date
$Properties = @(
    'SamAccountName'
    'UserPrincipalName'
    'GivenName'
    'SurName'
    'Description'
    'Enabled'
    'EmployeeType'
    'EmployeeNumber'
    'WhenCreated'
    'WhenChanged'
    'Mail'
    'Title'
    'HomeDirectory'
    'PasswordLastSet'
    'PasswordNeverExpires'
    'LastLogonDate'
    'LockedOut'
    'AccountExpirationDate'
    'PasswordExpired'
    'CanonicalName'
    'isCriticalSystemObject'
)
$SuplimentalProperties = @(
    'ExtensionAttribute13'
)
$SelectProperties = @(
    'SamAccountName'
    'UserPrincipalName'
    'GivenName'
    @{Name='SurName';Expression={$_.sn}}
    @{Name='Domain';Expression={$Domain}}
    'Description'
    'Enabled'
    'EmployeeType'
    'EmployeeNumber'
    'WhenCreated'
    'WhenChanged'
    @{Name='CreationTicket';Expression={$_.Extensionattribute13}}
    @{Name='Email';Expression={$_.mail}}
    'Title'
    'HomeDirectory'
    'PasswordLastSet'
    @{Name='PasswordAge';Expression={($Today-$_.PasswordLastSet).Days}}
    @{Name='PasswordExpires';Expression={-not $_.PasswordNeverExpires}}
    'LastLogonDate'
    @{Name='AccountIsDisabled';Expression={-not $_.Enabled}}
    @{Name='AccountIsLockedOut';Expression={$_.LockedOut}}
    @{Name='UserMustChangePassword';Expression={[boolean]($null -eq $_.passwordlastset)}}
    'AccountExpirationDate'
    @{Name='AccountIsExpired';Expression={[boolean]($_.AccountExpirationDate -lt $Today -and -not $null -eq $_.AccountExpirationDate)}}
    'PasswordExpired'
    'DistinguishedName'
    'CanonicalName'

)

Foreach ($Domain in $Domains) {
    Try {
    Get-ADUser -Filter * -Server $Domain -Credential $cred -Properties ($Properties + $SuplimentalProperties) -ErrorAction Stop|
        Where-Object {$_.isCriticalSystemObject -ne $True}|
        Select-Object -Property $SelectProperties|
        Sort-Object SamAccountName |
        Export-Excel -Path $ReportFile -WorksheetName $Domain -BoldTopRow -AutoSize -AutoFilter -FreezeTopRow -NoNumberConversion EmployeeNumber
    } Catch [System.ArgumentException] {
        Get-ADUser -Filter * -Server $Domain -Credential $cred -Properties $Properties -ErrorAction Stop|
        Where-Object {$_.isCriticalSystemObject -ne $True}|
        Select-Object -Property $SelectProperties|
        Sort-Object SamAccountName |
        Export-Excel -Path $ReportFile -WorksheetName $Domain -BoldTopRow -AutoSize -AutoFilter -FreezeTopRow -NoNumberConversion EmployeeNumber
    }
}

#Add Script content to the Report
Get-Content $MyInvocation.MyCommand.Path|Export-Excel -Path $ReportFile -WorksheetName "Script" -AutoSize -Title $MyInvocation.MyCommand.Name
