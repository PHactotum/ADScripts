[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [String]
    $Identity,
    [Parameter(Mandatory=$true)]
    [String]
    $Domain,
    [Parameter(Mandatory=$true, ParameterSetName='Default')]
    [String]
    $DomainController,
    [Parameter(Mandatory=$true, ParameterSetName='FQDN')]
    [String]
    $DomainControllerFQDN,
    [Parameter(Mandatory=$true)]
    [pscredential]
    $Credential,
    [Parameter(Mandatory=$false)]
    [Int32]
    $TimeOut=30
)

function Test-Credentials {
    [CmdletBinding()]
    Param(
        [PSCredential]
        $credentials,
        [string]
        $DomainControllerFQDN
        )
    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $pctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainControllerFQDN)
    $nc = $credentials.GetNetworkCredential()
    return $pctx.ValidateCredentials($nc.UserName, $nc.Password)
}

Function RandomPassword {
    <#
    .SYNOPSIS
    Creates Random Passwords
    .DESCRIPTION
    This function can be used to create random passwords in PowerShell based environments.
    It accepts a password length and an optional pattern (full or partial).
    A random pattern will be created or added if not specified.
    You can use patterns to make sure that your passwords has a guaranteed password complexity.
    .PARAMETER length
    The length of the password.
    .PARAMETER pattern
    [Optional] Define a specific pattern for the password
    .EXAMPLE
    RandomPassword -length 8
    8-char password with a random pattern
    .EXAMPLE
    RandomPassword -length 12 -pattern "ULNS"
    12-char with a partial start pattern "ULNS":
    one uppercase, one lowercase, one numeric, one specific
    the last six pattern classes will be generated in random
    .EXAMPLE
    RandomPassword -length 10 -pattern "LLLLSUUUUN"
    10-char password with a full pattern "LLLLSUUUUN":
    four lowercase, one special, four uppercase and one numeric
    #>
  param (
      [int]$length,
      [string]$pattern # optional
  )

  # Define classes of character pools, there are six classes
  # by default: L - lowercase, U - uppercase, N - numeric, A = alphabetic upper or lower, W = Whatever character
  # S - special
  #$pattern_class = @("L", "U", "N", "S", "A", "W")

  # Character pools for classes defined above
  $charpool = @{
      "L" = "abcdefghjkmnpqrstuvwxyz";
      "U" = "ABCDEFGHJKLMNPQRSTUVWXYZ";
      "N" = "1234567890";
      "S" = "!#%*^>@[]"
      "A" = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
      "W" = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz1234567890!#%*^>@";
  }

  $rnd = New-Object System.Random

  # Introduce a random delay to avoid same random seed
  # during frequent calls
  Start-Sleep -milliseconds $rnd.Next(500)

  # Create a random pattern if pattern is not defined or
  # fill the remaining if the pattern length is less than
  # password length
  if (!$pattern -or $pattern.length -lt $length) {

      if (!$pattern)
      {
          $pattern = ""
          $start = 0
      } else {
          $start = $pattern.length - 1
      }

      # Create a random pattern
      for ($i=$start; $i -lt $length; $i++)
      {
          $pattern += $pattern[$rnd.Next($pattern.length)]
      }

      # DEBUG: write-host "Random pattern : $pattern"
   }

   $password = ""

   for ($i=0; $i -lt $length; $i++)
   {
      $wpool = $charpool[[string]$pattern[$i]]
      $password += $wpool[$rnd.Next($wpool.length)]
   }

   return $password
} # End of Function to create Random Password


# Function to Test Password
Function TestPassword {
  param
  (
  [string]$Teststring
  )

  Switch -wildcard ($Teststring)
  {
  "*~[1!]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*1[`2\@~Q1]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*![`2\@~Q]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*2[1!QW3#2]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*@[1!QW3#]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*3[2\@WE4\`$3]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*#[2\@WE4\`$]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*4[#3ER5%4]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\`$[#3ER5%]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*5[\`$4RT6\^5]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*%[\`$4RT6\^]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*6[%5TY7&6]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\^[%5TY7&]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*7[\^6YU8\*7]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*&[\^6YU8\*]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*8[&7UI9\(8]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "\*[&7UI9\(]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*9[\*8IO0\)9]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\([\*8IO0\)]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*0[9\(OP-_0]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\)[9\(OP-_]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*-[0\)P\{\[=\+]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*_[0\)P\{\[=\+]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*Q[1!2\@ASWQ]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*W[QASE2\@3#W]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*E[WSDR34#\`$E]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*R[EDFT45\`$%R]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*T[RFGY56%\^T]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*Y[TGHU67\^&Y]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*U[YHJI78&\*U]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*I[UJKO89\(\*I]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*O[IKLP09\(\)O]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\[P;:'\`"`]}-_=\+]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\{[P;:'\`"`]}-_=\+]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*][\{\[\'\`"\\\|=\+]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*}[\{\[\'\`"\\\|=\+]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\\[`]}]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\|[`]}]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*A[QWSZA]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*S[AWEDXZS]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*D[SERFCXD]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*F[DRTGVCF]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*G[FTYHBVG]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*H[GYUJNBH]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*J[HUIKMNJ]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*K[JIOL<,MK]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*L[KOP><,\.;:L]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*;[LP\`[\{'\`"\/\?\.>]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*:[LP\`[\{'\`"\/\?\.>]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*'[;:\`[\{`]}\/\?]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\`"[;:\`[\{`]}\/\?]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*Z[ASXZ]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*X[ZS DCX]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*C[XD FVC]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*V[CF GBV]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*B[VG HNB]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*N[BH JMN]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*M[NJ K,<M]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*P[O;LP]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*<[MK L\.>]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*,[MK L\.>]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*>[,<. L;:\/\?]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\.[,<. L;:\/\?]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\/[\.>;:'\`"]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  "*\?[\.>;:`'\`"]*" {Set-Variable -Name TestResult -Value "Failed" -Scope 1}
  default {Set-Variable -Name TestResult -Value "Passed" -Scope 1}
  }
} # End of Function to Test Password

Function New-Password ()
  {
  Param(
  [int]$MinLength = 8,
    [int]$MaxLength = 9,
    #Password Pattern Default = UWNSA L - lowercase, U - uppercase, N - numeric, A = alphabetic upper or lower, W = Whatever character, S - special
    $pwdpattern = "UWNSA"
    )
                  # Set Test Result to Failed to start generating new passwords
                  $TestResult = "Failed"

                  # Script will continue to generate new passwords until a password passes the test
                  While ($TestResult -eq "Failed")
                      {
                      $RandomLength = Get-Random -Minimum $MinLength -Maximum $MaxLength
                      $Randompwd = RandomPassword -length $RandomLength -pattern "$pwdpattern"
                      write-verbose "`tTesting $Randompwd"
                      TestPassword -Teststring "$Randompwd"
                      write-verbose "`t$TestResult"
                      }
                  Return $Randompwd
}


if ($null -eq $DomainControllerFQDN) {
    $DomainControllerFQDN = (Get-ADDomainController -Server $Domain -Identity $DomainController).HostName
}
$PDC = (Get-ADDomainController -Discover -DomainName $domain -Service PrimaryDC).HostName[0]

$TestPass = $(ConvertTo-SecureString -AsPlainText (New-Password -pwdpattern 'UNLAAAAA') -Force)

[pscredential]$TestCredential = New-Object System.Management.Automation.PSCredential ($Identity,$TestPass)

$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$timeSpan = New-TimeSpan -Minutes $TimeOut
# All the above is to set is up to change the password, and Validate it
$ADUser = Get-ADUser -Credential $Credential -Identity $Identity -Server $DomainControllerFQDN -Properties LockedOut,AccountExpirationDate
if ($ADUser.LockedOut) {
    Write-Host "$($stopWatch.Elapsed.ToString()): Locked, unlocking"
    Unlock-ADAccount -Credential $Credential -Identity $Identity -Server $DomainControllerFQDN
}
If ($ADUser.AccountExpirationDate -le (Get-Date)) {
    Throw "00:00:00.0000000: Account Expired, test cannot continue"
    
}
$stopWatch.Start()
Set-ADAccountPassword -Credential $Credential -Identity $Identity -NewPassword $TestPass -Reset -Server $DomainControllerFQDN
$SetPasswordTime = $stopWatch.Elapsed.ToString()
$Valid = Test-Credentials -Credential $TestCredential -DomainControllerFQDN $DomainControllerFQDN
$ValidationTime = $stopWatch.Elapsed.ToString()
<#
[PSCustomObject]@{
    Identity = $Identity
    Password = ($TestCredential.GetNetworkCredential()).Password
    DCFQDN = $DomainControllerFQDN
    Valid = $Valid
    SetPasswordTime = $SetPasswordTime
    EndValidation = $ValidationTime
}
#>
Write-Host "IDentity: $Identity"
Write-Host "DCFQDN: $DomainControllerFQDN"
Write-Host "Valid: $Valid"
Write-Host "ValidationTime: $ValidationTime"
If ($Valid) {
Write-Host "Testing against PDC: $PDC"
Do {
    # Start-Sleep -Seconds 1
    if ((Get-ADUser -Credential $Credential -Identity $Identity -Server $PDC -Properties LockedOut).LockedOut) {
        Write-Host "$($stopWatch.Elapsed.ToString()): Locked, unlocking"
        Unlock-ADAccount -Credential $Credential -Identity $Identity -Server $PDC
    }
    $PDCValid = Test-Credentials -Credential $TestCredential -DomainControllerFQDN $PDC
    Write-Host "$($stopWatch.Elapsed.ToString()): PDC Valid: $PDCValid"
} until ($PDCValid -or ($stopWatch.Elapsed -ge $timeSpan))
$stopWatch.Stop()
} else {
    Write-Host "Not testing on PDC since local server is not valid"
}
[PSCustomObject]@{
    Identity = $Identity
    Password = ($TestCredential.GetNetworkCredential()).Password
    DCFQDN = $DomainControllerFQDN
    Valid = $Valid
    SetPasswordTime = $SetPasswordTime
    EndValidation = $ValidationTime
    PDCisValid = $PDCValid
    ElapsedTime=$stopWatch.Elapsed
}
