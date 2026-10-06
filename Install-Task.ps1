param(
    [string]$PythonPath,
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^\\/:*?"<>|\[\]]+$')]
    [string]$TaskName = 'ZJU-CampusAutoLogin-OpenSource',
    [ValidateRange(1, 1440)]
    [int]$IntervalMinutes = 5,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'

try {
    $script = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'campus_login.py'))
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $systemSid = 'S-1-5-18'
    $elevated = ([System.Security.Principal.WindowsPrincipal](
        [System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $dataDir = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'ZjuCampusAutoLogin' } else { $null }
    # The SYSTEM task runs without a user profile, so its data directory is explicit.
    $argument = if ($dataDir) { '"{0}" --data-dir "{1}"' -f $script, $dataDir } else { '"{0}"' -f $script }
    # Installations made before --data-dir existed used the bare script path.
    $legacyArgument = '"{0}"' -f $script
    $machineCredential = if ($dataDir) { Join-Path $dataDir 'credentials.system.dat' } else { $null }

    # Enumerate with terminating errors so a lookup failure cannot become an overwrite.
    $existing = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.TaskName -eq $TaskName }
    if ($existing) {
        $actions = @($existing.Actions)
        # Task Scheduler may normalize DOMAIN\user to a bare local account name.
        $existingUser = [string]$existing.Principal.UserId
        $existingSid = if ($existingUser -match '^S-1-') {
            [System.Security.Principal.SecurityIdentifier]::new($existingUser)
        } else {
            [System.Security.Principal.NTAccount]::new($existingUser).Translate(
                [System.Security.Principal.SecurityIdentifier])
        }
        # Our own tasks run as the current user (session mode) or as SYSTEM
        # (administrator mode); anything else is never overwritten or removed.
        $sameSource = $actions.Count -eq 1 -and
            $actions[0].Arguments -in @($argument, $legacyArgument) -and
            $actions[0].WorkingDirectory -eq $PSScriptRoot -and
            ($existingSid.Value -eq $currentSid -or $existingSid.Value -eq $systemSid)
        if (-not $sameSource) {
            throw "Task '$TaskName' belongs to another source directory or user. Use -TaskName with a distinct name, or remove it from its original installation. This installer will not overwrite or remove it."
        }
    }
    if ($Remove) {
        if ($existing) {
            try {
                Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false
            } catch {
                throw "Could not remove task '$TaskName'. A task installed in SYSTEM mode requires an elevated PowerShell. $($_.Exception.Message)"
            }
            Write-Output "Task '$TaskName' removed. Local files and encrypted credentials retained."
        } else {
            Write-Output "Task '$TaskName' is not installed. Nothing removed."
        }
        exit 0
    }
    if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
        throw "Missing campus_login.py beside this installer. Keep the complete source directory together."
    }
    if (-not $PythonPath) {
        $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($launcher) {
            $candidate = & $launcher.Source -3 -c 'import sys; print(sys.executable)' 2>$null
            if ($LASTEXITCODE -eq 0) { $PythonPath = ($candidate | Select-Object -Last 1) }
        }
        if (-not $PythonPath) {
            $command = Get-Command python.exe -ErrorAction SilentlyContinue
            if ($command) { $PythonPath = $command.Source }
        }
    }
    if (-not $PythonPath -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw 'Python was not found. Install Python 3.10+ with Tk support, then pass -PythonPath with its full python.exe path.'
    }
    $PythonPath = (Resolve-Path -LiteralPath $PythonPath).ProviderPath
    if ([System.IO.Path]::GetFileName($PythonPath) -ieq 'pythonw.exe') {
        $PythonPath = Join-Path (Split-Path -Parent $PythonPath) 'python.exe'
        if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
            throw 'The selected pythonw.exe has no matching python.exe. Select a complete Python installation.'
        }
    }
    & $PythonPath -c 'import sys, tkinter; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
    if ($LASTEXITCODE -ne 0) {
        throw 'The selected interpreter must be Python 3.10+ with Tk support. Run Setup.cmd using a supported Python installation.'
    }
    $pythonw = Join-Path (Split-Path -Parent $PythonPath) 'pythonw.exe'
    if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) {
        throw 'No pythonw.exe exists beside the selected Python interpreter. Install the Windows Python distribution with windowed execution support.'
    }
    # pythonw must be the sibling of this exact interpreter, never another PATH entry.
    $action = New-ScheduledTaskAction -Execute $pythonw -Argument $argument -WorkingDirectory $PSScriptRoot
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $interval = New-TimeSpan -Minutes $IntervalMinutes
    $description = "Check ZJU authentication every $IntervalMinutes minute(s); authenticate only when offline."

    # Session-independent mode: needs administrator rights at install time and
    # the machine-scope credential file written by the current Setup.cmd.
    $mode = 'USER'
    if ($elevated -and $machineCredential -and (Test-Path -LiteralPath $machineCredential -PathType Leaf)) {
        try {
            $systemTask = New-ScheduledTask -Action $action -Trigger @(
                    (New-ScheduledTaskTrigger -AtStartup),
                    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval $interval)) `
                -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
                -Settings $settings -Description "$description Runs without any user session."
            Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -InputObject $systemTask -Force | Out-Null
            $mode = 'SYSTEM'
        } catch {
            Write-Output ("Administrator-mode task registration failed; installing the user-session task instead. " + $_.Exception.Message)
        }
    } elseif ($elevated) {
        Write-Output 'Machine-scope credentials are missing. Run the current Setup.cmd first; installing the user-session task for now.'
    }
    if ($mode -eq 'USER') {
        $userTask = New-ScheduledTask -Action $action -Trigger @(
                (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval $interval),
                (New-ScheduledTaskTrigger -AtLogOn -User $user)) `
            -Principal (New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited) `
            -Settings $settings -Description "$description Requires the configured Windows user session; works while locked."
        Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -InputObject $userTask -Force | Out-Null
    }
    Write-Output "MODE=$mode"
    if ($mode -eq 'SYSTEM') {
        Write-Output "Task '$TaskName' installed: runs at startup and every $IntervalMinutes minute(s) as SYSTEM, no user session required."
    } else {
        Write-Output "Task '$TaskName' installed: runs at Windows logon and every $IntervalMinutes minute(s) in the current user session; it does not run after sign-out or before the first logon after a reboot."
        if (-not $elevated) {
            Write-Output 'Run Setup.cmd from an elevated (administrator) terminal to enable the session-independent startup mode.'
        }
    }
    Write-Output 'Keep this source directory and the selected Python installation in their current locations.'
} catch {
    Write-Error $_
    exit 1
}
