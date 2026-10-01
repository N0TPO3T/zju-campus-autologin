param(
    [string]$PythonPath,
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^\\/:*?"<>|\[\]]+$')]
    [string]$TaskName = 'ZJU-CampusAutoLogin-OpenSource',
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'

try {
    $script = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'campus_login.py'))
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
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
        $sameSource = $actions.Count -eq 1 -and $actions[0].Arguments -eq ('"{0}"' -f $script) -and
            $actions[0].WorkingDirectory -eq $PSScriptRoot -and
            $existingSid.Value -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if (-not $sameSource) {
            throw "Task '$TaskName' belongs to another source directory or user. Use -TaskName with a distinct name, or remove it from its original installation. This installer will not overwrite or remove it."
        }
    }
    if ($Remove) {
        if ($existing) {
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false
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
    $action = New-ScheduledTaskAction -Execute $pythonw -Argument ('"{0}"' -f $script) -WorkingDirectory $PSScriptRoot
    $hourly = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Hours 1)
    $logon = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask -Action $action -Trigger @($hourly, $logon) -Principal $principal -Settings $settings -Description 'Check ZJU authentication hourly and at Windows logon; authenticate only when offline. Requires the configured Windows user session; works while locked.'
    Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -InputObject $task -Force | Out-Null
    Write-Output "Task '$TaskName' installed. Runs hourly and at logon in the current user session, including while locked; does not run after sign-out."
    Write-Output 'Keep this source directory and the selected Python installation in their current locations.'
} catch {
    Write-Error $_
    exit 1
}
