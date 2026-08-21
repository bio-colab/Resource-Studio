param(
    [Parameter(Mandatory = $true)][string]$ApplicationPath,
    [Parameter(Mandatory = $true)][string]$PePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

function Find-ById([System.Windows.Automation.AutomationElement]$Root, [string]$Id) {
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Id)
    $element = $Root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
    if ($null -eq $element) { throw "AutomationId not found: $Id" }
    return $element
}

function Find-Window([string]$Pattern) {
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Window)
    $windows = [System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Subtree, $condition)
    foreach ($window in $windows) { if ($window.Current.Name -match $Pattern) { return $window } }
    return $null
}

function Wait-Until([scriptblock]$Action, [string]$Description, [int]$TimeoutSeconds = 15) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $value = & $Action
            if ($null -ne $value -and $value -ne $false) { return $value }
        } catch { }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for $Description"
}

function Invoke-Element([System.Windows.Automation.AutomationElement]$Element) {
    $pattern = $Element.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    ([System.Windows.Automation.InvokePattern]$pattern).Invoke()
}

$app = $null
$about = $null
try {
    $resolvedPe = [System.IO.Path]::GetFullPath($PePath)
    $app = Start-Process -FilePath $ApplicationPath -ArgumentList @('--open', ('"{0}"' -f $resolvedPe)) -PassThru
    $main = Wait-Until { if ($app.MainWindowHandle -ne 0) { [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle) } } 'main window'
    Wait-Until { (Find-ById $main 'ResourceCountText').Current.Name -notmatch '^0 resources$' } 'resources loaded' | Out-Null

    Invoke-Element (Find-ById $main 'ThemeButton')
    Invoke-Element (Find-ById $main 'AboutButton')
    $about = Wait-Until { Find-Window '^About Resource Studio$' } 'About window'
    foreach ($id in @('AboutTitleText', 'AboutProjectText', 'AboutRepositoryLink', 'AboutDeveloperText', 'AboutEmailLink', 'AboutCloseButton')) {
        Find-ById $about $id | Out-Null
    }
    if ((Find-ById $about 'AboutTitleText').Current.Name -notmatch 'Resource Studio') { throw 'About title is not visible' }
    if ((Find-ById $about 'AboutProjectText').Current.Name -notmatch 'verification-first') { throw 'About project description is not visible' }
    if ((Find-ById $about 'AboutDeveloperText').Current.Name -ne 'Elias Sharar') { throw 'About developer is not visible' }
    $emailElement = Find-ById $about 'AboutEmailLink'
    if ($emailElement.Current.Name -notmatch 'aliasbio95@gmail.com') { throw 'About email is not visible' }
    if ((Find-ById $about 'AboutRepositoryLink').Current.Name -notmatch 'github.com/bio-colab/Resource-Studio') { throw 'About repository is not visible' }
    Write-Output 'about-ui-automation: passed in toggled theme'
    Invoke-Element (Find-ById $about 'AboutCloseButton')
    $about = $null
    $main.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
    $app.WaitForExit(5000)
    Write-Output 'about-ui-automation: complete'
    exit 0
}
catch {
    Write-Error "about-ui-automation: failed: $($_.Exception.ToString())"
    exit 1
}
finally {
    if ($null -ne $about) { try { $about.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close() } catch { } }
    if ($null -ne $app -and -not $app.HasExited) { $app.Kill() }
}
