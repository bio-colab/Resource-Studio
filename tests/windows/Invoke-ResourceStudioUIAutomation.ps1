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

function Find-ByName([System.Windows.Automation.AutomationElement]$Root, [System.Windows.Automation.ControlType]$Type, [string]$Name) {
    $typeCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $Type)
    $nameCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, $Name)
    $condition = [System.Windows.Automation.AndCondition]::new($typeCondition, $nameCondition)
    return $Root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}

function Find-TopWindow([string]$Pattern) {
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

function Set-ElementValue([System.Windows.Automation.AutomationElement]$Element, [string]$Value) {
    $pattern = $Element.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    ([System.Windows.Automation.ValuePattern]$pattern).SetValue($Value)
}

function Get-ElementValue([System.Windows.Automation.AutomationElement]$Element) {
    $pattern = $Element.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    return ([System.Windows.Automation.ValuePattern]$pattern).Current.Value
}

function Get-ElementText([System.Windows.Automation.AutomationElement]$Element) { return $Element.Current.Name }

function Select-Element([System.Windows.Automation.AutomationElement]$Element) {
    $pattern = $Element.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
    ([System.Windows.Automation.SelectionItemPattern]$pattern).Select()
}

$app = $null
try {
    $resolvedPe = [System.IO.Path]::GetFullPath($PePath)
    $app = Start-Process -FilePath $ApplicationPath -ArgumentList @('--open', ('"{0}"' -f $resolvedPe), '--image-kind', 'icon') -PassThru
    $main = Wait-Until { if ($app.MainWindowHandle -ne 0) { [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle) } } 'main window'
    $openButton = Find-ById $main 'OpenPeButton'
    $openButton.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern) | Out-Null

    $pathBox = Wait-Until { Find-ById $main 'PathBox' } 'PathBox'
    Find-ById $main 'OutputPolicyText' | Out-Null
    Find-ById $main 'StatusDetailText' | Out-Null
    foreach ($id in @('ResourcesTab', 'PreviewTab', 'SearchTab', 'BatchTab', 'LocalizationTab', 'InspectTab', 'DiffTab', 'ResourceGrid', 'PropertyGrid')) { Find-ById $main $id | Out-Null }
    Wait-Until { (Get-ElementText (Find-ById $main 'ResourceCountText')) -notmatch '^0 resources$' } 'resources loaded' | Out-Null
    Wait-Until { (Get-ElementText (Find-ById $main 'CliStateText')) -eq 'Completed' } 'CLI completed state' | Out-Null
    $stopButton = Find-ById $main 'StopCliButton'
    if ($stopButton.Current.IsEnabled) { throw 'Stop button remained enabled after completion' }
    Wait-Until { (Get-ElementText (Find-ById $main 'StatusDetailText')) -match 'completed' } 'CLI completion detail' | Out-Null
    if ((Get-ElementText (Find-ById $main 'OutputPolicyText')) -notmatch 'Save As') { throw 'Save As policy is not visible' }
    Wait-Until { try { (Get-ElementValue $pathBox) -ieq $resolvedPe } catch { (Get-ElementText $pathBox) -match [regex]::Escape([System.IO.Path]::GetFileName($resolvedPe)) } } 'PE path loaded' | Out-Null

    $searchTab = Find-ByName $main ([System.Windows.Automation.ControlType]::TabItem) 'Search'
    Select-Element $searchTab
    Set-ElementValue (Find-ById $main 'SearchQueryBox') 'MANIFEST'
    Invoke-Element (Find-ById $main 'SearchButton')
    Wait-Until { $gridCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataGrid); $main.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $gridCondition) } 'search grid' | Out-Null

    Invoke-Element (Find-ById $main 'ThemeButton')
    Wait-Until { (Get-ElementText (Find-ById $main 'MainStatusText')) -match 'Dark mode' } 'dark mode status' | Out-Null

    $previewTab = Find-ByName $main ([System.Windows.Automation.ControlType]::TabItem) 'Preview'
    Select-Element $previewTab
    Wait-Until { Find-ById $main 'PreviewDetailsBox' } 'preview details box' | Out-Null

    Invoke-Element (Find-ById $main 'ImageWizardButton')
    $imageWindow = Wait-Until { Find-TopWindow '^Image Wizard$' } 'Image Wizard window'
    foreach ($id in @('ImagePePathBox', 'ImageKindBox', 'ImageLoadButton', 'ImagePreview', 'ImageExportBmpButton', 'ImageApplyBmpButton', 'StopCliButton')) { Find-ById $imageWindow $id | Out-Null }
    if ((Find-ById $imageWindow 'StopCliButton').Current.IsEnabled) { throw 'Image Wizard Stop button remained enabled while idle' }
    Wait-Until { (Get-ElementValue (Find-ById $imageWindow 'ImagePePathBox')) -ieq $resolvedPe } 'Image Wizard PE path' | Out-Null
    Invoke-Element (Find-ById $imageWindow 'ImageLoadButton')
    Wait-Until { (Get-ElementText (Find-ById $imageWindow 'ImagePreview')) -match '^BMP preview' } 'individual BMP preview' | Out-Null

    $imageWindow.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
    $main.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
    $app.WaitForExit(5000)
    Write-Output 'ui-automation-tests: passed'
    exit 0
}
catch {
    Write-Error "ui-automation-tests: failed: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($null -ne $app -and -not $app.HasExited) { $app.Kill() }
}
