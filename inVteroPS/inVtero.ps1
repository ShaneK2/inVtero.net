#
# Starting to build out PS scripting 
# This script is meant for general demo/test of functionality
#
if($IsCoreCLR)
{
	$config_path = "inVteroCore.dll.config"
	[System.AppDomain]::CurrentDomain.SetData("APP_CONFIG_FILE", $config_path)
	$ModuleName = "inVteroCore.dll"
} else {
	$config_path = "inVtero.net.dll.config"
	[System.AppDomain]::CurrentDomain.SetData("APP_CONFIG_FILE", $config_path)
	$ModuleName = "inVtero.net.dll"
}

if($IsCoreCLR)
{
	if($IsLinux) {
		$InVteroDir = "/data/"
		$InputSnapshot = "/data/test/Windows 10 x64-PRO-1703-40599dd1.vmem"
		#$InputSnapshot = "/data/test/MSEdge - Win10_preview-e70efcb2.vmem"
	} 
	elseif($IsWindows) {
		$vm = "Windows Server 2016-02431799.vmem";
		#$vm = "MSEdge.Win10.RS2.VMWare\MSEdge - Win10_preview\MSEdge - Win10_preview-e70efcb2.vmem";
		$InVteroDir = "C:\temp\inVtero.net"
		$InputSnapshot = "D:\Users\files\VMs\Windows Server 2016\" + $vm
	}
	elseif($IsOsX)
	{
		Write-Warning "Not tested yet! (however it may work ;)?"
		Write-Warning "Manually configure settings please."
	} else {
		Write-Error "Unknown state."
		return;
	}
}

if($args[0] -and (Test-Path $args[0] -PathType Leaf)) { $InputSnapshot = $args[0] }


#scan for module matching our environment
$moduleItem = Get-ChildItem -Filter $ModuleName -Recurse -ErrorAction SilentlyContinue -Force
$p = [Environment]::GetEnvironmentVariable("PSModulePath")
$p += ";.;" + $moduleItem.DirectoryName
[Environment]::SetEnvironmentVariable("PSModulePath",$p)

Import-Module -Force $moduleItem.FullName
$Module = Get-Module $moduleItem.BaseName

# setup GLobal flags
[inVtero.net.Vtero]::VerboseLevel = 1
[inVtero.net.Vtero]::VerboseOutput = $true
[inVtero.net.Vtero]::DiagOutput = $false
[inVtero.net.Vtero]::DisableProgressBar = $true

#Add-InVteroDB -VF C:\temp\psIV -HS 256 -BufferCount 100000000 -I C:\Windows\System32\drivers
# stopwatch for perf testing

Write-Host "Running Test-Snapshot cmdlet..."
Measure-Command {
try
{
	Test-Snapshot -CHash $True -VF $InVteroDir -HashSize 256 -InputFile $InputSnapshot -M GENERIC 
} catch {
    Write-Error $_.Exception.ToString()
	Read-Host
}} | Write-Host "total seconds: " |select TotalSeconds  | ft -hidetableheaders | 

Write-Host "Test-Snapshot runtime "




#Remove-Module $Module.Name
#Remove-Item $Module.ModuleBase -Force
