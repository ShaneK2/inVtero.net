#
# Starting to build out PS scripting 
# This script is meant for general demo/test of functionality
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


#So we do not have to install officially
#scan for our module matching the environment
$moduleItem = Get-ChildItem -Filter $ModuleName -Recurse -ErrorAction SilentlyContinue -Force
$p = [Environment]::GetEnvironmentVariable("PSModulePath")
$p += ";.;" + $moduleItem.DirectoryName
[Environment]::SetEnvironmentVariable("PSModulePath",$p)

Import-Module -Force $moduleItem.FullName
$Module = Get-Module $moduleItem.BaseName

# some info from the internals
#[inVtero.net.Vtero]::VerboseOutput = $true

ConvertTo-TypeInfo -I C:\windows\system32\ntoskrnl.exe -T _EPROCESS

