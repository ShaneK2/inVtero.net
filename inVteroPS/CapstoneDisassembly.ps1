#
# Starting to build out PS scripting 
# This script is meant for general demo/test of functionality
#
if($IsCoreCLR)
{
	[System.AppDomain]::CurrentDomain.SetData("APP_CONFIG_FILE", $config_path)
	$ModuleName = "inVteroCore.dll"
} else {
	$config_path = "inVtero.net.dll.config"
	[System.AppDomain]::CurrentDomain.SetData("APP_CONFIG_FILE", $config_path)
	$ModuleName = "inVtero.net.dll"
}

#scan for module matching our environment
$moduleItem = Get-ChildItem -Filter $ModuleName -Recurse -ErrorAction SilentlyContinue -Force
$p = [Environment]::GetEnvironmentVariable("PSModulePath")
$p += ";.;" + $moduleItem.DirectoryName
[Environment]::SetEnvironmentVariable("PSModulePath",$p)

Import-Module -Force $moduleItem.FullName
$Module = Get-Module $moduleItem.BaseName

	
$Bytes = [Byte[]] @( 0x10, 0xf1, 0x10, 0xe7, 0x11, 0xf2, 0x31, 0xe7, 0xdc, 0xa1, 0x2e, 0xf3, 0xe8, 0x4e, 0x62, 0xf3 )


Write-Host "Running CapstoneDissassembly cmdlet..."
Measure-Command {
try
{
	 $Bytes | Get-CapstoneDissassembly -D 0 
} catch {
    Write-Error $_.Exception.ToString()
	Read-Host
}} | Write-Host "total seconds: " |select TotalSeconds  | ft -hidetableheaders | 

Write-Host "done."

