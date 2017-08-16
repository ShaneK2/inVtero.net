#
# inVtero.ps1
# This or quickdumps config
$config_path = ".\invtero.net\bin\x64\Debug\inVtero.net.dll.config"
[System.AppDomain]::CurrentDomain.SetData("APP_CONFIG_FILE", $config_path)

#$env:PSModulePath + ";."
#Save the current value in the $p variable.
$p = [Environment]::GetEnvironmentVariable("PSModulePath")

#Add the new path to the $p variable. Begin with a semi-colon separator.
$p += ";.\inVtero.net\bin\x64\Debug\"

#Add the paths in $p to the PSModulePath value.
[Environment]::SetEnvironmentVariable("PSModulePath",$p)

Import-Module .\invtero.net\bin\x64\Debug\inVtero.net.dll

$Module = Get-Module InVtero.net

Read-Host -Prompt "Waiting for debugger."

try
{
	Add-InVteroDB -VF C:\temp\psIV -HS 256 -BufferCount 100000000 -I C:\Windows\System32\drivers
}
catch
{
    Write-Error $_.Exception.ToString()
    Read-Host -Prompt "The above error occurred. Press Enter to exit."
}

Remove-Module $Module.Name
Remove-Item $Module.ModuleBase -Force
