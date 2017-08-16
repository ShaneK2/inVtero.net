<#
	My Function $env:PSModulePath = 
	
	$env:PSModulePath + ";."
	Import-Module .\inVtero.net.dll
	#New-InVteroDB 
	Add-InVteroDB -VF C:\temp\psIV -HS 256 -BufferCount 100000000 -I C:\Windows\System32\drivers
#>
Import-Module inVtero.net
function CreateVteroDB {
	New-InVteroDB -VF C:\temp\psIV -Size 512M
}

function LoadVteroDB {
	Add-InVteroDB -VF C:\temp\psIV -HS 256 -BufferCount 100000000 -I C:\Windows\System32\drivers
}
#LoadVteroDB