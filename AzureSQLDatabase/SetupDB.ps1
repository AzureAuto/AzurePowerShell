<#
	The MIT License (MIT)

	Copyright (c) 2015 James Corbould

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

.DESCRIPTION 
	Creates a new Azure SQL database in the pre-existing db server.  Sets the database up (e.g. creates tables) and creates
	a firewall rule on the db server, for the machine running this script.
.EXAMPLE
	.\SetupDb.ps1 -pDbServerName "alpha" -pDbServerUsername "big" -pDbServerPassword "bird" -pDDLScripts "CreateTableFoo.sql,InsertTableFoo.sql"
.DEPENDENCIES
	Need to run CreateSQLCredential.ps1 first to create secure SQL credential file.
.SOURCE
	https://github.com/AzureAuto/AzurePowerShell
.CHANGE_HISTORY:
	Version		Date			Who			Change Description
	-------		----------		-------		----------------------------
	1.0.0.0		08/10/2015		JRC			Created.
#>
param(
	[CmdletBinding(SupportsShouldProcess=$true)]
        
	# The Azure data centre location.
    [string]$pLocation="Southeast Asia",

    [Parameter(Mandatory = $true)]
    [String]$pDbServerName,

	[string]$pDbName="Datamate",

	[Parameter(Mandatory = $true)]
    [String]$pDbServerUsername,

	[Parameter(Mandatory = $true)]
    [String]$pDbServerPassword,

	# Optionally pass in path to DDL scripts to be run on successful db creation.
	[string]$pDDLScriptPath,

	# Optionally pass in a list of DDL scripts to be run on successful db creation.
	[string]$pDDLScripts
)

#================================================
# GLOBAL VARS
#================================================

$_ComputerName = $env:COMPUTERNAME
$_CurrentDateTime = Get-Date -Format s
$_CurrentDateTime = $_CurrentDateTime -replace ':','_'
$_PSPath = Split-Path -Parent $PSCommandPath
$_LogName = [string]::Format("Logging\{0}_SetupDB_{1}.log", $_CurrentDateTime, $_ComputerName)
$_LogFile = Join-Path $_PSPath $_LogName
$_ScriptName = "SetupDB.ps1"
$_MaxLoop = 100

#================================================
# FUNCTIONS
#================================================

Function Write-Log($LogMessage)
{
	if (!(Test-Path -Path "Logging"))
	{
		New-Item -Path "Logging" -ItemType directory | Out-Null
	}

	if (!(Test-Path -Path $_LogFile))
	{
		New-Item -Path $_LogFile -Value $LogMessage`n -ItemType file | Out-Null
	}
	else
	{
		Add-Content $_LogFile -Value $LogMessage
	}
}

Function Write-Success($Message)
{
	Write-Host $Message -ForegroundColor Green
	Write-Log "$(Get-Date -Format s) $Message"
}

Function Write-Warning($Message)
{
	Write-Host $Message -ForegroundColor Yellow
	Write-Log "$(Get-Date -Format s) $Message"
}

Function Write-Error($Message)
{
	Write-Host $Message -ForegroundColor Red
	Write-Log "$(Get-Date -Format s) $Message"
}

Function SetupFirewallAccessRuleDbServer($DbServerName)
{
	try
	{
		$success = $true
		$loopCount = 0

		Write-Success "Entered function SetupFirewallAccessRuleDbServer."

		$clientFirewallRuleName = "ClientIPAddress_" + (Get-Random).ToString()
		# Retrieve IPv4 address only.  TODO: check that this is a IPv4 address, otherwise loop through and find one.
		$clientIP = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -ne $null }).ipaddress[0]
		Write-Success "Creating firewall access rule '$clientFirewallRuleName' on db server '$pDbServerName' for client IP address '$clientIP'."
		New-AzureSqlDatabaseServerFirewallRule -ServerName $pDbServerName `
			  -RuleName $clientFirewallRuleName -StartIpAddress $clientIP -EndIpAddress $clientIP | Out-Null

		# Loop until the fw rule has been provisioned.
		do 
		{
			$rule = Get-AzureSqlDatabaseServerFirewallRule -ServerName $pDbServerName -RuleName $clientFirewallRuleName
			$ruleName = $rule.RuleName
			Write-Success "Waiting for the firewall rule to be setup..."
			sleep 10
			$loopCount += 10
		} until ($ruleName -eq $clientFirewallRuleName -and $loopCount -le $_MaxLoop)

		if ($ruleName -eq $null -or $ruleName -ne $clientFirewallRuleName)
		{
			Write-Error "Failed to provision firewall client access rule or reached provision check timeout."
			$success = $false
		}
		else
		{
			Write-Success "Firewall client access rule has been created!"
		}
	}
	catch [System.Exception]
	{
		$errMessage = [string]::Format("Error :: SetupFirewallAccessRuleDbServer function failed with the following error:`n{0}", $error[0])
		Write-Error $errMessage
		$success = $false;
	}

	return $success
}

Function CreateDatabase($DbServerName, $Location, $AppDatabaseName, $Credential)
{
    try
	{
		$success = $true
		$loopCount = 0

		Write-Success "Entered function CreateDatabase."
		Write-Success "Obtaining Azure SQL db server context for server '$DbServerName'."

		$context = New-AzureSqlDatabaseServerContext -ServerName $DbServerName -Credential $Credential
    
		Write-Success "Creating database '$AppDatabaseName' in database server '$DbServerName'."
    
		$dmdb = New-AzureSqlDatabase -DatabaseName $AppDatabaseName -Context $context -Edition "Basic"
		
		if ($dmdb -eq $null)
		{
			$success = $false
		}

		if ($success -eq $true)
		{
			# Loop until the database has been provisioned.
			do 
			{
				$db = Get-AzureSqlDatabase -ServerName $DbServerName -DatabaseName $AppDatabaseName
				$state = $db.ServiceObjectiveAssignmentStateDescription
				Write-Success "Waiting for the database to be provisioned..."
				sleep 10
				$loopCount += 10
			} until ($state -eq 'Complete' -and $loopCount -le $_MaxLoop)

			if ($state -ne 'Complete')
			{
				Write-Error "Failed to provision database or reached provision check timeout."
				$success = $false
			}
			else
			{
				Write-Success "Database has been created!"
			}
		}
	}
	catch [System.Exception]
	{
		$errMessage = [string]::Format("Error :: CreateDatabase function failed with the following error:`n{0}", $error[0])
		Write-Error $errMessage
		$success = $false;
	}

	return $success
}

Function SetupDatabase($DbServerName, $AppDatabaseName, $Username, $Password)
{
	$success = $true

	try
	{
		Write-Success "Entered function SetupDatabase."

		if ([string]::IsNullOrEmpty($pDDLScriptPath))
		{
			# If no path to DDL scripts provided, assume it's in the same directory as this PS script.
			$sqlPath = $_PSPath
		}
		else
		{
			$sqlPath = $pDDLScriptPath
		}

		[Array]$sqlFiles = $pDDLScripts -split ','

		foreach ($sqlFile in $sqlFiles)
		{
			$ddlPath = Join-Path $sqlPath $sqlFile
			Write-Success "Invoking sqlcmd on file '$ddlPath'..."
			Invoke-Sqlcmd -InputFile $ddlPath -ServerInstance "$DbServerName.database.windows.net" -Database $AppDatabaseName -WarningAction SilentlyContinue -OutputSqlErrors $false -Username $Username -Password $Password -EncryptConnection | Out-Null
		}

		Write-Success "Completed function SetupDatabase."
	}
	catch [System.Exception]
	{
		$errMessage = [string]::Format("Error :: SetupDatabase function failed with the following error:`n{0}", $error[0])
		Write-Error $errMessage
		$success = $false
	}

	return $success
}

Function VerifyDatabaseSetupCorrectly($DbServerName, $AppDatabaseName, $UserID, $UserPwd, $DbConfigXML)
{
	#TODO: using the XML config specified in $DbConfigXML, check that this database has been setup correctly by comparing
	#      against the expected setup/outcome specified in the XML config file.

}

#================================================
# MAIN EXECUTION HERE
#================================================

$startDateTime = Get-Date -Format s
Write-Success "====================================="
Write-Success "Start of script execution"
Write-Success "Script name :: '$_ScriptName'"
Write-Success "Computer name :: '$_ComputerName'"
Write-Success "Datetime :: $startDateTime"
Write-Success "====================================="

try
{
	$credPath = Join-Path (Split-Path -parent $PSCommandPath) CreateSQLCredential.ps1.credential

	if ($credPath -eq $null)
	{
		Write-Success "Error :: SQL credential is null.`nCheck that credential file exists at this location: '$credPath'"
	}
	else
	{
		Write-Success "Loading SQL credential file at '$credPath'..."
		$SQLcredential = Import-CliXml $credPath

		if ($SQLcredential -eq $null)
		{
			Write-Success "Error :: Failed to load SQL credential file at this location: '$credPath'"
		}
		else
		{
			$createFwRuleSuccess = SetupFirewallAccessRuleDbServer $pDbServerName

			if($createFwRuleSuccess -eq $true)
			{
				$createDBSuccess = CreateDatabase $pDbServerName $pLocation $pDbName $SQLcredential

				if($createDBSuccess -eq $true)
				{
					# Db has been successfully created so now set it up.
					Write-Success "Successfully created database '$pDbName' in server '$pDbServerName'."

					if($pDDLScripts)
					{
						$setupDBSuccess = SetupDatabase $pDbServerName $pDbName $pDbServerUsername $pDbServerPassword

						if ($setupDBSuccess -eq $true)
						{
							Write-Success "Successfully setup database '$pDbName' in server '$pDbServerName'."
						}
						else
						{
							Write-Error "Error :: Failed to setup database '$pDbName' in server '$pDbServerName'."
						}
					}
					else
					{
						Write-Warning "Warning :: No DDL scripts specified for database setup so this step did not execute."
					}
				}
				else
				{
					Write-Error "Error :: Failed to create database '$pDbName' in server '$pDbServerName'"
				}
			}
			else
			{
				Write-Error "Error :: Failed to create client firewall access rule for server '$pDbServerName'."
			}
		}
	}
}
catch [System.Exception]
{
	$errMessage = [string]::Format("Error :: Main execution failed with the following error:`n{0}", $error[0])
	Write-Error $errMessage
}

Write-Success "====================================="
Write-Success "End of script execution"
Write-Success "Elapsed time: $(New-Timespan –Start $startDateTime –End $(Get-Date -Format s))"
Write-Success "====================================="