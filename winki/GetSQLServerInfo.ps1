# --------------------------------------------------------------------------------------
# The script is gathering configuration information from all locally  installed
# SQL-Server instance to support the KI trace analysis on Windows Server OS. The script
# is part of the HPE WinKI project and distribution. 
#
# © Copyright 2021 Hewlett Packard Enterprise Development LP
# 
# Author  : Lars Berger (lars.berger@hpe.com)
# Version :  
#    0.71 - initial setup
#    0.72 - adding new file output (csv wo quotes ) ,  new script parameter
#    0.73 - adding copyright
#    0.74 - adding try catch
#    0.75 - added Wait and Spin Stats (Mark Ray)
#    0.76 - changed extensions from .out to .csv or .txt, which ever is more appropriate
# --------------------------------------------------------------------------------------


# Must be the first statement in your script 
# get parameter from  command line
param([String]$DateStr='') 

# get current hostname
$computerName = [System.Net.Dns]::GetHostName()


# gather all installed and running instances
$sqlInstances = Get-Itemproperty -path 'HKLM:\software\microsoft\Microsoft SQL Server' | Select-Object -expandproperty InstalledInstances
$sqlInstances_cnt = $sqlInstances|measure | Select-Object -expandproperty Count
if ($sqlInstances_cnt -eq 0)
{
  Write-Host "No SQL Instances were detected on the server - Exit processing" -ForegroundColor Yellow
  Exit 
} 

Write-Host "$sqlInstances_cnt SQL Instance(s) were detected on the server - Start data gathering" -ForegroundColor Green

# dump out which kind of instance with the PID
# globales
# 1 file with all SQL-Instances and reponding services with PID - Instance Overview_PID
# per Instance
# 1 file per Instance <Instance>_<PID>_Threadlist_<Timestamp>.txt
# Timestamp: mmdd_HHMM (Problems with locales)
# 
# loop over all SQL instances 

# create time stamp for file names, when nothing set via param
if ($DateStr -eq '')
{
  $Date = Get-Date
  $DateStr = $Date.ToString("MMdd_HHmm")
}


# create output file name
$instance_overview_pid = 'SQL_InstanceOverview_PID_' + $DateStr + '.txt'

# create output file for overview thread list
$SQLThreadList = 'SQLThreadList' + '.' + $DateStr

# create collection to store SQL INSTANCE with PID
$collectionInstance = New-Object System.Collections.ArrayList

# loop over all SQL instances 
ForEach($sqlInstance in $sqlInstances)
{
  Write-Host "The following SQL Instances were detected on the server $env:Computername $SQLInstance" -ForegroundColor Yellow
  $temp = New-Object System.Object
  If ($SQLInstance -ne "MSSQLSERVER") { 
    # concatenate the instance name for connection 
    $sqlInstanceName = ".\" + $sqlInstance
  } 
  Else 
  { Write-Host "Standard SQL Instance was found, proceeding with the script."
    # concatenate the instance name for connection
    $sqlInstanceName = "."
  }
  
  try {
  # gather PID of SQL-Server service and insert into file
  Write-Host "SQL-Instance $sqlInstanceName : Process ID and Service Name" -ForegroundColor Green
  Invoke-Sqlcmd -Query "SELECT ServiceName, status_desc,process_id, last_startup_time, service_account FROM sys.dm_server_services" -ServerInstance $sqlInstanceName -verbose | Out-File $instance_overview_pid -Append


  # gather PID and TID of SQL-Server service and insert into file for WINKI
  Write-Host "SQL-Instance $sqlInstanceName : Process , Threads ID and Command" -ForegroundColor Green
  Invoke-Sqlcmd -Query "select SERVERPROPERTY('ProcessID') as PID, SERVERPROPERTY('InstanceName') as INSTANCE , p.kpid as TID, p.cmd as CMD  from sys.dm_os_tasks t JOIN sys.dm_os_schedulers s on s.scheduler_id = t.scheduler_id 
                       JOIN sys.sysprocesses p on p.spid = t.session_id" -ServerInstance $sqlInstanceName | export-csv -verbose -path .\$SQLThreadList -Append -notypeinformation 
  # remove " double quotes from output text file
  (Get-Content $SQLThreadList) | Foreach-Object {$_ -replace '"', ''}|Out-File $SQLThreadList

  # get process id for current instance
  $processID = Invoke-Sqlcmd -Query "select SERVERPROPERTY('processid') as processid" -ServerInstance $sqlInstanceName -verbose 
  # temporary save all instance values for furhter process (Instance Name, Intance Name for connection, process id)
  $temp | Add-Member -MemberType NoteProperty -Name "SQL_INSTANCE" -Value $sqlInstance
  $temp | Add-Member -MemberType NoteProperty -Name "SQL_INSTANCE_NAME" -Value $sqlInstanceName
  $temp | Add-Member -MemberType NoteProperty -Name "SQL_PID" -Value $processID.processid
  $collectionInstance.Add($temp) | Out-Null
  } catch {
    Write-Host($error) -ForegroundColor RED
  }


  
}

# loop over all SQL-Instances for detailed informations
$collectionInstance | foreach-Object {

  $sqlInstanceName = $_.SQL_INSTANCE_NAME
  $sqlProcessID = $_.SQL_PID
  $sqlInstanceShort =  $_.SQL_INSTANCE

  Write-Host "The discovery and information gathering is executed on SQL-Instance $sqlInstanceShort" -ForegroundColor Yellow

  # --------------------------------------------------------------------------------------------
  # gather version and setup information
  Write-Host "SQL-Instance $sqlInstanceName : Version and Config" -ForegroundColor Green
  $instance_version = 'SQL_' + $sqlInstanceShort + '_' + $sqlProcessID + '_Version_' + $DateStr + '.csv'   # create output file name

  try {
	  $out_version = Invoke-Sqlcmd -Query "SELECT	
			SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS [Current Node Name],
			SERVERPROPERTY('ServerName') AS [Instance Name],
			SERVERPROPERTY('ProductVersion') AS [ProductVersion],
			SERVERPROPERTY ('Edition') AS [Edition],
			SERVERPROPERTY('ProductLevel') AS [Service Pack],
			SERVERPROPERTY('IsIntegratedSecurityOnly') AS [Server Authentication],
			SERVERPROPERTY('IsClustered') AS [IsClustered],
			[cpu_count] AS [CPUs],
			[physical_memory_kb]/1024 AS [RAM (MB)]
		FROM	
			[sys].[dm_os_sys_info]" -ServerInstance $sqlInstanceName 
	  $out_version | Format-Table | Out-File $instance_version

	  # gather OS Memory usage for SQL-Server Instance / Process
	  Write-Host "SQL-Instance $sqlInstanceName : OS Memory usage for SQL-Server Instance / Process" -ForegroundColor Green
	  $instance_procmem = 'SQL_' + $sqlInstanceShort + '_' + $sqlProcessID + '_ProcMem_' + $DateStr + '.csv'   # create output file name
	  Invoke-Sqlcmd -Query "select * from sys.dm_os_process_memory" -ServerInstance $sqlInstanceName -verbose | export-csv -verbose $instance_procmem -notypeinformation
	  
	  # gather OS Memory Node(NUMA) configuration (sys.dm_os_memory_nodes)
	  Write-Host "SQL-Instance $sqlInstanceName : OS Memory Node(NUMA) configuration" -ForegroundColor Green
	  $instance_nodemem = 'SQL_' + $sqlInstanceShort + '_' + $sqlProcessID + '_NodeMem_' + $DateStr + '.csv'   # create output file name
	  Invoke-Sqlcmd -Query "select * from sys.dm_os_memory_nodes" -ServerInstance $sqlInstanceName -verbose | export-csv -verbose $instance_nodemem -notypeinformation

	  # gather thread information for SQL-Server scheduler, worker and threads
	  Write-Host "SQL-Instance $sqlInstanceName : OS thread information for SQL-Server scheduler, worker and threads" -ForegroundColor Green
	  $instance_threadlist = 'SQL_' + $sqlInstanceShort + '_' + $sqlProcessID + '_ThreadList_' + $DateStr + '.csv'   # create output file name
	  Invoke-Sqlcmd -Query "select p.kpid, p.cmd, s.*  from sys.dm_os_tasks t JOIN sys.dm_os_schedulers s on s.scheduler_id = t.scheduler_id 
		JOIN sys.sysprocesses p on p.spid = t.session_id" -ServerInstance $sqlInstanceName -verbose | export-csv -verbose $instance_threadlist -notypeinformation

      # gather  SQL-Server Wait statistics
      $instance_waitstats = 'SQL_' + $sqlInstanceShort + '_' + $sqlProcessID + '_WaitStats_' + $DateStr + '.csv'   # create output file name
      Write-Host "SQL-Instance $sqlInstanceName Wait Statistics"
      Invoke-Sqlcmd -InputFile ".\wait.sql" | export-csv -verbose $instance_waitstats -notypeinformation

      # gather  SQL-Server Spin statistics
      $instance_spinstats = 'SQL_' + $sqlInstanceShort + '_' + $sqlProcessID + '_SpinStats_' + $DateStr + '.csv'   # create output file name
      Write-Host "SQL-Instance $sqlInstanceName Spin Statistics"
      Invoke-Sqlcmd -InputFile ".\spin.sql" | export-csv -verbose $instance_spinstats -notypeinformation

  }  catch {
     Write-Host($error) -ForegroundColor RED
  } 
}

# end of the loops
