@echo off
REM #**************************************************************************
REM # Copyright 2020 Hewlett Packard Enterprise Development LP.
REM # This program is free software; you can redistribute it and/or modify
REM # it under the terms of the GNU General Public License as published by
REM # the Free Software Foundation; either version 2 of the License, or (at
REM # your option) any later version. This program is distributed in the
REM # hope that it will be useful, but WITHOUT ANY WARRANTY; without even
REM # the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
REM # PURPOSE. See the GNU General Public License for more details. You
REM # should have received a copy of the GNU General Public License along
REM # with this program; if not, write to the Free Software Foundation,
REM # Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
REM #***************************************************************************
REM # runki script  -- captures WinKI trace data (ETL)
@echo ** runki for Windows $Date: 2021/11/09 $Revision: 7.2	 **

REM # Buf size is 2GB by default (2048).   Increase for large systems (>=64 cores) or very active systems.
REM # You can also reduce the timeout value to have a better change of avoiding missing trace events.
set bufsz=2048

set tmo=20
if [%1] NEQ [] set tmo=%1
if [%tmo%] EQU [0] set tmo=20

for /F %%A in ('wmic os get LocalDateTime ^| find "."') do set tag1=%%A
set tag=%tag1:~4,4%_%tag1:~8,4%

@echo ** runki for Windows $Date: 2021/11/09 $Revision: 7.2 ** >ki.err.%tag%
tasklist >tasklist.%tag%
xperf -on Latency+PROC_THREAD+POWER+LOADER+CSWITCH+DISPATCHER+DISK_IO+DISK_IO_INIT+PROFILE+FILENAME+FILE_IO+FILE_IO_INIT+DPC+Interrupt+NETWORK+SYSCALL+SPINLOCK -stackwalk CSwitch+Profile+ReadyThread -BufferSize %bufsz% -MaxBuffers %bufsz% -MaxFile %bufsz% -FileMode Circular && timeout %tmo%
if [%errorlevel%] NEQ [0] goto error

@echo:
@echo Dumping to ki.%tag%.etl...
@echo Dumping to ki.%tag%.etl... >>ki.err.%tag%
xperf -d ki.%tag%.etl

@echo: 
@echo xperf collection complete.  Collecting system information...
@echo xperf collection complete.  Collecting system information... >>ki.err.%tag%
systeminfo >systeminfo.%tag%
wmic cpu list brief >cpulist.%tag%
wmic cpu get SocketDesignation, NumberOfCores, NumberOfLogicalProcessors /Format:List >corelist.%tag%

if exist "./GetSQLServerInfo.ps1" ( 
	@echo Collecting SQL Instance information ....
	powershell -NoLogo -ExecutionPolicy Bypass -Command "./GetSQLServerInfo.ps1 -DateStr %tag%" >>ki.err.%tag%
)

@echo Compessing files to ki_all.%computername%.%tag%.zip using Powershell.  Please wait...
@echo Compessing files to ki_all.%computername%.%tag%.zip using Powershell.  >> ki.err.%tag%
powershell "Compress-Archive *%tag%* ki_all.%computername%.%tag%.zip
if [%errorlevel%] NEQ [0] goto error
del *.%tag% ki.%tag%.etl SQL*%tag%.out

@echo:  
@echo ** Please collect the ki_all.%computername%.%tag%.zip and analyze using LinuxKI on a Linux server
@echo ** You may also extract the ETL file from the ZIP and analyze with WPA or PerfView.
@echo ** (note if runki is executed directly with "Run as Administrator", 
@echo ** the file may be in c:/Windows/System32 or the Administrator home directory)
goto end

:error
echo "error %errorlevel%!!!"
echo "error %errorlevel%!!!" >>ki.err.%tag%
del corelist.%tag% cpulist.%tag% systeminfo.%tag% tasklist.%tag% ki.%tag%.etl SQL*%tag%.out

:end
