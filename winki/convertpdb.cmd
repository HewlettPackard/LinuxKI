@for /r %%i in (*.pdb) do .\pdbdump.exe "%%i" >%%~ni.txt
