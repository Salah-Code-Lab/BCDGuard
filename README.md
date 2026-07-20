## BCDGuard

This driver protects the Boot Configuration Data from Writes and Deletions
as a File System Filter 

# Note 
You must add to your solution FltMgr.lib 

otherwise it won't compile at least from my testing

the default path is: 

C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\km\x64\FltMgr.lib


# Additional:
You can edit the UNICODE string manually to protect anything else but i don't guarentee that it may work






> io web: https://salah-code-lab.github.io/BCDGuard/
> 
