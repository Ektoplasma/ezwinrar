# ezwinrar
Python tool exploiting CVE-2018-20250 found by CheckPoint folks : https://research.checkpoint.com/extracting-code-execution-from-winrar/
> By crafting the filename field of the ACE format, the destination folder (extraction folder) is ignored, and the relative path in the filename field becomes an absolute Path. This logical bug, allows the extraction of a file to an arbitrary location which is effectively code execution.

### Usage:

`python3 ezwinrar.py /path/to/winace.exe` (default is `C:\Program File (x86)\WinAce\winace.exe`)

(1) User's startup folder:  
Since it is not possible to guess the name of the victime in advance (else use 3), the path will be like `..\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`   

(2) System startup folder:  
File will be in `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`. System privileges are required.

(3) Custom local location  

(4) SMB location [not implemented yet]  