PatchPae (v2) by wj32.
Tested on: Windows Vista SP2, Windows 7 SP0, Windows 7 SP1, Windows 8, Windows 8.1, Windows 10 (build 10586)

== Installation ==
1.  Open an elevated Command Prompt window.

2.  cd C:\Windows\system32.
    Make sure the current directory is in fact system32.

[[ For Windows 8, Windows 8.1 and Windows 10: ]]
3.  C:\WherePatchPaeIs\PatchPae2.exe -type kernel -o ntoskrnx.exe ntoskrnl.exe
    This will patch the kernel to enable a maximum of 128GB of RAM.
[[ For Windows Vista and Windows 7: ]]
3.  C:\WherePatchPaeIs\PatchPae2.exe -type kernel -o ntkrnlpx.exe ntkrnlpa.exe
    This will patch the kernel to enable a maximum of 128GB of RAM.

4.  C:\WherePatchPaeIs\PatchPae2.exe -type loader -o winloadp.exe winload.exe
    This will patch the loader to disable signature verification.

5.  bcdedit /copy {current} /d "Windows (PAE Patched)"
    This will create a new boot entry. A message should appear:
    The entry was successfully copied to {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.

[[ For Windows 8, Windows 8.1 and Windows 10: ]]
6.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} kernel ntoskrnx.exe
    This will set our boot entry to load our patched kernel.
[[ For Windows Vista and Windows 7: ]]
6.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} kernel ntkrnlpx.exe
    This will set our boot entry to load our patched kernel.

7.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} path \Windows\system32\winloadp.exe
    This will set our loader to be our patched loader.

8.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} nointegritychecks 1
    This will disable verification of the loader.

9.  bcdedit /set {bootmgr} default {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
    This will set our boot entry to be the default.

10. bcdedit /set {bootmgr} timeout 2
    This will set the timeout to be shorter.
    Note: you can change this timeout to whatever you like.

11. Restart the computer and enjoy.

== Removal ==
To remove the patch:
 * Run msconfig, click Boot, highlight the entry named "Windows (PAE Patched)", and click Delete.
 * Delete the files ntoskrnx.exe (or ntkrnlpx.exe) and winloadp.exe from C:\Windows\system32.

== Updates ==
When Windows Update installs new updates on your computer, you should run Step 3 again to ensure
that you have the latest version of the kernel.

== Compiling ==
To compile PatchPae2, you need to get Process Hacker and build it.
The directory structure should look like this:
 * ...\ProcessHacker2\lib\...
 * ...\ProcessHacker2\phlib\...
 * ...\src\PatchPae2.sln
