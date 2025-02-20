@echo off
setlocal enabledelayedexpansion

set "watchDir=C:\Users\User\Desktop\WatchDir"
set "destDir=C:\Users\User\Desktop\DestDir" 
set "pythonScript=C:\Users\User\Desktop\test\func_script\MA_DA.py"

set "flagFile=processing.flag"

set "ignoreDir=%watchDir%\ignored"

if not exist "%ignoreDir%" mkdir "%ignoreDir%"

:monitor
if exist "%flagFile%" (
    timeout /t 2 >nul
    goto monitor
)

for /f "delims=" %%F in ('dir /b /a-d "%watchDir%" 2^>nul') do (
    echo Processing > "%flagFile%"
    
    set "fileToProcess=%%F"
    
    move "%watchDir%\!fileToProcess!" "%destDir%" >nul
    
    set "fileFullPath=%destDir%\!fileToProcess!"
    
    python "%pythonScript%" "!fileFullPath!"
    
    del "%flagFile%"
    
    for /f "delims=" %%G in ('dir /b /a-d "%watchDir%" 2^>nul') do (
         move "%watchDir%\%%G" "%ignoreDir%" >nul
    )
    
    goto monitor
)

timeout /t 2 >nul
goto monitor
