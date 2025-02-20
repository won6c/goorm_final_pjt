@echo off
setlocal enabledelayedexpansion

rem === 환경 설정 ===
set "watchDir=C:\Users\User\Desktop\WatchDir"         :: 감시할 폴더 (파일 생성/이동 감지 대상)
set "destDir=C:\Users\User\Desktop\DestDir"           :: 파일을 전송할 폴더
set "pythonScript=C:\Users\User\Desktop\test\func_script\MA_DA.py"  :: 실행할 파이썬 스크립트 경로

:: 처리 중임을 표시할 임시 파일
set "flagFile=processing.flag"

:: 파이썬 스크립트 동작 중 생성된 새 파일들을 보관할 폴더 (미처리 대상)
set "ignoreDir=%watchDir%\ignored"

:: ignoreDir이 없으면 생성
if not exist "%ignoreDir%" mkdir "%ignoreDir%"

:monitor
rem --- 파이썬 스크립트가 실행 중이면 (flagFile 존재) ---
if exist "%flagFile%" (
    timeout /t 2 >nul
    goto monitor
)

rem --- watchDir에 처리할 파일이 있는지 확인 (폴더 내 파일만 대상) ---
for /f "delims=" %%F in ('dir /b /a-d "%watchDir%" 2^>nul') do (
    rem 처리 시작을 알리기 위해 flagFile 생성
    echo Processing > "%flagFile%"
    
    rem 처리할 파일명 저장 (첫번째로 발견된 파일)
    set "fileToProcess=%%F"
    
    rem 파일을 destDir로 이동
    move "%watchDir%\!fileToProcess!" "%destDir%" >nul
    
    rem 이동된 파일의 절대 경로 생성
    set "fileFullPath=%destDir%\!fileToProcess!"
    
    rem 파이썬 스크립트를 인자로 절대 경로 전달하여 실행 (실행 완료까지 대기)
    python "%pythonScript%" "!fileFullPath!"
    
    rem 파이썬 스크립트 종료 후 flagFile 삭제
    del "%flagFile%"
    
    rem --- 파이썬 스크립트 동작 중 생성된 파일들 무시 처리 ---
    for /f "delims=" %%G in ('dir /b /a-d "%watchDir%" 2^>nul') do (
         move "%watchDir%\%%G" "%ignoreDir%" >nul
    )
    
    goto monitor
)

timeout /t 2 >nul
goto monitor
