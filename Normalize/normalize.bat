@echo off
rem --------------------------------------------------------------------------
rem Prejde vsetky podadresare a vykona normalizaciu zachytenych paketov.
rem Ponecha povodne subory a vytvori nove s predponou _
rem 
rem                                         Software (c) 2016, Zdeno Sekerak
rem --------------------------------------------------------------------------

rem Najdi subory .pap
for /F "delims=" %%i IN ('dir /s /b "*.cap"') do call :NormalizeIt %%i
exit

:NormalizeIt
	set var=%~n1:~0,1
	set var=%var:~0,1%

	if "%var%" equ "_" goto :eof

	@echo Spracuvavam %1
 	%~dp0GPRS_norm.exe %1
	goto :eof
