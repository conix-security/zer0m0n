bcdedit /set TESTSIGNING ON
bcdedit /debug ON
bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200 /start AUTOENABLE /noumex
bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS
bcdedit.exe /set {current} nx AlwaysOff
