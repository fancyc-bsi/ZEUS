if exist "%USERPROFILE%\ZAP\.ZAP_JVM.properties" (
	set /p jvmopts=< "%USERPROFILE%\ZAP\.ZAP_JVM.properties"
) else (
	set jvmopts=-Xmx512m
)

java %jvmopts% -jar zap-2.14.0.jar %*
