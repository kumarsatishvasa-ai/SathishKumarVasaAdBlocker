@ECHO OFF

SET APP_HOME=%~dp0

IF "%JAVA_HOME%"=="" (
    SET JAVACMD=java.exe
) ELSE (
    SET JAVACMD=%JAVA_HOME%\bin\java.exe
)

"%JAVACMD%" -classpath "%APP_HOME%gradle\wrapper\gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain %*
