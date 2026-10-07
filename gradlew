#!/bin/sh

#
# Copyright © 2015-2021 the original authors.
#
# Licensed under the Apache License, Version 2.0
#

APP_HOME=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar

if [ -n "$JAVA_HOME" ]; then
    JAVACMD="$JAVA_HOME/bin/java"
else
    JAVACMD="java"
fi

if [ ! -x "$JAVACMD" ]; then
    echo "ERROR: JAVA_HOME is not set correctly."
    exit 1
fi

exec "$JAVACMD" \
    -classpath "$CLASSPATH" \
    org.gradle.wrapper.GradleWrapperMain "$@"
