# card42 Java toolchain.
#
# Override with e.g. make JAVA_HOME=/path/to/jdk (must be a full JDK, i.e.
# contain bin/javac).

JAVA_HOME     ?= /usr/lib/jvm/java-21-openjdk
JAVA          ?= $(JAVA_HOME)/bin/java
JAVAC         ?= $(JAVA_HOME)/bin/javac
JAR           ?= $(JAVA_HOME)/bin/jar
JAVAC_RELEASE ?= 8
