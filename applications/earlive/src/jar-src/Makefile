JAR=jar
RM=rm -rf
JARFLAGS=cvfm
JARNAME=../../www_files/earlive-0.2.jar
JC=javac
JFLAGS=-cp ../../www_files/jchart2d-2.0.1.jar:earlive -source 1.4 -target 1.4
JAVASRC=earlive/*.java
CLASSES=$(JAVASRC:.java=.class)

all: rm-jar jar

jar: classes
	$(JAR) $(JARFLAGS) $(JARNAME) MANIFEST.MF earlive/ 
	
classes:
	$(JC) $(JFLAGS) $(JAVASRC)

rm-jar:
	$(RM) ../../www_files/earlive-0.2.jar

