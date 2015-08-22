# dec903
{903} password decoder - used in oc4j configuration files 

Oracle Webapp server OC4J store reversible passwords, encrypted with DES and a fixed key, in configuration files
(j2ee/home/config/system-jazn-data.xml).

dec903 decrypt these passwords. 

INSTALLATION : 
javac dec903.java

USAGE : 

java dec903 [OPTIONS]
	 -h help
	 -f file 		 use this hashes file
	 hash 			 including {903}


EXAMPLES : 

$ java dec903 {903}aaDNAx2b/w75niUWBXd3kDT8ntGFBEpQd0ocSeUfuX4=
oracle112      ({903}aaDNAx2b/w75niUWBXd3kDT8ntGFBEpQd0ocSeUfuX4=)

$ cat hashes.txt
{903}aaDNAx2b/w75niUWBXd3kDT8ntGFBEpQd0ocSeUfuX4=
{903}MpGLyRjOecImXViyEqELeodQcHNnvK1hjR/ybyAKbuA=

$ java dec903 -f hashes.txt
acle112      ({903}aaDNAx2b/w75niUWBXd3kDT8ntGFBEpQd0ocSeUfuX4=)
oracle112      ({903}MpGLyRjOecImXViyEqELeodQcHNnvK1hjR/ybyAKbuA=)



