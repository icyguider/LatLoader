WMIBOFNAME := ProcCreate
WRITEFILEBOFNAME := writefileBOF
CXX_x64 := x86_64-w64-mingw32-g++
CXX_x86 := i686-w64-mingw32-g++
CC_x64 := x86_64-w64-mingw32-gcc

all:
	mkdir -p bin
	$(CXX_x64) -o bin/$(WMIBOFNAME).x64.o -c src/wmiBOF.cpp -w
	$(CC_x64) -o bin/$(WRITEFILEBOFNAME).x64.o -c src/writefileBOF.c -w
	$(CC_x64) src/loader.c -static -w -s -Wl,-subsystem,windows -o bin/loader.exe
	$(CXX_x64) src/sideloader.cpp src/HWSyscalls.cpp src/cryptbase.def -static -s -w -shared -fpermissive -o bin/sideloader.dll
	rm -f bin/signed_sideloader.dll
	osslsigncode sign -pkcs12 src/cert_0.pfx -in bin/sideloader.dll -out bin/signed_sideloader.dll

sign:
	rm -f bin/signed_sideloader.dll
	osslsigncode sign -pkcs12 src/cert_0.pfx -in bin/sideloader.dll -out bin/signed_sideloader.dll

standalone:
	mkdir -p bin/standalone
	$(CXX_x64) src/standalone/wmiexec.cpp -I include -l oleaut32 -l ole32 -l wbemuuid -s -w -static -o bin/standalone/wmiexec.exe
	$(CC_x64) src/standalone/writefile.c -s -w -static -o bin/standalone/writefile.exe
