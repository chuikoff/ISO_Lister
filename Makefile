# IsoLister — MinGW build (box / Linux cross-compile). MSVC: IsoLister.sln.
#   make            plugin .wlx/.wlx64, standalone CLI, test host
#   make test       run the CLI on test fixtures under Wine (FIXTURES=dir)
#   make dist       dist_box/ISO_Lister_v<VERSION>.zip
CXX32 = i686-w64-mingw32-g++
CXX64 = x86_64-w64-mingw32-g++
WINDRES32 ?= i686-w64-mingw32-windres
WINDRES64 ?= x86_64-w64-mingw32-windres
CXXFLAGS = -std=c++17 -O2 -Wall -Wno-unused-variable -Wno-unused-function -Wno-sign-compare \
           -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -finput-charset=UTF-8
LDFLAGS = -static -static-libgcc -static-libstdc++ -s
LIBS = -lgdiplus -lgdi32 -luser32
B = build
VERSION = $(shell tr -d ' \r\n' < VERSION)
SRC = IsoLister.cpp IsoModel.cpp IsoView.cpp IsoPlugin.cpp
HDRS = IsoAnalysis.h IsoModel.h IsoView.h listplug.h version_auto.h

all: $(B)/IsoLister.wlx $(B)/IsoLister.wlx64 $(B)/IsoListerTest.exe $(B)/testhost.exe $(B)/testhost32.exe

$(B):
	mkdir -p $(B)

# regenerated on every build, like the MSVC pre-build step
version_auto.h: FORCE
	sh tools/gen_version.sh . >/dev/null

$(B)/IsoLister32.res.o: IsoLister.rc version_auto.h | $(B)
	$(WINDRES32) -I. -O coff -i IsoLister.rc -o $@

$(B)/IsoLister64.res.o: IsoLister.rc version_auto.h | $(B)
	$(WINDRES64) -I. -O coff -i IsoLister.rc -o $@

$(B)/IsoLister.wlx: $(SRC) $(HDRS) $(B)/IsoLister32.res.o | $(B)
	$(CXX32) $(CXXFLAGS) -I. -shared -o $@ $(SRC) $(B)/IsoLister32.res.o -Wl,--kill-at $(LDFLAGS) $(LIBS)

$(B)/IsoLister.wlx64: $(SRC) $(HDRS) $(B)/IsoLister64.res.o | $(B)
	$(CXX64) $(CXXFLAGS) -I. -shared -o $@ $(SRC) $(B)/IsoLister64.res.o $(LDFLAGS) $(LIBS)

# standalone report CLI (same as test/build_standalone.bat)
$(B)/IsoListerTest.exe: IsoLister.cpp $(HDRS) | $(B)
	$(CXX64) $(CXXFLAGS) -I. -municode -DISO_LISTER_STANDALONE -o $@ IsoLister.cpp $(LDFLAGS) -lgdi32 -luser32

$(B)/testhost.exe: tools/testhost.cpp | $(B)
	$(CXX64) $(CXXFLAGS) -municode -o $@ tools/testhost.cpp $(LDFLAGS) -lgdi32 -luser32

$(B)/testhost32.exe: tools/testhost.cpp | $(B)
	$(CXX32) $(CXXFLAGS) -municode -o $@ tools/testhost.cpp $(LDFLAGS) -lgdi32 -luser32

FIXTURES ?= test/fixtures
test: $(B)/IsoListerTest.exe
	bash tools/run_fixtures.sh $(B)/IsoListerTest.exe $(FIXTURES)

dist: $(B)/IsoLister.wlx $(B)/IsoLister.wlx64
	rm -rf $(B)/stage && mkdir -p $(B)/stage dist_box
	cp $(B)/IsoLister.wlx $(B)/IsoLister.wlx64 README.md LICENSE $(B)/stage/
	iconv -f UTF-8 -t CP1251 installer/pluginst.inf > $(B)/stage/pluginst.inf
	rm -f dist_box/ISO_Lister_v$(VERSION).zip
	cd $(B)/stage && zip -9 -q -X ../../dist_box/ISO_Lister_v$(VERSION).zip pluginst.inf IsoLister.wlx IsoLister.wlx64 README.md LICENSE

clean:
	rm -rf $(B)

FORCE:
.PHONY: all test dist clean FORCE
