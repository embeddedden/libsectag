CXX = g++
CXXFLAGS = -Wall -Wpedantic -Werror -Wextra -std=c++14

SUBDIRS = tests

SUBCLEAN = $(addsuffix .clean,$(SUBDIRS))

all: libsectag tests

libsectag:
	$(CXX) $(CXXFLAGS) -c SecurityTags.cpp && ar rc libsectag.a SecurityTags.o

$(SUBDIRS): libsectag
	$(MAKE) -C $@

clean: $(SUBCLEAN)
	rm -f *.o *.a

$(SUBCLEAN): %.clean:
	$(MAKE) -C $* clean
