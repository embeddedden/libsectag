CXX = g++
CXXFLAGS = -Wall -Wpedantic -Werror -Wextra -std=c++14

all: 
	$(CXX) $(CXXFLAGS) main.cpp -L.. -lsectag -lselinux -I../ -o main
clean:
	rm main
