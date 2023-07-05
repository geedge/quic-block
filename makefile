CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lssl -lcrypto

TARGET = test
SRCS = quic_lfl.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
