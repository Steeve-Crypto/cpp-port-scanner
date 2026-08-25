CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
TARGET   = portscan
SRC      = main.cpp

.PHONY: all clean debug install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

debug: CXXFLAGS = -std=c++17 -Wall -Wextra -g -O0 -pthread
debug: $(TARGET)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
