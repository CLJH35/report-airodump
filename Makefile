CXX ?= g++
CPPFLAGS += -Iinclude $(shell pkg-config --cflags libpcap 2>/dev/null)
CXXFLAGS ?= -O2 -g -std=c++17 -Wall -Wextra -Wpedantic
LDLIBS += $(shell pkg-config --libs libpcap 2>/dev/null || echo -lpcap) -pthread

TARGET := airodump
SOURCES := src/main.cpp src/packet.cpp src/scanner.cpp
OBJECTS := $(SOURCES:.cpp=.o)
TEST_TARGET := parser_test
TEST_SOURCES := tests/parser_test.cpp src/packet.cpp src/scanner.cpp

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

src/%.o: src/%.cpp include/packet.hpp include/scanner.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(TEST_TARGET): $(TEST_SOURCES)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -pthread -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	$(RM) $(OBJECTS) $(TARGET) $(TEST_TARGET)
