CXX = g++
CXXFLAGS = -O2 -Wall -g -std=c++17
LDLIBS = -lpcap

TARGET = tcp-block
OBJS = main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJS)
