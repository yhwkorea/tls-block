CXX       = g++
CXXFLAGS  = -O2 -Wall -g -std=c++17
LDLIBS    = -lpcap

TARGET    = tls-block
OBJS      = tls-block.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

tls_block.o: tls_block.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJS)
