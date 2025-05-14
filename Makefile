CXX      = g++
CXXFLAGS = -std=c++11 -O2 -Wall -Iinclude
LDFLAGS  = -lcrypto

# 如果只有这两个源文件，就直接写死
OBJS     = src/main.o src/aes_modes.o
TARGET   = e2aes

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# 生成 %.o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
