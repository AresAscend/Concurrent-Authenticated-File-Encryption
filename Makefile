CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Wpedantic -pthread -I.
LDFLAGS = -framework Security

TARGET = encrypt_decrypt
SRC = main.cpp \
      src/app/processes/ProcessManagement.cpp \
      src/app/encryptDecrypt/Cryption.cpp
OBJ = $(SRC:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) $(LDFLAGS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
