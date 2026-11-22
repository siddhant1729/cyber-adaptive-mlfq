# Cyber-Adaptive MLFQ — build file
#   make          build ./cmlfq
#   make test     build and run the unit tests
#   make run      run a full comparison on a generated mixed attack
#   make clean    remove build artefacts

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -pthread -Iinclude
LDFLAGS  := -pthread

SRC_DIR   := src
BUILD_DIR := build
TARGET    := cmlfq
TEST_BIN  := $(BUILD_DIR)/test_runner

SRCS      := $(wildcard $(SRC_DIR)/*.cpp)
LIB_SRCS  := $(filter-out $(SRC_DIR)/main.cpp,$(SRCS))
LIB_OBJS  := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(LIB_SRCS))
MAIN_OBJ  := $(BUILD_DIR)/main.o
TEST_OBJ  := $(BUILD_DIR)/test_main.o

.PHONY: all test run scenarios clean

all: $(TARGET)

$(TARGET): $(LIB_OBJS) $(MAIN_OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp $(wildcard include/*.h) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TEST_OBJ): tests/test_main.cpp $(wildcard include/*.h) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TEST_BIN): $(LIB_OBJS) $(TEST_OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^

test: $(TEST_BIN)
	./$(TEST_BIN)

run: $(TARGET)
	./$(TARGET) --generate --legit 50 --bots 200 --seed 42 --attack mixed --compare

scenarios: $(TARGET)
	./$(TARGET) --generate --legit 50 --bots 200 --seed 42 --scenarios

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(TARGET) results/*.csv
