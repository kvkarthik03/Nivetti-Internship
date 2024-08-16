cmake_minimum_required(VERSION 3.12)
project(test-app)

# Set C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS ON)

# Include FetchContent module to download dependencies
include(FetchContent)

# Fetch nlohmann/json library
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.2  # Specify a stable version or the latest version you want
)

FetchContent_MakeAvailable(json)

# Find PcapPlusPlus and OpenSSL
find_package(PcapPlusPlus REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Create executable
add_executable("${PROJECT_NAME}" detectMalware_15Aug2024.cpp)

# Set output directory to the same folder as the .cpp file (near the PCAP file)
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

# Link with PcapPlusPlus libraries
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)

# Link with OpenSSL libraries
target_link_libraries("${PROJECT_NAME}" PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Link with nlohmann::json (no need to explicitly link for header-only library, but for clarity)
target_link_libraries("${PROJECT_NAME}" PUBLIC nlohmann_json::nlohmann_json)

target_link_libraries("${PROJECT_NAME}" PUBLIC CURL::libcurl)
