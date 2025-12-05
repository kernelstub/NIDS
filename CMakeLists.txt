cmake_minimum_required(VERSION 3.15)
project(NetIntrusionSys VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Add compiler warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find required packages
find_package(PcapPlusPlus REQUIRED)
find_package(spdlog REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(GTest REQUIRED)

# Add subdirectories
add_subdirectory(src)
add_subdirectory(tests)

# Create main executable
add_executable(${PROJECT_NAME} src/main.cpp)

# Link libraries
target_link_libraries(${PROJECT_NAME}
    PRIVATE
    PcapPlusPlus::PcapPlusPlus
    spdlog::spdlog
    nlohmann_json::nlohmann_json
)

# Install targets
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Install configuration files
install(FILES
    ${CMAKE_SOURCE_DIR}/config/nids_config.json
    DESTINATION etc/${PROJECT_NAME}
)
