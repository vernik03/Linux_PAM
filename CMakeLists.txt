cmake_minimum_required(VERSION 3.14.5)

set(CMAKE_CXX_STANDARD 20)

project(PamControlClient)
include(grpc_common.cmake)


get_filename_component(rg_proto "pam.proto" ABSOLUTE)
get_filename_component(rg_proto_path "${rg_proto}" PATH)

# Generated sources
set(rg_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/pam.pb.cc")
set(rg_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pam.pb.h")
set(rg_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/pam.grpc.pb.cc")
set(rg_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pam.grpc.pb.h")
add_custom_command(
        OUTPUT "${rg_proto_srcs}" "${rg_proto_hdrs}" "${rg_grpc_srcs}" "${rg_grpc_hdrs}"
        COMMAND ${_PROTOBUF_PROTOC}
        ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${rg_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${rg_proto}"
        DEPENDS "${rg_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# rg_grpc_proto
add_library(rg_grpc_proto
        ${rg_grpc_srcs}
        ${rg_grpc_hdrs}
        ${rg_proto_srcs}
        ${rg_proto_hdrs})
target_link_libraries(rg_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF})

find_package (SQLite3)
include_directories(${SQLite3_INCLUDE_DIRS})
find_package(Boost COMPONENTS system filesystem REQUIRED)

# Targets (client|server)
add_executable(client "client/main.cpp")
target_link_libraries(client
        rg_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF}
        ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY})

add_executable(server
        "server/main.cpp" server/DBHandler.cpp server/DBHandler.h server/ServerImpl.cpp server/ServerImpl.h server/GrpcMethods.cpp server/GrpcMethods.h)
target_link_libraries(server
        rg_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF})
target_link_libraries (server ${SQLite3_LIBRARIES})