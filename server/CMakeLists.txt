
find_package (SQLite3)
include_directories(${SQLite3_INCLUDE_DIRS})

add_executable(server
        "main.cpp" DBHandler.cpp DBHandler.h ServerImpl.cpp ServerImpl.h GrpcMethods.cpp GrpcMethods.h)


target_link_libraries(server myproto)

target_link_libraries (server ${SQLite3_LIBRARIES})