
#include <iostream>
#include <string>
#include <map>

#include "DBHandler.h"
#include "ServerImpl.h"

int kThreads = 4;
int kPort = 50051;

std::map<std::string,std::string> parse_args(int argc, char** argv) {
    std::map<std::string, std::string> args;
    std::string key = "";
    for (int i=1; i<argc; i++) {
        if (i % 2 == 1) {
            key = argv[i];
        } else {
            args[key] = argv[i];
        }
    }
    return args;
}

void usage(char** argv) {
    std::cout << "Usage: " << argv[0] << " -db <path_to_db> [-p port_num] [-t num_threads]" << std::endl;
    std::cout << "\tDefault number of threads: " << kThreads << std::endl;
    std::cout << "\tDefault port number: " << kPort << std::endl;
}

int main(int argc, char** argv) {
    auto args = parse_args(argc, argv);

    if (args.count("-db") == 0) {
        usage(argv);
        exit(1);
    }

    if (args.count("-t") != 0) {
        kThreads = std::stoi(args["-t"]);
    }

    if (args.count("-p") != 0) {
        kPort = std::stoi(args["-p"]);
    }

    DBHandler db(args["-db"]);
    ServerImpl server;
    server.Run(db, kThreads, kPort);
    return 0;
}
