//
// Created by robotknik on 18.07.22.
//

#ifndef PAMCONTROLCLIENT_SERVERIMPL_H
#define PAMCONTROLCLIENT_SERVERIMPL_H

#include <thread>
#include <utility>
#include <vector>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>

#include "pam.grpc.pb.h"
#include "DBHandler.h"
#include "GrpcMethods.h"

using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;

using helloworld::PAM;


class ServerImpl final {
public:
    ~ServerImpl() {
        server_->Shutdown();
        cq_->Shutdown();
    }

    void Run(DBHandler &db, int num_threads, int port);

private:


    // This can be run in multiple threads if needed.
    void HandleRpcs(std::shared_ptr<DBHandler> db_ptr, std::shared_ptr<TokenHandler> tokenh);

    std::unique_ptr<ServerCompletionQueue> cq_;
    PAM::AsyncService service_;
    std::unique_ptr<Server> server_;
};


#endif //PAMCONTROLCLIENT_SERVERIMPL_H
