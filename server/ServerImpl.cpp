//
// Created by robotknik on 18.07.22.
//

#include "ServerImpl.h"


void ServerImpl::Run(DBHandler &db, int num_threads, int port) {
    std::string server_address("0.0.0.0:" + std::to_string(port));

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    builder.RegisterService(&service_);
    cq_ = builder.AddCompletionQueue();
    server_ = builder.BuildAndStart();

    std::cout << "Server listening on " << server_address << std::endl;

    // Create pool of threads, each handle requests to server
    std::vector<std::thread> pool;
    std::shared_ptr<DBHandler> db_ptr(&db);
    std::shared_ptr<TokenHandler> tokenh(new TokenHandler);

    pool.reserve(num_threads);
    for (int i=0; i<num_threads; i++) {
        pool.emplace_back(&ServerImpl::HandleRpcs, this, db_ptr, tokenh);
    }

    std::cout << "Started server, waiting for connection" << std::endl;

    for (auto& thr : pool) {
        thr.join();
    }
}


void ServerImpl::HandleRpcs(std::shared_ptr<DBHandler> db_ptr, std::shared_ptr<TokenHandler> tokenh) {
    // Spawn a new CallData instance to serve new clients.
    new GetSecretCall(db_ptr, &service_, cq_.get());
    new GetSecretListCall(db_ptr, &service_, cq_.get());
    new AuthoriseCall(db_ptr, &service_, cq_.get(), tokenh);
    new RemoveSecretCall(db_ptr, &service_, cq_.get(), tokenh);
    new AddSecretCall(db_ptr, &service_, cq_.get(), tokenh);
    new EditSecretCall(db_ptr, &service_, cq_.get(), tokenh);
    new GetAllSecretsCall(db_ptr, &service_, cq_.get(), tokenh);
    new GetAllUsersCall(db_ptr, &service_, cq_.get(), tokenh);
    new ShareSecretCall(db_ptr, &service_, cq_.get(), tokenh);
    new DenySecretCall(db_ptr, &service_, cq_.get(), tokenh);
    new IsUserExistsCall(db_ptr, &service_, cq_.get(), tokenh);

    void* tag;  // uniquely identifies a request.
    bool ok;
    while (true) {
        // Block waiting to read the next event from the completion queue. The
        // event is uniquely identified by its tag, which in this case is the
        // memory address of a CallData instance.
        // The return value of Next should always be checked. This return value
        // tells us whether there is any kind of event or cq_ is shutting down.
        GPR_ASSERT(cq_->Next(&tag, &ok));
        GPR_ASSERT(ok);
        static_cast<CallData*>(tag)->Proceed();
    }
}

