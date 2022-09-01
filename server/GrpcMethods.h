//
// Created by robotknik on 21.07.22.
//

#ifndef PAMCONTROLCLIENT_GRPCMETHODS_H
#define PAMCONTROLCLIENT_GRPCMETHODS_H

#include <vector>
#include <memory>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <shared_mutex>
#include <random>

#include "pam.grpc.pb.h"
#include "DBHandler.h"

using grpc::ServerAsyncResponseWriter;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;
using grpc::Status;

using helloworld::PAM;
using helloworld::Secret;
using helloworld::RequestedSecret;
using helloworld::UserData;
using helloworld::SecretList;
using helloworld::Token;
using helloworld::AuthData;
using helloworld::SecretAdmin;
using helloworld::UpdatedSecret;
using helloworld::SecretAdminList;
using helloworld::UserRoles;
using helloworld::Empty;
using helloworld::UserDataList;
using helloworld::ErrorCode;

inline std::string type_to_str(helloworld::SecretType type);

class TokenHandler {
public:
    // TODO: method to cleanup expired tokens
    std::string generateToken(const std::string& user);
    // Get user_id associated with token
    // On failure returns -1
    std::string getUser(const std::string &token);
private:
    class token_s {
    public:
        std::string user;
        std::string token;
    };

    bool isUsed(const std::string& token) const;

    std::shared_mutex mutex_;
    std::vector<token_s> tokens_;
};

// Abstract class for processing requests
class CallData {
public:
    CallData() = default;

    // Spawn new instance of child class and handle request in status_ == PROCESS
    // if status_ == FINISH then deallocate himself
    virtual void Proceed() = 0;

    // states for tiny state machine.
    enum CallStatus { CREATE, PROCESS, FINISH };

    // The means of communication with the gRPC runtime for an asynchronous server.
    PAM::AsyncService* service_;

    // Context for the rpc, allowing to tweak aspects of it such as the use
    // of compression, authentication, as well as to send metadata back to the
    // client.
    ServerContext ctx_;
    CallStatus status_;
};

class GetSecretCall: public CallData {
public:
    GetSecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService* service, ServerCompletionQueue* cq);

    void Proceed() override;
private:
    // The producer-consumer queue where for asynchronous server notifications.
    ServerCompletionQueue* cq_;

    RequestedSecret request_;
    Secret reply_;
    // Use async io to send reply_ to the client
    ServerAsyncResponseWriter<Secret> responder_;
    std::shared_ptr<DBHandler> db_;
};

class GetSecretListCall: public CallData {
public:
    GetSecretListCall(std::shared_ptr<DBHandler> db, PAM::AsyncService* service, ServerCompletionQueue* cq);

    void Proceed() override;
private:
    UserData request_;
    SecretList reply_;
    ServerAsyncResponseWriter<SecretList> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<DBHandler> db_;
};

class AuthoriseCall: public CallData {
public:
    AuthoriseCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                  std::shared_ptr<TokenHandler> &tokenh);

    void Proceed() override;
private:
    AuthData request_;
    Token reply_;
    ServerAsyncResponseWriter<Token> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class RemoveSecretCall: public CallData {
public:
    RemoveSecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                     std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    Secret request_;
    Secret reply_;
    ServerAsyncResponseWriter<Secret> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class AddSecretCall: public CallData {
public:
    AddSecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                     std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    Secret request_;
    Secret reply_;
    ServerAsyncResponseWriter<Secret> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class EditSecretCall: public CallData {
public:
    EditSecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                  std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    UpdatedSecret request_;
    Secret reply_;
    ServerAsyncResponseWriter<Secret> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class GetAllSecretsCall: public CallData {
public:
    GetAllSecretsCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                   std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    Token request_;
    SecretList reply_;
    ServerAsyncResponseWriter<SecretList> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class GetAllUsersCall: public CallData {
public:
    GetAllUsersCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                    std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    Token request_;
    UserDataList reply_;
    ServerAsyncResponseWriter<UserDataList> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class ShareSecretCall: public CallData {
public:
    ShareSecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                   std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    SecretAdmin request_;
    Empty reply_;
    ServerAsyncResponseWriter<Empty> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class DenySecretCall: public CallData {
public:
    DenySecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                      std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    SecretAdmin request_;
    Empty reply_;
    ServerAsyncResponseWriter<Empty> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

class IsUserExistsCall: public CallData {
public:
    IsUserExistsCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                   std::shared_ptr<TokenHandler> &tokenh);
    void Proceed() override;
private:
    UserData request_;
    Empty reply_;
    ServerAsyncResponseWriter<Empty> responder_;
    ServerCompletionQueue* cq_;
    std::shared_ptr<TokenHandler> tokenh_;
    std::shared_ptr<DBHandler> db_;
};

#endif //PAMCONTROLCLIENT_GRPCMETHODS_H
