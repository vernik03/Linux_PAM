//
// Created by robotknik on 21.07.22.
//

#include "GrpcMethods.h"


inline std::string type_to_str(helloworld::SecretType type) {
    switch (type) {
        case (helloworld::SecretType::SSH):
            return "SSH";
        case (helloworld::SecretType::RDP):
            return "RDP";
        case (helloworld::SecretType::VNC):
            return "VNC";
        default:
            return "UNKN";
    }
}


std::string TokenHandler::generateToken(const std::string& user) {
    std::string alpha = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int token_len = 15;
    std::string result;
    result.resize(token_len);
    std::random_device rd;  //Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> distrib(0, alpha.size()-1);

    std::unique_lock mutex_l(mutex_);

    do {
        for (int i = 0; i < token_len; i++) {
            result[i] = alpha[distrib(gen)];
        }
    } while (isUsed(result));

    tokens_.push_back(token_s{user, result});
    return result;
}

std::string TokenHandler::getUser(const std::string &token) {
    std::shared_lock mutex_l(mutex_);

    for (const auto& v_token : tokens_) {
        if (token == v_token.token)
            return v_token.user;
    }
    return "";
}

bool TokenHandler::isUsed(const std::string& token) const {
    for (const auto& v_token : tokens_) {
        if (token == v_token.token)
            return true;
    }
    return false;
}

////////////////////
/////// GetSecretCall
////////////////////

GetSecretCall::GetSecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService* service, ServerCompletionQueue* cq): CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_) {
    service_ = service;
    status_ = PROCESS;
    service->RequestGetSecret(&ctx_, &request_, &responder_, cq_, cq_, this);
}


void GetSecretCall::Proceed() {
    if (status_ == PROCESS) {
        // Spawn a new CallData instance to serve new clients while we process
        // the one for this CallData. The instance will deallocate itself as
        // part of its FINISH state.
        new GetSecretCall(db_, service_, cq_);

        std::cout << "Requested secret for the user: " << request_.user().login() << " of type: " << type_to_str(request_.type()) << std::endl;
        std::vector<std::string> logins, pass;
        std::vector<int> types;
        bool found = false;
        auto cur_user = db_->getUser(request_.user().login());
        auto secrets = db_->getCredentials(cur_user.uid());
        for (const auto& secret : secrets ) {
            if (secret.type() == request_.type()) {
                reply_ = secret;
                found = true;
                break;
            }
        }

        if (!found) {
            std::cerr << "Unable to find credentials for the user: " << request_.user().login() << std::endl;
        }

        // And we are done! Let the gRPC runtime know we've finished, using the
        // memory address of this instance as the uniquely identifying tag for
        // the event.
        status_ = FINISH;
        responder_.Finish(reply_, Status::OK, this);
    } else {
        GPR_ASSERT(status_ == FINISH);
        // Once in the FINISH state, deallocate ourselves (CallData).
        delete this;
    }
}

////////////////////
/////// GetSecretListCall
////////////////////


GetSecretListCall::GetSecretListCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service,
                                                 ServerCompletionQueue *cq): CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_) {
    service_ = service;
    status_ = PROCESS;
    service->RequestGetSecretsForUser(&ctx_, &request_, &responder_, cq_, cq_, this);
}


void GetSecretListCall::Proceed() {
    if (status_ == PROCESS) {
        new GetSecretListCall(db_, service_, cq_);

        std::cout << "Requested list of secrets for the user: " << request_.login() << std::endl;
        auto cur_user = db_->getUser(request_.login());
        auto secrets = db_->getCredentials(cur_user.uid());
        for (const auto& secret : secrets) {
            Secret *new_secret = reply_.add_secret();
            *new_secret = secret;
        }

        status_ = FINISH;
        responder_.Finish(reply_, Status::OK, this);
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}


////////////////////
/////// Authorise
////////////////////


AuthoriseCall::AuthoriseCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service, ServerCompletionQueue *cq,
                             std::shared_ptr<TokenHandler> &tokenh): CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh) {
    service_ = service;
    status_ = PROCESS;
    service->RequestAuthorise(&ctx_, &request_, &responder_, cq_, cq_, this);
}

void AuthoriseCall::Proceed() {
    if (status_ == PROCESS) {
        new AuthoriseCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;

        std::cout << "Requested authorize for user: " << request_.user() << std::endl;
        auto user = db_->getUser(request_.user());
        if (user.has_password() && user.password() == request_.pass()) {
            std::string token = tokenh_->generateToken(request_.user());
            reply_.set_token(token);
            responder_.Finish(reply_, Status::OK, this);
        } else {
            responder_.Finish(reply_, Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid username or password"), this);
        }

    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}



////////////////////
/////// RemoveSecret
////////////////////


RemoveSecretCall::RemoveSecretCall(std::shared_ptr <DBHandler> db, PAM::AsyncService *service,
                                   ServerCompletionQueue *cq, std::shared_ptr <TokenHandler> &tokenh): CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh)  {
    service_ = service;
    status_ = PROCESS;
    service->RequestRemoveSecret(&ctx_, &request_, &responder_, cq_, cq_, this);
}

void RemoveSecretCall::Proceed() {
    if (status_ == PROCESS) {
        new RemoveSecretCall(db_, service_, cq_, tokenh_);
        // TODO: check token

        std::cout << "Requested remove of secret for login: " << request_.login() << std::endl;
        int rc = db_->removeSecret(request_);
        reply_ = request_;
        if (rc == -1) {
            responder_.Finish(reply_, Status(grpc::StatusCode::CANCELLED, "Unable to remove secret " + db_->getLastError()), this);
        } else {
            responder_.Finish(reply_, Status::OK, this);
        }

        status_ = FINISH;
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}


////////////////////
/////// AddSecret
////////////////////

AddSecretCall::AddSecretCall(std::shared_ptr <DBHandler> db, PAM::AsyncService *service,
                                   ServerCompletionQueue *cq, std::shared_ptr <TokenHandler> &tokenh): CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh)  {
    service_ = service;
    status_ = PROCESS;
    service->RequestAddSecret(&ctx_, &request_, &responder_, cq_, cq_, this);
}

void AddSecretCall::Proceed() {
    if (status_ == PROCESS) {
        new AddSecretCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;
        // TODO: check token

        std::cout << "Request create secret with login: " << request_.login() << std::endl;

        int rc = db_->addSecret(request_);
        reply_ = request_;

        if (rc == -1) {
            responder_.Finish(reply_, Status(grpc::StatusCode::CANCELLED, "Unable to add secret " + db_->getLastError()), this);
        } else {
            responder_.Finish(reply_, Status::OK, this);
        }
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}


////////////////////
/////// EditSecret
////////////////////

EditSecretCall::EditSecretCall(std::shared_ptr <DBHandler> db, PAM::AsyncService *service,
                             ServerCompletionQueue *cq, std::shared_ptr <TokenHandler> &tokenh):
                             CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh)  {
    service_ = service;
    status_ = PROCESS;
    service->RequestEditSecret(&ctx_, &request_, &responder_, cq_, cq_, this);
}

void EditSecretCall::Proceed() {
    if (status_ == PROCESS) {
        new EditSecretCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;
        // TODO: check token

        std::cout << "Request edit secret for login: " << request_.old().login() << std::endl;
        reply_ = request_.new_();
        int rc = db_->updateSecret(request_.old(), request_.new_());
        if (rc == -1) {
            responder_.Finish(reply_, Status(grpc::StatusCode::CANCELLED, "Unable to update secret " + db_->getLastError()), this);
            return;
        }

        responder_.Finish(reply_, Status::OK, this);

    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}


////////////////////
/////// GetAllSecretsCall
////////////////////

GetAllSecretsCall::GetAllSecretsCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service,
                                     ServerCompletionQueue *cq, std::shared_ptr<TokenHandler> &tokenh):
                                     CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh) {
    service_ = service;
    status_ = PROCESS;
    service->RequestGetAllSecrets(&ctx_, &request_, &responder_, cq_, cq_, this);
}


void GetAllSecretsCall::Proceed() {
    if (status_ == PROCESS) {
        new GetAllSecretsCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;

        std::cout << "Request all secrets " << std::endl;

        std::string req_user_name = tokenh_->getUser(request_.token());
        if (req_user_name.empty() || db_->getUser(req_user_name).role() != UserRoles::Admin) {
            std::cerr << "User isn't an admin or token is invalid" << std::endl;
            responder_.Finish(reply_, Status(grpc::StatusCode::INVALID_ARGUMENT, "User isn't an admin or token is invalid"), this);
            return;
        }

        std::vector<Secret> secrets = db_->getAllCredentials();
        for (const auto &secret: secrets) {
            *reply_.add_secret() = secret;
        }

        responder_.Finish(reply_, Status::OK, this);
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}

////////////////////
/////// GetAllUsersCall
////////////////////

GetAllUsersCall::GetAllUsersCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service,
                                     ServerCompletionQueue *cq, std::shared_ptr<TokenHandler> &tokenh):
        CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh) {
    service_ = service;
    status_ = PROCESS;
    service->RequestGetAllUsers(&ctx_, &request_, &responder_, cq_, cq_, this);
}


void GetAllUsersCall::Proceed() {
    if (status_ == PROCESS) {
        new GetAllUsersCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;

        std::cout << "Request all users " << std::endl;

        std::string req_user_name = tokenh_->getUser(request_.token());
        if (req_user_name.empty() || db_->getUser(req_user_name).role() != UserRoles::Admin) {
            std::cerr << "User isn't an admin or token is invalid" << std::endl;
            responder_.Finish(reply_, Status(grpc::StatusCode::INVALID_ARGUMENT, "User isn't an admin or token is invalid"), this);
            return;
        }

        std::vector<UserData> users = db_->getUsers();
        for (const auto &user: users) {
            *reply_.add_user_data() = user;
        }

        responder_.Finish(reply_, Status::OK, this);
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}


////////////////////
/////// ShareSecretCall
////////////////////

ShareSecretCall::ShareSecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service,
                                     ServerCompletionQueue *cq, std::shared_ptr<TokenHandler> &tokenh):
        CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh) {
    service_ = service;
    status_ = PROCESS;
    service->RequestShareSecret(&ctx_, &request_, &responder_, cq_, cq_, this);
}


void ShareSecretCall::Proceed() {
    if (status_ == PROCESS) {
        new ShareSecretCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;

        std::cout << "Request share secret to user: " << request_.user().login()  << std::endl;

        std::string req_user_name = tokenh_->getUser(request_.token().token());
        if (req_user_name.empty() || db_->getUser(req_user_name).role() != UserRoles::Admin) {
            std::cerr << "User isn't an admin or token is invalid" << std::endl;
            responder_.Finish(reply_, Status(grpc::StatusCode::INVALID_ARGUMENT, "User isn't an admin or token is invalid"), this);
            return;
        }

        int rc;
        auto user = db_->getUser(request_.user().login());
        if (user.uid() != kEmptyUserId) {
            rc = db_->shareSecret(request_.secret(), user.uid());
            if (rc != -1) {
                responder_.Finish(reply_, Status::OK, this);
            } else {
                std::cerr << "Unable to change ownership of a secret" << std::endl;
                std::cerr << db_->getLastError() << std::endl;
                responder_.Finish(reply_, Status(grpc::StatusCode::CANCELLED, "Unable to change ownership of a secret"), this);
            }
        } else {
            std::cerr << "Database dont have a user with given username" << std::endl;
            responder_.Finish(reply_, Status(grpc::StatusCode::NOT_FOUND, "Not found username in database"), this);
        }
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}

////////////////////
/////// DenySecretCall
////////////////////

DenySecretCall::DenySecretCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service,
                                 ServerCompletionQueue *cq, std::shared_ptr<TokenHandler> &tokenh):
        CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh) {
    service_ = service;
    status_ = PROCESS;
    service->RequestDenySecret(&ctx_, &request_, &responder_, cq_, cq_, this);
}


void DenySecretCall::Proceed() {
    if (status_ == PROCESS) {
        new DenySecretCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;

        std::cout << "Request deny secrets for user: " << request_.user().login()  << std::endl;

        std::string req_user_name = tokenh_->getUser(request_.token().token());
        if (req_user_name.empty() || db_->getUser(req_user_name).role() != UserRoles::Admin) {
            std::cerr << "User isn't an admin or token is invalid" << std::endl;
            responder_.Finish(reply_, Status(grpc::StatusCode::INVALID_ARGUMENT, "User isn't an admin or token is invalid"), this);
            return;
        }

        int rc;
        auto user = db_->getUser(request_.user().login());
        if (user.uid() != kEmptyUserId) {
            rc = db_->denySecret(request_.secret(), user.uid());
            if (rc != -1) {
                responder_.Finish(reply_, Status::OK, this);
                return;
            } else {
                std::cerr << "Unable to deny ownership of a secret" << std::endl;
                std::cerr << db_->getLastError() << std::endl;
                responder_.Finish(reply_, Status(grpc::StatusCode::CANCELLED, "Unable to deny ownership of a secret"), this);
            }
        } else {
            std::cerr << "Database dont have a user with given username" << std::endl;
            responder_.Finish(reply_, Status(grpc::StatusCode::NOT_FOUND, "Not found username in database"), this);
        }
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}

////////////////////
/////// IsUserExistsCall
////////////////////

IsUserExistsCall::IsUserExistsCall(std::shared_ptr<DBHandler> db, PAM::AsyncService *service,
                               ServerCompletionQueue *cq, std::shared_ptr<TokenHandler> &tokenh):
        CallData(), db_(std::move(db)), cq_(cq), responder_(&ctx_), tokenh_(tokenh) {
    service_ = service;
    status_ = PROCESS;
    service->RequestIsUserExists(&ctx_, &request_, &responder_, cq_, cq_, this);
}


void IsUserExistsCall::Proceed() {
    if (status_ == PROCESS) {
        new IsUserExistsCall(db_, service_, cq_, tokenh_);
        status_ = FINISH;

        std::cout << "Request isUserExists by username: " << request_.login()  << std::endl;

        int rc;
        auto user = db_->getUser(request_.login());
        if (user.uid() != kEmptyUserId) {
            responder_.Finish(reply_, Status::OK, this);
        } else {
            responder_.Finish(reply_, Status(grpc::StatusCode::NOT_FOUND, "Not found username in database"), this);
        }
    } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
    }
}