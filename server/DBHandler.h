//
// Created by robotknik on 16.07.22.
//

#ifndef PAMCONTROLCLIENT_DBHANDLER_H
#define PAMCONTROLCLIENT_DBHANDLER_H

#include <string>
#include <sqlite3.h>
#include <iostream>
#include <vector>

#include "pam.grpc.pb.h"

using helloworld::Secret;
using helloworld::UserData;

const int kEmptyUserId = 0;

class DBHandler {
public:
    explicit DBHandler(const std::string& db_path);

    DBHandler(DBHandler &&other) noexcept ;
    ~DBHandler();
    DBHandler(DBHandler const &other) = delete;

    std::string getLastError();

    UserData getUser(const std::string &user);
    // Retrieve credentials for user
    std::vector<Secret> getCredentials(int uid);
    std::vector<Secret> getAllCredentials();
    // Returns -1 on failure
    int removeSecret(const Secret& secret);
    int addSecret(const Secret& secret);
    int updateSecret(const Secret& s_old, const Secret& s_new);
    // Transfer the ownership over the secret to other user
    int shareSecret(const Secret& target, int new_uid);
    int denySecret(const Secret& target, int old_uid);
    std::vector<UserData> getUsers();

private:
    sqlite3 *db;
};


#endif //PAMCONTROLCLIENT_DBHANDLER_H
