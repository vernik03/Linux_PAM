//
// Created by robotknik on 16.07.22.
//

#include <vector>
#include "DBHandler.h"


DBHandler::DBHandler(const std::string& db_path) {
    int rc;

    if (sqlite3_threadsafe() == 0) {
        throw std::runtime_error("libsqlite3 was compiled without mutexes");
    }

    rc = sqlite3_open_v2(db_path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);

    if( rc ) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    sqlite3_exec(db, "PRAGMA foreign_keys = ON",nullptr,nullptr,nullptr);
}

DBHandler::DBHandler(DBHandler &&other) noexcept {
    db = other.db;
    other.db = nullptr;
}

DBHandler::~DBHandler() {
    sqlite3_close_v2(db);
}

std::string DBHandler::getLastError() {
    return sqlite3_errmsg(db);
}

std::vector<Secret> DBHandler::getCredentials(int uid) {
    char sql[] = "SELECT addr,login,password,port,type FROM credentials WHERE id IN (SELECT cred_id FROM users_creds WHERE user_id == ?)";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return {};
    }

    rc = sqlite3_bind_int(stmt, 1, uid);
    if( rc ) {
        std::cerr << "Can't bind text to parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return {};
    }
#if 0
    //    switch(sqlite3_step(stmt)) {
//        case SQLITE_ROW:
//            std::cout << "Row retrieved" <<std::endl;
//            break;
//        case SQLITE_BUSY:
//            std::cout << "db is bussy" <<std::endl;
//            break;
//        case SQLITE_ERROR:
//            std::cout << "ERROR occured " << sqlite3_errmsg(db) << std::endl;
//            break;
//        default:
//            std::cout << "Unknown return code" << std::endl;
//    }
#endif
    std::vector<Secret> result;
    while((rc=sqlite3_step(stmt)) ==  SQLITE_ROW) {
        Secret tmp_secret;
        tmp_secret.set_addr(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        tmp_secret.set_login(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        tmp_secret.set_pass(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
        tmp_secret.set_port(sqlite3_column_int(stmt, 3));
        tmp_secret.set_type(static_cast<helloworld::SecretType>(sqlite3_column_int(stmt, 4)));
        result.push_back(tmp_secret);
    }
    if (rc == SQLITE_ERROR) {
        std::cerr << "Sql request returned error: " << sqlite3_errmsg(db) << std::endl;
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<Secret> DBHandler::getAllCredentials() {
    char sql[] = "SELECT addr,login,password,port,type FROM credentials";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return {};
    }

    std::vector<Secret> result;
    while((rc=sqlite3_step(stmt)) ==  SQLITE_ROW) {
        Secret tmp_secret;
        tmp_secret.set_addr(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        tmp_secret.set_login(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        tmp_secret.set_pass(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
        tmp_secret.set_port(sqlite3_column_int(stmt, 3));
        tmp_secret.set_type(static_cast<helloworld::SecretType>(sqlite3_column_int(stmt, 4)));
        result.push_back(tmp_secret);
    }
    if (rc == SQLITE_ERROR) {
        std::cerr << "Sql request returned error: " << sqlite3_errmsg(db) << std::endl;
    }
    sqlite3_finalize(stmt);
    return result;
}

UserData DBHandler::getUser(const std::string &user) {
    char sql[] = "SELECT id,name,password,role FROM users WHERE name==?";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return {};
    }
    rc = sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
    if( rc ) {
        std::cerr << "Can't bind text to parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return {};
    }
    UserData result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result.set_uid(sqlite3_column_int(stmt, 0));
        result.set_login(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        result.set_password(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
        result.set_role(sqlite3_column_int(stmt, 3));
    }
    sqlite3_finalize(stmt);
    return result;
}

int DBHandler::removeSecret(const Secret& secret) {
    char sql[] = "DELETE FROM credentials WHERE login==? AND addr==?";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    rc = sqlite3_bind_text(stmt, 1, secret.login().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 2, secret.addr().c_str(), -1, SQLITE_STATIC);
    if( rc ) {
        std::cerr << "Can't bind text to parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_ROW || rc == SQLITE_DONE) {
        return 0;
    }
    return -1;
}

int DBHandler::addSecret(const Secret &secret) {
    char sql[] = "INSERT INTO credentials(addr,login,password,port,type) VALUES (?,?,?,?,?)";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    rc = sqlite3_bind_text(stmt, 1, secret.addr().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 2, secret.login().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 3, secret.pass().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_int(stmt, 4, secret.port());
    rc |= sqlite3_bind_int(stmt, 5, secret.type());
    if( rc ) {
        std::cerr << "Can't bind text to parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) {
        return 0;
    } else if (rc == SQLITE_ERROR) {
        std::cerr << "Error occurred when executing sql: " << sqlite3_errmsg(db) << std::endl;
    }
    return -1;
}

int DBHandler::updateSecret(const Secret &s_old, const Secret &s_new) {
    char sql[] = "UPDATE credentials SET addr=?, login=?, password=?, port=?, type=? WHERE addr==? AND login==?";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    rc = sqlite3_bind_text(stmt, 1, s_new.addr().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 2, s_new.login().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 3, s_new.pass().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_int(stmt, 4, s_new.port());
    rc |= sqlite3_bind_int(stmt, 5, s_new.type());
    rc |= sqlite3_bind_text(stmt, 6, s_old.addr().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 7, s_old.login().c_str(), -1, SQLITE_STATIC);
    if( rc ) {
        std::cerr << "Can't bind text to parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_ROW) {
        return 0;
    } else if (rc == SQLITE_ERROR) {
        std::cerr << "Error occurred when executing sql: " << sqlite3_errmsg(db) << std::endl;
    }
    return -1;
}

int DBHandler::shareSecret(const Secret &target, int new_uid) {
    char sql[] = "INSERT INTO users_creds(user_id,cred_id) VALUES (?,(SELECT id FROM credentials WHERE addr==? AND login==?))";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    rc = sqlite3_bind_int(stmt, 1, new_uid);
    rc |= sqlite3_bind_text(stmt, 2, target.addr().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 3, target.login().c_str(), -1, SQLITE_STATIC);
    if( rc ) {
        std::cerr << "Can't bind text to parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_ROW) {
        return 0;
    } else if (rc == SQLITE_ERROR) {
        std::cerr << "Error occurred when executing sql: " << sqlite3_errmsg(db) << std::endl;
    }
    return -1;
}

int DBHandler::denySecret(const Secret &target, int old_uid) {
    char sql[] = "DELETE FROM users_creds WHERE user_id==? AND cred_id == (SELECT id FROM credentials WHERE addr==? AND login==?)";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    rc = sqlite3_bind_int(stmt, 1, old_uid);
    rc |= sqlite3_bind_text(stmt, 2, target.addr().c_str(), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(stmt, 3, target.login().c_str(), -1, SQLITE_STATIC);
    if( rc ) {
        std::cerr << "Can't bind text to parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_ROW) {
        return 0;
    } else if (rc == SQLITE_ERROR) {
        std::cerr << "Error occurred when executing sql: " << sqlite3_errmsg(db) << std::endl;
    }
    return -1;
}

std::vector<UserData> DBHandler::getUsers() {
    char sql[] = "SELECT id,name,password,role FROM users";
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_prepare(db, sql, -1, &stmt, nullptr);
    if( rc ) {
        std::cerr << "Can't prepare request: " << sqlite3_errmsg(db) << std::endl;
        return {};
    }

    std::vector<UserData> result;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        UserData data;
        data.set_uid(sqlite3_column_int(stmt, 0));
        data.set_login(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        data.set_password(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
        data.set_role(sqlite3_column_int(stmt, 3));
        result.push_back(data);
    }
    sqlite3_finalize(stmt);
    return result;

}
