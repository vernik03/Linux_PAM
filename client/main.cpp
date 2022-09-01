#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <map>

#include <boost/process.hpp>
#include <grpcpp/grpcpp.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "pam.grpc.pb.h"
#endif

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;
using helloworld::PAM;
using helloworld::RequestedSecret;
using helloworld::Secret;
using helloworld::UserData;
using helloworld::SecretList;
using helloworld::SecretType;
using helloworld::SecretAdmin;
using helloworld::Token;
using helloworld::AuthData;
using helloworld::SecretAdminList;
using helloworld::UpdatedSecret;
using helloworld::Empty;
using helloworld::UserDataList;

class Console
{
public:
  Console(){};
  ~Console(){};
  
  void print(){
      std::cout << "🟥🟧🟨🟩➡️   ";
  }

  void printAdmin(){
      std::cout << "🟩  ";
  }

  void printUser(){
      std::cout << "🟨  ";
  }

  void printErrorMessage(){
      std::cout << "🟥  ";
  }

  void printWarningMessage(){
      std::cout << "🟧  ";
  }

  void printUserWaitInput(){
      std::cout << "🟨➡️   ";
  }

  void printAdminWaitInput(){
      std::cout << "🟩➡️   ";
  }
};


class GreeterClient {
 public:
  explicit GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(PAM::NewStub(channel)) {}

  Secret GetSecret(RequestedSecret& user) {
    Secret reply;
    ClientContext context;
    Status status = stub_->GetSecret(&context, user, &reply);

    if (status.ok()) {
      return reply;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;     
    }
  }

  bool AddSecret(Secret& user) {
    Secret reply;
    ClientContext context;    
    Status status = stub_->AddSecret(&context, user, &reply);

    if (status.ok()) {
      return 1;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      return 0;
    }
  }

  bool EditSecret(Secret& to_edit, Secret& edited) {
    ClientContext context;
    Secret reply;   
    UpdatedSecret send;    
    *send.mutable_old() = to_edit;
    *send.mutable_new_() = edited;
    Status status = stub_->EditSecret(&context, send, &reply);

    if (status.ok()) {
      return 1;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      return 0;
    }
  }

  bool RemoveSecret(Secret& to_remove) {
    ClientContext context;
    Secret reply;
    Status status = stub_->RemoveSecret(&context, to_remove, &reply);

    if (status.ok()) {
      return 1;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      return 0;
    }
  }

  bool ShareSecret(SecretAdmin& to_share) {
    ClientContext context;
    Empty reply;
    Status status = stub_->ShareSecret(&context, to_share, &reply);

    if (status.ok()) {
      return 1;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      return 0;
    }
  }

   bool DenySecret(SecretAdmin& to_deny) {
    ClientContext context;
    Empty reply;
    Status status = stub_->DenySecret(&context, to_deny, &reply);

    if (status.ok()) {
      return 1;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      return 0;
    }
  }

  Token AuthoriseUser(AuthData& user) {
    Token reply;
    ClientContext context;
    Status status = stub_->Authorise(&context, user, &reply);

    if (status.ok()) {
      return reply;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;     
    }
  }

  bool IsUserExists(UserData& user) {
    Empty reply;
    ClientContext context;
    Status status = stub_->IsUserExists(&context, user, &reply);

    if (status.ok()) {
      return 1;
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;     
      return 0;
    }
  }

  google::protobuf::RepeatedPtrField<helloworld::Secret> GetSecretsForUser(RequestedSecret& user) {
    SecretList reply;
    ClientContext context;
    Status status = stub_->GetSecretsForUser(&context, user.user(), &reply);

    if (status.ok()) {
      return reply.secret();
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
    }
  }

  google::protobuf::RepeatedPtrField<helloworld::Secret> GetSecretsForAdmin(Token& token) {
    SecretList reply;
    ClientContext context;
    Status status = stub_->GetAllSecrets(&context, token, &reply);

    if (status.ok()) {
      return reply.secret();
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
    }
  }

  google::protobuf::RepeatedPtrField<helloworld::UserData> GetUsersForAdmin(Token& token) {
    UserDataList reply;
    ClientContext context;
    Status status = stub_->GetAllUsers(&context, token, &reply);

    if (status.ok()) {
      return reply.user_data();
    } else {
      console.printErrorMessage();
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
    }
  }



private:
  std::unique_ptr<PAM::Stub> stub_;
  bool is_admin = 0;
  Console console;
};

class Interface
{
public:
  Interface(){
    ip = "localhost";
    port = "50051";
    target_str = ip + ":" + port;
    name = "root";
    password = "";
    type = "ssh";
    token.set_token("");
	  greeter = std::make_unique<GreeterClient>(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));
  };
  ~Interface(){};

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

  void run(int argc, char** argv) {
    if (argc > 1) {
      auto args = parse_args(argc, argv);

      if (args.count("-name") != 0) { 
          name = args["-name"];
      }
      else{
        console.printWarningMessage();
          std::cout << "Enter your name: ";
          std::cin >> name;
      }

      if (args.count("-password") != 0) {
          password = args["-name"];
          AuthData auth;
          auth.set_user(name);
          auth.set_pass(password);
          token = greeter->AuthoriseUser(auth);
      }

      if (args.count("-ip") != 0) {
          ip = args["-ip"];
      }
    
      if (args.count("-port") != 0) {
          port = args["-port"];
      }

      if (args.count("-help") != 0) { 
          console.printWarningMessage();
          std::cout<<"Using: pam -name <your name> -password <your password> -ip <server address> -port <server port>"<<std::endl;
          help();
          return;
      }

     
      type = "ssh";
      new_request.set_type(SecretType::SSH);
      new_user_data.set_login(name); 
      while (!greeter->IsUserExists(new_user_data)){   
        console.printWarningMessage();
        std::cout << "Enter your name: ";
        std::cin >> name;
        new_user_data.set_login(name); 
      }  
      *new_request.mutable_user() = new_user_data;
      if (password != "") {
        new_request.set_password(password);
      }
      
      cycleInterface();
    } 
    else {
      console.printErrorMessage();
      std::cout<<"No target specified"<<std::endl;
      console.printWarningMessage();
      std::cout<<"Using: pam -name <your name> -password <your password> -ip <server address> -port <server port>"<<std::endl;
      help();
      return;
    }
  }

  bool isAdmin(){
    for (int i = 0; i < 3; i++)
      {
        if (token.token() == "")
        {
          console.printErrorMessage();
          std::cout << "Permission denied ❌" <<std::endl;
          console.printUserWaitInput();
          std::cout << "Enter password: ";
          std::cin >> password;
          AuthData auth;
          auth.set_user(name);
          auth.set_pass(password);
          token = greeter->AuthoriseUser(auth);
        }
        else{
          break;
        }
      }
       if (token.token() != "")
      {
        return 1;
      }
      else{
        console.printErrorMessage();
        std::cout << "Permission denied ❌" << std::endl;
        return 0;
      }
  }

  int listSelectAdmin(google::protobuf::RepeatedPtrField<helloworld::Secret> reply_list){
    int i = 0;
    for (auto secret : reply_list)
    {
      console.printAdmin();
      std::cout << "secret-" << i+1 << ": " << secret.login() << " " << secret.addr();
      switch (secret.type()) {
            case (SecretType::SSH):
                std::cout << " SSH" << std::endl;
                break;
            case (SecretType::RDP):
                std::cout << " RDP" << std::endl;
                break;
            case (SecretType::VNC):
                std::cout << " VNC" << std::endl;
                break;
            default:
                std::cout << std::endl;
                break;
        }
      i++;
    }
    console.printAdminWaitInput();
    std::cout << "Enter secret number (or '0' to cancel): ";
    int secret_number;
    std::cin >> secret_number;
    return secret_number;
  }

  void cycleInterface(){
  std::string command = "";
  while (command != "exit")
  {
    console.print();
    std::cin >> command;
    if (command == "connect")
    {
      auto reply_list = greeter->GetSecretsForUser(new_request);  
      int i = 0;
      for (auto secret : reply_list)
      {
        console.printUser();
        std::cout << "secret-" << i+1 << ": " << secret.login() << " " << secret.addr();
      switch (secret.type()) {
            case (SecretType::SSH):
                std::cout << " SSH" << std::endl;
                break;
            case (SecretType::RDP):
                std::cout << " RDP" << std::endl;
                break;
            case (SecretType::VNC):
                std::cout << " VNC" << std::endl;
                break;
            default:
                std::cout << std::endl;
                break;
        }
        i++;
      }
      console.printUserWaitInput();
      std::cout << "Enter secret number (or '0' to cancel): ";
      int secret_number;
      std::cin >> secret_number;
      if  (secret_number != 0)
      {
        auto reply = reply_list.Get(secret_number-1);
        boost::process::child proc;
        std::string vnc_command;
        switch (reply.type()) {
            case (SecretType::SSH):
                proc = boost::process::child(boost::process::search_path("sshpass"), "-p", reply.pass(),
                      "ssh", "-Y", "-o", "StrictHostKeyChecking=no", reply.login()+"@"+reply.addr(),
                      "-p", std::to_string(reply.port()));
                break;
            case (SecretType::RDP):
                 proc = boost::process::child (boost::process::search_path("xfreerdp"), "/u:"+reply.login(),
                      "/p:" + reply.pass(), "/v:" + reply.addr(), "/port:" + std::to_string(reply.port()));
                break;
                // xfreerdp /u:test2 /p:test2_pass /v:178.159.224.36 /port:33890
            case (SecretType::VNC):
              vnc_command = "echo '" + reply.pass() + "' | vncviewer -autopass " + reply.addr() +"::" + std::to_string(reply.port());
              system(vnc_command.c_str());
              break;
            default:
                std::cout << "Unknown type of secret: " << reply.type() << std::endl;
                break;
        }
        proc.wait();
      }
    }
    else if(command == "list"){
      if (isAdmin()){
        int i = 0;
        auto reply_list = greeter->GetSecretsForAdmin(token);
        for (auto secret : reply_list)
        {
          console.printAdmin();
          std::cout << "secret-" << i+1 << ": " << secret.addr() << std::endl;
          i++;
        }
      }
    }
    else if(command == "add"){
      if (isAdmin()){
        Secret new_secret;
        std::string input;      
        console.printAdminWaitInput();
        std::cout << "Enter address: ";
        std::cin >> input;
        new_secret.set_addr(input);
        console.printAdminWaitInput();
        std::cout << "Enter port: ";
        std::cin >> input;
        new_secret.set_port(std::stoi(input));
        console.printAdminWaitInput();
        std::cout << "Enter login: ";
        std::cin >> input;
        new_secret.set_login(input);
        console.printAdminWaitInput();
        std::cout << "Enter password: ";
        std::cin >> input;
        new_secret.set_pass(input);
        std::string type;
        while (true)
        {      
          console.printAdminWaitInput();
          std::cout << "Enter connection type (SSH/VNC/RDP):";
          std::cin >> type;
          std::transform(type.begin(), type.end(), type.begin(), tolower);
          if (type == "ssh") {
            new_secret.set_type(SecretType::SSH);
            break;
          }
          else if (type == "vnc") {
            new_secret.set_type(SecretType::VNC);
            break;
          }
          else if (type == "rdp") {
            new_secret.set_type(SecretType::RDP);
            break;
          }
          else {
            console.printErrorMessage();
            std::cout << "Wrong connection type" << std::endl;
          }
        }
        Secret new_secret_admin = new_secret;

        if (greeter->AddSecret(new_secret_admin)){
          console.printAdmin();
          std::cout << "🎉 Secret added" << std::endl;
        }
      }
    }
    else if(command == "edit"){

      if (isAdmin()){
        auto reply_list = greeter->GetSecretsForAdmin(token);
        int secret_number = listSelectAdmin(reply_list);
        if(secret_number != 0){
          auto secret_to_edit = reply_list.Get(secret_number-1);
          Secret secret_result;
          secret_result = secret_to_edit;
          bool end = 0;
          while (!end)
          {
            console.printAdmin();
            std::cout<<"(1) address: \t"<<secret_to_edit.addr() << "\t-\t" << secret_result.addr() << std::endl;
            console.printAdmin();
            std::cout<<"(2) port:    \t"<<secret_to_edit.port() << "\t-\t" << secret_result.port() << std::endl;
            console.printAdmin();
            std::cout<<"(3) login:   \t"<<secret_to_edit.login() << "\t-\t" << secret_result.login() << std::endl;
            console.printAdmin();
            std::cout<<"(4) password:\t"<<secret_to_edit.pass() << "\t-\t" << secret_result.pass() << std::endl;
            console.printAdmin();
            std::cout<<"(5) type:    \t"<<secret_to_edit.type() << "\t-\t" << secret_result.type() << std::endl;
            console.printAdminWaitInput();
            std::cout<<"Enter number of field to edit or '0' to end editing: ";
            int field_number;
            std::cin >> field_number;

            Secret new_secret = secret_result;
            std::string input;
            switch (field_number)
            {
              case 0:
                end = 1;
                break;
              case 1:
                console.printAdminWaitInput();
                std::cout << "Enter new address: ";
                std::cin >> input;
                new_secret.set_addr(input);
                break;
              case 2:
                console.printAdminWaitInput();
                std::cout << "Enter new port: ";
                std::cin >> input;
                new_secret.set_port(std::stoi(input));
                break;
              case 3:
                console.printAdminWaitInput();
                std::cout << "Enter new login: ";
                std::cin >> input;
                new_secret.set_login(input);
                break;
              case 4:
                console.printAdminWaitInput();
                std::cout << "Enter new password: ";
                std::cin >> input;
                new_secret.set_pass(input);
                break;
              case 5:
                console.printAdminWaitInput();
                std::cout << "Enter new connection type (SSH/VNC/RDP): " << std::endl;
                std::cin >> input;
                std::transform(input.begin(), input.end(), input.begin(), tolower);
                if (input == "ssh") {
                  new_secret.set_type(SecretType::SSH);
                }
                else if (input == "vnc") {
                  new_secret.set_type(SecretType::VNC);
                }
                else if (input == "rdp") {
                  new_secret.set_type(SecretType::RDP);
                }
                else {
                  console.printErrorMessage();
                  std::cout << "Wrong connection type" << std::endl;
                }
                break;
              default:
                std::cout<<"Wrong number"<<std::endl;
                break;
            }
            
            secret_result = new_secret;
          }
          
          if(greeter->EditSecret(secret_to_edit, secret_result)){
            console.printAdmin();
            std::cout << "🎉 Secret edited" << std::endl;
          }
        }
      }  
    }
    else if(command == "remove"){
      if (isAdmin()){
        auto reply_list = greeter->GetSecretsForAdmin(token);
        int secret_number = listSelectAdmin(reply_list);
        if(secret_number != 0){
           auto secret_to_remove = reply_list.Get(secret_number-1);
          if(greeter->RemoveSecret(secret_to_remove)){
            console.printAdmin();
            std::cout << "🎉 Secret removed" << std::endl;
          }
        }
      }
    }
    else if(command == "share"){
      if (isAdmin()){
        auto reply_list = greeter->GetSecretsForAdmin(token);
        int secret_number = listSelectAdmin(reply_list);
        SecretAdmin secret_admin_to_share;
        if(secret_number != 0){
          auto secret_to_share = reply_list.Get(secret_number-1);
          *secret_admin_to_share.mutable_secret() = secret_to_share;
          auto reply_list_users = greeter->GetUsersForAdmin(token);
          int i = 0;
          for (auto user : reply_list_users)
          {
            console.printAdmin();
            std::cout << "user-" << i+1 << ": " << user.login() << std::endl;
            i++;
          }
          console.printAdminWaitInput();
          std::cout << "Enter secret number (or '0' to cancel): ";
          int user_number;
          std::cin >> user_number;
          if(user_number != 0){
            auto user_to_share = reply_list_users.Get(user_number-1);
            *secret_admin_to_share.mutable_user() = user_to_share; 
            *secret_admin_to_share.mutable_token() = token;
            
            if(greeter->ShareSecret(secret_admin_to_share)){
              console.printAdmin();
              std::cout << "🎉 Secret shared" << std::endl;
            }
          }
        }
      }
    }
    else if(command == "deny"){
      if (isAdmin()){
        auto reply_list = greeter->GetSecretsForAdmin(token);
        int secret_number = listSelectAdmin(reply_list);
        SecretAdmin secre_admin_to_deny;
        if(secret_number != 0){
          auto secret_to_share = reply_list.Get(secret_number-1);
          *secre_admin_to_deny.mutable_secret() = secret_to_share;

          auto reply_list_users = greeter->GetUsersForAdmin(token);
          int i = 0;
          for (auto user : reply_list_users)
          {
            console.printAdmin();
            std::cout << "user-" << i+1 << ": " << user.login() << std::endl;
            i++;
          }
          console.printAdminWaitInput();
          std::cout << "Enter secret number (or '0' to cancel): ";
          int user_number;
          std::cin >> user_number;
          if(user_number != 0){
            auto user_to_deny = reply_list_users.Get(user_number-1);
            *secre_admin_to_deny.mutable_user() = user_to_deny; 
            *secre_admin_to_deny.mutable_token() = token;
            
            if(greeter->DenySecret(secre_admin_to_deny)){
              console.printAdmin();
              std::cout << "🎉 Secret denied" << std::endl;
            }
          }
        }
      }
    }
    else if(command == "help"){
      help();

    }
    else if(command == "exit"){
      continue;
    }
    else{
      console.printErrorMessage();
      std::cout << "❓ Unknown command" << std::endl;
    }
  }
}

void help(){
std::cout << std::endl;
      std::cout << "Visual navigation: " << std::endl;
      console.printErrorMessage();
      std::cout << "- error message" << std::endl;
      console.printWarningMessage();
      std::cout << "- warning or info message" << std::endl;
      console.printUser();
      std::cout << "- user command" << std::endl;
      console.printAdmin();
      std::cout << "- admin command" << std::endl;
      std::cout << "➡️   " << "- the program is waiting for input" << std::endl;
      std::cout << std::endl;
      std::cout << "Available commands: " << std::endl;
      console.printUser();
      std::cout << "🔸connect - connect to the computer by secret" << std::endl;
      console.printAdmin();
      std::cout << "🔸list - show all secrets" << std::endl;
      console.printAdmin();
      std::cout << "🔸add - add new secret" << std::endl;
      console.printAdmin();
      std::cout << "🔸edit - edit secret" << std::endl;
      console.printAdmin();
      std::cout << "🔸remove - remove secret" << std::endl;
      console.printAdmin();
      std::cout << "🔸share - share access to secret for user" << std::endl;
      console.printAdmin();
      std::cout << "🔸deny - deny access to secret from user" << std::endl;
      console.printUser();
      std::cout << "🔸exit - close program" << std::endl;
      std::cout << std::endl;
}

private:
  std::unique_ptr<GreeterClient> greeter;  
  RequestedSecret new_request;
  UserData new_user_data;

  std::string ip;
  std::string port;
  std::string target_str;
  std::string name;
  std::string password;
  std::string type;

  Console console;
  Token token;
};


int main(int argc, char** argv) {

    Interface interface;
    interface.run(argc, argv);

  return 0;
}
