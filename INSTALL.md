# Installation

## Build from sources

Get stable version from github repository
```sh
git clone https://github.com/apriorit/linux-pam-2022.git
cd linux-pam-2022 && git checkout release
```

## Build
Dependencies: cmake, build-essentials, libsqlite3-dev, grpc, libboost-filesystem-dev, libboost-system-dev
```shell
mkdir cmake && cd cmake
cmake ..
make
```

If build end successfully, there should be two files, `client` and `server`. Copy them to jump server and server with database respectively.


## Install client
Set-up ssh server, so external users can connect to jump-server
```shell
sudo apt install openssh-server
sudo systemctl enable ssh
```

Create working directory
```shell
cd /opt
sudo mkdir pam && cd pam
sudo nano fake_shell.sh
# Insert following lines:
# #!/bin/bash
# /opt/pam_client -user "$USER" -ip "<path_to_db_server>"
sudo chmod +x /opt/fake_shell.sh

# Now copy client binary to /opt/pam_client
```
...  add users in system for every worker that intend to use this jump-server ...
Note: for each user specify login shell as /opt/fake_shell.sh
```shell
# For new user
sudo useradd -s /opt/fake_shell.sh <username>
sudo passwd <username>

# For existing user
sudo usermod --shell /opt/fake_shell.sh <username>
```


## Install server
Create working directory
```shell
su -s
groupadd pam-server
useradd -g pam-server pam-server
mkdir -p /opt/pam && cd /opt/pam
# Copy server and assets/pam_control.sql here
cat pam_control.sql | sqlite3 database.db
# Set correct permissions
chmod -R 550 .
chown -R pam-server:pam-server .
# And start server
./server
```