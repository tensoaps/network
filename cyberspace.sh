#!/bin/bash

if [ $# -eq 0 ]
then
    echo "Usage: $0 -<option>"
    echo "Options:"
    echo "  upgradecore - Update Linux kernel"
    echo "  yuminstalls - Install dependencies"
    echo "  createusers - Create new users"
    echo "  setfirewall - Set the firewall"
    echo "  updatenginx - Update Nginx servers"
    echo "  maintrojans - Run the trojan server"
    echo "  dingtalkgpt - Start dingtalk-chatgpt"
    exit 1
fi

case "$1" in
    -upgradecore)
        wget git.io/warp.sh
        #sudo sh warp.sh 4
        sudo rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
        sudo rpm -Uvh https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
        sudo yum --enablerepo=elrepo-kernel install kernel-lt
        sudo grub2-set-default 0
        sudo sed -i 's/GRUB_DEFAULT=saved/GRUB_DEFAULT=0/' /etc/default/grub
        sudo grub2-mkconfig -o /boot/grub2/grub.cfg
        sudo reboot
        ;;
    -yuminstalls)
        sudo yum install -y tmux htop 
        sudo yum install -y socat cronie curl 
        sudo systemctl start crond
        sudo systemctl enable crond
        sudo yum install -y xz
        sudo yum install -y nginx
        sudo yum install -y yum-utils device-mapper-persistent-data lvm2
        sudo yum-config-manager -y --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        sudo yum install firewalld firewall-config
        sudo systemctl start firewalld
        sudo systemctl enable firewalld
        sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        sudo systemctl start docker
        sudo systemctl enable docker
        echo "Start docker server ..."
        ;;
    -createusers)
        echo "Enter the username: "
        read username

        echo "Enter the password: "
        read -s password
        echo "Confirm the password: "
        read -s password2
        if [ "$password" != "$password2" ]
        then
            echo "Passwords do not match."
            exit 1
        fi

        sudo useradd $username
        echo "$password" | sudo passwd --stdin $username &>/dev/null
        echo "User $username has been created"

        sudo usermod -aG wheel $username
        echo "Add $username to sudoers"

        sudo mkdir /home/$username/.ssh
        sudo chmod 700 /home/$username/.ssh
        sudo touch /home/$username/.ssh/authorized_keys
        sudo chmod 600 /home/$username/.ssh/authorized_keys
        sudo chown -R $username:$username /home/$username/.ssh
        echo "Create .ssh file, please paste your id_rsa.pub here: "
        sudo vi /home/$username/.ssh/authorized_keys

        sudo groupadd certusers
        echo "Group certusers has been created"

        sudo useradd -r -M -G certusers trojan
        sudo useradd -r -m -G certusers acme
        echo "Users trojan,acme have been created"

        sudo usermod -aG docker $username
        ;;
    -setfirewall)
        echo "Enter your IPv4 address: "
        read YourIPaddress
        echo "Enter your New SSH port: "
        read NewSSHport

        sudo sed -i "s/#Port 22/Port $NewSSHport/" /etc/ssh/sshd_config
        sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        echo "SSH config file updated"

        sudo firewall-cmd --permanent --zone=public --remove-service=ssh 
        sudo firewall-cmd --permanent --zone=public --add-service=http --add-service=https  
        sudo firewall-cmd --permanent --zone=public --add-rich-rule="rule family=\"ipv4\" source address=\"$(echo $YourIPaddress | cut -d '.' -f 1-3).0/24\" port protocol=\"tcp\" port=\"$NewSSHport\" accept"
        sudo firewall-cmd --reload
        sudo iptables -I IN_public_allow -s 0.0.0.0/0 -p tcp --dport $NewSSHport -m conntrack --ctstate NEW -m time --timestart 13:14 --timestop 13:44 -j ACCEPT
        sudo semanage port -a -t ssh_port_t -p tcp $NewSSHport
        echo "Setting firewall finished"
        sudo systemctl restart sshd
        ;;
    -updatenginx)
        if [ ! -d "/etc/nginx/sites-available" ];then
            sudo mkdir /etc/nginx/sites-available
        fi
        if [ ! -d "/etc/nginx/sites-enabled" ];then
            sudo mkdir /etc/nginx/sites-enabled
        fi
        echo "Enter Server domain: "
        read Domainname

        echo "Enter server IPv4 address: "
        read ServerIPaddress

        echo "
        server {
            listen 127.0.0.1:80 default_server;
            server_name $Domainname;
            
            location / {
                proxy_pass https://store.steampowered.com;
            }
            
            client_header_timeout 120s;
            client_body_timeout 120s;

            location /dingtalk-smartkitty/ {
                proxy_set_header Host \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-Proto \$scheme;
                proxy_set_header X-Forwarded-For \$remote_addr;
                proxy_pass http://localhost:8090/;
            }
        }

        server {
            listen 127.0.0.1:80;
            server_name $ServerIPaddress;

            return 301 https://$Domainname\$request_uri;
        }

        server {
            listen 0.0.0.0:80;
            listen [::]:80;
            
            server_name _;
            
            location / {
                return 301 https://\$host\$request_uri;
            }

            location /.well-known/acme-challenge {
                root /var/www/acme-challenge;
            }
        }" | sed 's/^        //g' > /etc/nginx/sites-available/$Domainname
        sudo ln -s /etc/nginx/sites-available/$Domainname /etc/nginx/sites-enabled/
        sudo systemctl restart nginx
        ;;
    -maintrojans)
        sudo sed -i '37,54d' /etc/nginx/nginx.conf
        sudo sed -i '37i\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
        sudo setsebool -P httpd_can_network_connect true

        sudo mkdir -p /etc/letsencrypt/live
        sudo chown -R acme:acme /etc/letsencrypt/live
        sudo usermod -G certusers nginx
        sudo mkdir -p  /var/www/acme-challenge
        sudo chown -R acme:certusers /var/www/acme-challenge

        echo "Solve SELinux issue"
        sudo semanage fcontext -a -t httpd_sys_content_t '/var/www/acme-challenge(/.*)?'
        sudo restorecon -R /var/www/acme-challenge
        sudo systemctl enable nginx
        sudo systemctl restart nginx

        echo "CA application, and Install CA ...... "

        sudo su - acme -c "curl https://get.acme.sh | sh; exit;"

        sudo su -l acme << EOF
Domainname=$(ls /etc/nginx/sites-available/);
/home/acme/.acme.sh/acme.sh --set-default-ca --server letsencrypt;
/home/acme/.acme.sh/acme.sh --issue -d \$Domainname -w /var/www/acme-challenge;

/home/acme/.acme.sh/acme.sh --install-cert -d \$Domainname --key-file /etc/letsencrypt/live/private.key --fullchain-file /etc/letsencrypt/live/certificate.crt;
/home/acme/.acme.sh/acme.sh --upgrade --auto-upgrade;
chown -R acme:certusers /etc/letsencrypt/live;
chmod -R 750 /etc/letsencrypt/live;
exit;
EOF
        echo "Install trojan server ...... "
        sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
        sudo chown -R trojan:trojan /usr/local/etc/trojan
        sudo cp /usr/local/etc/trojan/config.json /usr/local/etc/trojan/config.json.bak

        echo "Enter the password: "
        read password
        sudo sed -i '8,9d' /usr/local/etc/trojan/config.json
        sudo sed -i "8i\        \"$password\"" /usr/local/etc/trojan/config.json
        sudo sed -i 's/^[[:space:]]*\"cert\".*/        \"cert\": \"\/etc\/letsencrypt\/live\/certificate.crt\",/' /usr/local/etc/trojan/config.json
        sudo sed -i 's/^[[:space:]]*\"key\".*/        \"key\": \"\/etc\/letsencrypt\/live\/private.key\",/' /usr/local/etc/trojan/config.json

        sudo sed -i '9i\User=trojan' /etc/systemd/system/trojan.service
        sudo systemctl daemon-reload
        sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/trojan
        sudo systemctl enable trojan
        sudo systemctl restart trojan

        echo "Automatically update CA"
        echo "0 0 1 * * killall -s SIGUSR1 trojan" | sudo -u trojan crontab -
        ;;
    -dingtalkgpt)
        # The new version does not work! Resolved Now! Re-pull the latest image
        wget https://raw.githubusercontent.com/eryajf/chatgpt-dingtalk/main/config.example.yml
        mv config.example.yml config.yml
        vi config.yml
        docker run -itd --name chatgpt -p 8090:8090  -v `pwd`/config.yml:/app/config.yml --restart=always  registry.cn-hangzhou.aliyuncs.com/ali_eryajf/chatgpt-dingtalk
        ;;
    -test)
        echo "Welcome to cyberspace!"
        ;;
    *)
        echo "Invalid option."
        exit 1
        ;;
esac
