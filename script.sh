#!/bin/bash
currDate=$(date +'%Y%m%d %T')
echo "$currDate -- Starting installation, please wait..." >> /opt/install.log

yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum install -y git wget lsof mlocate

currDate=$(date +'%Y%m%d %T')
echo "$currDate -- Base packages installed" >> /opt/install.log

# update certificates
yum install -y ca-certificates
update-ca-trust force-enable

currDate=$(date +'%Y%m%d %T')
echo "$currDate -- Certificates installed" >> /opt/install.log

# install python 3.7
currDate=$(date +'%Y%m%d %T')
echo "$currDate -- Begin install python 3.7" >> /opt/install.log

yum install -y gcc openssl-devel bzip2-devel libffi-devel

cd /opt
wget https://www.python.org/ftp/python/3.7.3/Python-3.7.3.tgz
tar xfz Python-3.7.3.tgz
cd /opt/Python-3.7.3 && ./configure --enable-optimizations
cd /opt/Python-3.7.3 && make altinstall
/usr/local/bin/pip3.7 install --upgrade pip
ln -s /usr/local/bin/pip /usr/bin/pip

currDate=$(date +'%Y%m%d %T')
echo "$currDate -- End install python 3.7" >> /opt/install.log

rm -rf /opt/Python-3.7*

currDate=$(date +'%Y%m%d %T')
echo "$currDate -- Finish installation" >> /opt/install.log
