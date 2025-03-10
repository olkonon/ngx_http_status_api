#!/bin/bash -x

DIR="$(pwd)"
NGINX_VERSION="1.27.3"
VTS_MODULE_VERSION="v0.0.1"
DYNAMIC_HEALTHCHECK_VTS_MODULE_VERSION="v0.0.1"

echo "Nginx version $NGINX_VERSION"
echo "Directory: $DIR"
mkdir -p $DIR/buildnginx/modules/ngx_module_vts/
wget "https://github.com/olkonon/ngx_module_vts/archive/refs/tags/${VTS_MODULE_VERSION}.tar.gz"
tar -xzf ${VTS_MODULE_VERSION}.tar.gz $DIR/buildnginx/modules/ngx_module_vts/
rm ${VTS_MODULE_VERSION}.tar.gz


mkdir -p $DIR/buildnginx/modules/ngx_healthcheck/
wget "https://github.com/olkonon/ngx_healthcheck/archive/refs/tags/${DYNAMIC_HEALTHCHECK_VTS_MODULE_VERSION}.tar.gz"
tar -xzf ${DYNAMIC_HEALTHCHECK_VTS_MODULE_VERSION}.tar.gz $DIR/buildnginx/modules/ngx_healthcheck/
rm ${DYNAMIC_HEALTHCHECK_VTS_MODULE_VERSION}.tar.gz


mkdir -p $DIR/buildnginx/modules/ngx_http_status_api/
mv src $DIR/buildnginx/modules/ngx_http_status_api/
mv config $DIR/buildnginx/modules/ngx_http_status_api/

wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar -xzf nginx-${NGINX_VERSION}.tar.gz
mv nginx-${NGINX_VERSION}/* $DIR/buildnginx/
cd $DIR/buildnginx

./configure --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security' --with-pcre --with-stream --with-http_ssl_module --add-module=./modules/ngx_healthcheck/
--add-module=./modules/ngx_module_vts/ --add-module=./modules/ngx_http_status_api/
make -j12