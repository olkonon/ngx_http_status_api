#!/bin/bash -x

DIR="$(pwd)"
NGINX_VERSION="1.27.4"
VTS_MODULE_VERSION="0.0.1"
STS_MODULE_VERSION="0.0.1"
DYNAMIC_HEALTHCHECK_VTS_MODULE_VERSION="0.0.1"

echo "Nginx version $NGINX_VERSION"
echo "Directory: $DIR"
mkdir -p $DIR/buildnginx/modules/ngx_module_vts/
wget "https://github.com/olkonon/ngx_module_vts/archive/refs/tags/v${VTS_MODULE_VERSION}.tar.gz"
tar -xzf v${VTS_MODULE_VERSION}.tar.gz
ls -la
mv ngx_module_vts-${VTS_MODULE_VERSION}/* $DIR/buildnginx/modules/ngx_module_vts/
rm v${VTS_MODULE_VERSION}.tar.gz


mkdir -p $DIR/buildnginx/modules/ngx_module_sts/
wget "https://github.com/olkonon/ngx_module_sts/archive/refs/tags/v${STS_MODULE_VERSION}.tar.gz"
tar -xzf v${STS_MODULE_VERSION}.tar.gz
ls -la
mv ngx_module_sts-${STS_MODULE_VERSION}/* $DIR/buildnginx/modules/ngx_module_sts/
rm v${STS_MODULE_VERSION}.tar.gz


mkdir -p $DIR/buildnginx/modules/ngx_healthcheck/
wget "https://github.com/olkonon/ngx_healthcheck/archive/refs/tags/v${DYNAMIC_HEALTHCHECK_VTS_MODULE_VERSION}.tar.gz"
tar -xzf v${DYNAMIC_HEALTHCHECK_VTS_MODULE_VERSION}.tar.gz
mv ngx_healthcheck-${DYNAMIC_HEALTHCHECK_STS_MODULE_VERSION}/* $DIR/buildnginx/modules/ngx_healthcheck/
rm v${DYNAMIC_HEALTHCHECK_STS_MODULE_VERSION}.tar.gz


mkdir -p $DIR/buildnginx/modules/ngx_http_status_api/
mv src $DIR/buildnginx/modules/ngx_http_status_api/
mv config $DIR/buildnginx/modules/ngx_http_status_api/

wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar -xzf nginx-${NGINX_VERSION}.tar.gz
mv nginx-${NGINX_VERSION}/* $DIR/buildnginx/
cd $DIR/buildnginx

./configure --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security' \
--build="nginx-${NGINX_VERSION}" \
--with-pcre \
--with-stream \
--with-http_ssl_module \
--with-http_stub_status_module \
--add-module=./modules/ngx_healthcheck/ \
--add-module=./modules/ngx_module_vts/ \
--add-module=./modules/ngx_module_sts/ \
--add-module=./modules/ngx_http_status_api/ \

make -j12