## git clone git@github.com:gubaojian/uWebSockets.git

cd third_party/uWebSockets
git submodule init
git submodule update

cd uSockets
git submodule init
git submodule update

cd boringssl
git submodule init
git submodule update


## 代理下载代码
## export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 all_proxy=socks5://127.0.0.1:7890
