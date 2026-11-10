# Backend InsecureBankv2 cho quét động

Dựng AndroLabServer (Python 2) trong container, chỉ lắng nghe trên 127.0.0.1. ZAP dùng chung network namespace với
backend nên `http://127.0.0.1:8888` trỏ đúng backend cả trên máy Mac lẫn bên trong container ZAP.

```bash
git clone --depth 1 https://github.com/dineshshetty/Android-InsecureBankv2.git /tmp/ib
cp -R /tmp/ib/AndroLabServer 04_code/dynamic/backend/
docker build -t ib-backend 04_code/dynamic/backend
docker run -d --name ib-backend -p 127.0.0.1:8888:8888 -p 127.0.0.1:8090:8090 ib-backend
curl -s -X POST -d "username=dinesh&password=x" http://127.0.0.1:8888/login   # phải trả về JSON
docker run -d --name zap --network container:ib-backend zaproxy/zap-stable \
    zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=$ZAP_API_KEY \
    -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

`AndroLabServer/` không commit vào repo (mã của bên thứ ba).
