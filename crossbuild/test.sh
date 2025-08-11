openssl genrsa -out private.pem 2048
# 从私钥中提取公钥，保存为 public.pem（PEM 格式）
openssl rsa -in private.pem -pubout -out public.pem
openssl rsa -in private.pem -out private.der -outform DER
openssl asn1parse -inform der -in private.der

