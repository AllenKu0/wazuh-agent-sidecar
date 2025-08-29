* Docker Build
```
docker build -t wazuh-webhook:v1.0 .
docker tag wazuh-webhook:v1.0 <your_repository_username>/wazuh-webhook:v1.0
docker push <your_repository_username>/wazuh-webhook:v1.0
```
* 產生tls、ca檔
```
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -subj "/CN=wazuh-webhook-ca" -days 365 -out ca.crt
<!-- cat 放到MutatingWebhookConfiguration的caBundle中，不能換行 -->
cat ca.crt | base64 | tr -d '\n'

openssl genrsa -out tls.key 2048

openssl req -new -key tls.key -subj "/CN=wazuh-webhook-svc.default.svc" -out tls.csr

cat > config.cnf <<EOF
[ v3_ext ]
subjectAltName = DNS:wazuh-webhook-svc.default.svc,DNS:wazuh-webhook-svc,DNS:localhost
EOF

openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 365 -extfile config.cnf -extensions v3_ext
```
* sercrete創建
```
kubectl create secret tls wazuh-webhook-tls --cert=tls.crt --key=tls.key
```
* 從wazuh server 看wazuh-wui的credential(sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt)
先編碼
```
echo -n 'wazuh-wui' | base64
```
存進 wazuh-manager-credentials.yaml 檔後
```
kubectl apply -f wazuh-manager-credentials.yaml
```
* 測試(順序很重要，先跑mwc會讓之後建pod都觸發webhook)
```
kubectl apply -f webhook.yaml 
<!-- 等webhook running -->
kubectl get po
kubectl apply -f mwc.yaml 
kubectl apply -f test.yaml 
```
