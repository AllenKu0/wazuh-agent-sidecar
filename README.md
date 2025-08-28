* Docker Build
```
docker build -t wazuh-webhook:v1.0
docker tag wazuh-webhook:v1.0 <your_repository_username>/wazuh-webhook:v1.0
docker push <your_repository_username>/wazuh-webhook:v1.0
```
* 產生tls、ca檔
```
openssl genrsa -out tls.key 2048

openssl req -new -key tls.key -subj "/CN=wazuh-webhook-svc.default.svc" -out tls.csr

cat > config.cnf <<EOF
[ v3_ext ]
subjectAltName = DNS:wazuh-webhook-svc.default.svc,DNS:wazuh-webhook-svc,DNS:localhost
EOF

openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 365 -extfile config.cnf -extensions v3_ext
```
* 測試(順序很重要，先跑mwc會讓之後建pod都觸發webhook)
```
kubectl apply -f webhook.yaml 
<!-- 等webhook running -->
kubectl get po
kubectl apply -f mwc.yaml 
kubectl apply -f test.yaml 
```
