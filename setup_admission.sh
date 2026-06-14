#!/bin/bash
# Останавливаем скрипт при любой ошибке
set -e

echo "=================================================="
echo "🛡️  АВТОМАТИЧЕСКАЯ НАСТРОЙКА PROACTIVE ADMISSION CONTROL"
echo "=================================================="

# 1. Динамически определяем текущий IP-адрес WSL
WSL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$WSL_IP" ]; then
    echo "❌ Ошибка: не удалось определить IP-адрес WSL."
    exit 1
fi
echo "📡 Обнаружен рабочий IP-адрес WSL: $WSL_IP"

# 2. Генерируем конфигурационный файл для OpenSSL SAN
echo "🔑 Генерация конфигурации SAN для сертификатов..."
cat <<EOF > req.cnf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = host.minikube.internal
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $WSL_IP
EOF

# 3. Выпускаем корневой сертификат CA
echo "📦 Генерация корневого сертификата CA..."
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -subj "/CN=KubeRiskCA" -days 365 -out ca.crt 2>/dev/null

# 4. Выпускаем серверный закрытый ключ и запрос
echo "🔑 Генерация серверных ключей..."
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -subj "/CN=$WSL_IP" -out server.csr -config req.cnf 2>/dev/null

# 5. Подписываем серверный сертификат
echo "✍️  Подпись серверного сертификата нашим CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile req.cnf 2>/dev/null

# Удаляем временные файлы конфигурации
rm -f req.cnf server.csr ca.srl

# 6. Кодируем CA в Base64 без переносов строк
echo "🔄 Кодирование ca.crt в Base64..."
CA_BUNDLE=$(base64 -w 0 ca.crt)

# 7. Генерируем динамический манифест admission-webhook.yaml
echo "📄 Создание файла конфигурации admission-webhook.yaml..."
cat <<EOF > admission-webhook.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: kube-risk-admission-webhook
webhooks:
  - name: validate.kuberisk.io
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
        scope: "Namespaced"
    clientConfig:
      url: "https://$WSL_IP:8000/admission/validate"
      caBundle: $CA_BUNDLE
    admissionReviewVersions: ["v1"]
    sideEffects: None
    timeoutSeconds: 5
    failurePolicy: Ignore
EOF

# 8. Применяем манифест в Minikube
echo "☸️  Применение конфигурации вебхука в Kubernetes..."
kubectl apply -f admission-webhook.yaml

echo "=================================================="
echo "🎉 НАСТРОЙКА УСПЕШНО ЗАВЕРШЕНА!"
echo "=================================================="
echo "Для запуска FastAPI в защищенном режиме выполни:"
echo "uvicorn app.main:app --host 0.0.0.0 --port 8000 --ssl-keyfile=server.key --ssl-certfile=server.crt"
echo "=================================================="