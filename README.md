## Как подготовить данные
1. Запустить Minikube: minikube start --driver=docker
2. Создать дамп: kubectl get role,clusterrole,rolebinding,clusterrolebinding -A -o yaml > cluster_dump.yaml

## Как запустить приложение
source venv/bin/activate
uvicorn app.main:app --reload

## Как поднять kubernetes dashboard
minikube dashboard

## Остановка

### В терминале, где запущен uvicorn
Ctrl+C
### В терминале, где запущен minikube
minikube stop
### В терминале, где запущен WSL
exit