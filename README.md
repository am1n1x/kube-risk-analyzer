## Как подготовить данные
1. Запустить Minikube: minikube start --driver=docker
2. Создать дамп: kubectl get role,clusterrole,rolebinding,clusterrolebinding -A -o yaml > cluster_dump.yaml

## Как запустить
source venv/bin/activate
uvicorn app.main:app --reload

## Как остановить
minikube stop

## Как поднять kubernetes dashboard
minikube dashboard