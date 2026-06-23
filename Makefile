.PHONY: build run stop compose-up compose-down k8s-apply k8s-delete health logs install test

IMAGE   ?= cardioai-backend
TAG     ?= latest
NS      ?= cardioai

install:
	pip install -r requirements.txt

test:
	pytest ../tests/test_iomt_cardioai_handshake.py -v

build:
	docker build -t $(IMAGE):$(TAG) .

run: build
	docker run -d \
	  --name cardioai-backend \
	  --restart unless-stopped \
	  --env-file .env \
	  -p 8765:8765 \
	  -p 8080:8080 \
	  $(IMAGE):$(TAG)

stop:
	docker stop cardioai-backend || true
	docker rm   cardioai-backend || true

compose-up:
	docker-compose up -d --build

compose-down:
	docker-compose down

k8s-apply:
	kubectl apply -k k8s/

k8s-delete:
	kubectl delete -k k8s/

health:
	curl -sf http://localhost:8080/health | python3 -m json.tool

logs:
	docker logs -f cardioai-backend 2>/dev/null || journalctl -u cardioai -f
