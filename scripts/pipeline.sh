#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "starting root ============="
echo $PROJECT_ROOT
echo "========================="

if [[ "$1" == "start" ]]; then
	echo "starting pipeline"
	docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d
elif [[ "$1" == "stop" ]]; then
	echo "stopping piepeline"
	docker stop $(docker ps -q)
	docker rm $(docker ps -a -q)
	docker volume prune -f
elif [[ "$1" == "restart" ]]; then
	echo "composing donw"
	docker compose -f "$PROJECT_ROOT/docker-compose.yml" down -v
	echo "removing files"
	rm -r "$PROJECT_ROOT/neo4j"
	echo "done"
	docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d
elif [[ "$1" == "build" ]]; then
	echo "building images"
	docker build \
        -f "$PROJECT_ROOT/attack-stix-injestion/Dockerfile" \
        -t pipeline \
        "$PROJECT_ROOT"
	echo "done building piepline image"
elif [[ "$1" == "webbuild" ]]; then
	echo "building webservice"
	docker build \
        -f "$PROJECT_ROOT/mitre-crud/Dockerfile" \
        -t mitrecrud \
        "$PROJECT_ROOT"
	echo "done building webservice image"
else
	echo "what the heck"
fi
