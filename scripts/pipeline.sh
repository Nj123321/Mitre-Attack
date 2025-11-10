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
	# or
	# docker stop neo4j
	# docker rm neo4j
	echo "removing files"
	rm -r "$PROJECT_ROOT/data" "$PROJECT_ROOT/logs" "$PROJECT_ROOT/import" "$PROJECT_ROOT/plugins"
	echo "done"
	docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d
else
	echo "what the heck"
fi
