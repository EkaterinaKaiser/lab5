Лабораторная 1 - выполнена

Выполнить после деплоя:

# Stop current EveBox container
docker stop root-evebox-1
docker rm root-evebox-1

# Relaunch with log volume mounted
docker run -d \
  --name root-evebox-1 \
  -v /var/log/suricata:/var/log/suricata:ro \
  -p 5636:5636 \
  jasonish/evebox:latest \
  evebox server --host 0.0.0.0 --port 5636 --input /var/log/suricata/eve.json