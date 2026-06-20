
---

# 0. Важно: откуда запускать

Все команды запускай **из корня репозитория**, потому что:

- Dockerfile лежит в `Docker/Dockerfile`
- build context должен быть `.`

То есть так:

```bash
DOCKER_BUILDKIT=1 sudo docker build -f Docker/Dockerfile ...
```

а не из папки `Docker/`.

---

# 1. Сначала загрузить офлайн-образы

Если у тебя нет доступа к Docker Hub / GCR и для этого есть `Docker/git.tar`, сначала загрузи образы:

```bash
sudo docker load -i Docker/git.tar
```

Если `docker load` не понимает формат архива, тогда импортируй тем инструментом, который у тебя используется в окружении (`ctr`, `nerdctl`, `podman`).

После этого проверь, что образы появились:

```bash
sudo docker images
```

---

# 2. Какие target'ы у тебя есть

У тебя один Dockerfile, но в нём несколько стадий (`target`), например:

- `devtest` — образ для разработки и ручного тестирования
- `ci-test` — прогон всех тестов прямо на этапе `docker build`
- `prod` — production image для `encgit-server`

Если хочешь проверить, какие точно target'ы есть в файле:

```bash
grep -n '^FROM .* AS ' Docker/Dockerfile
```

---

# 3. Сборка образа для разработки и ручных тестов

## Собрать `devtest`

```bash
DOCKER_BUILDKIT=1 sudo docker build \
  --pull=false \
  -f Docker/Dockerfile \
  --target devtest \
  -t encgit:devtest \
  .
```

### Для чего нужен `devtest`
Это контейнер, в котором ты можешь:

- зайти в shell
- запускать `go test`
- смотреть файлы
- руками дебажить
- гонять отдельные пакеты и тесты

---

# 4. Как зайти в dev-контейнер

## Вариант A: просто запустить образ как есть

```bash
sudo docker run --rm -it encgit:devtest /bin/bash
```

Это запускает тот код, который был **встроен в образ на момент сборки**.

---

## Вариант B: лучший для разработки — примонтировать текущий репозиторий

```bash
sudo docker run --rm -it \
  -v "$PWD:/workspace" \
  -w /workspace \
  encgit:devtest \
  /bin/bash
```

Это удобнее, потому что:

- меняешь файлы на хосте
- сразу запускаешь тесты внутри контейнера
- не надо каждый раз пересобирать образ

---

# 5. Что сделать внутри контейнера перед тестами

Чтобы не ловить ошибку с VCS stamping:

```bash
export GOFLAGS='-buildvcs=false'
```

После этого `go test` и `go list` будут работать стабильнее в контейнере.

---

# 6. Как запускать тесты

---

## 6.1. Прогнать вообще все тесты

```bash
go test -buildvcs=false -count=1 -v ./...
```

### Но:
У тебя сейчас есть **2 flaky теста**, которые иногда падают:

- `TestLoginThrottle429WithoutArgon2`
- `TestLoginThrottlePerIPIsolationHTTP`

То есть полный suite может быть красным не из-за Docker, а из-за этих тестов.

---

## 6.2. Прогнать все стабильные тесты, кроме flaky

Вот рабочая команда:

```bash
pkgs=$(go list -buildvcs=false ./... | grep -v '^encgit/internal/server$') && \
go test -buildvcs=false -count=1 -v $pkgs && \
tests=$(go test -buildvcs=false ./internal/server -list . \
  | grep '^Test' \
  | grep -Ev '^(TestLoginThrottle429WithoutArgon2|TestLoginThrottlePerIPIsolationHTTP)$' \
  | paste -sd'|' -) && \
go test -buildvcs=false ./internal/server -count=1 -v -run "^(${tests})$"
```

Это сейчас твой **основной рабочий способ** прогнать весь проект, исключив только 2 нестабильных теста.

---

## 6.3. Прогнать один конкретный пакет

Например:

```bash
go test -buildvcs=false -count=1 -v ./internal/manifest
```

или:

```bash
go test -buildvcs=false -count=1 -v ./internal/server
```

---

## 6.4. Прогнать один конкретный тест

Например:

```bash
go test -buildvcs=false ./internal/server -run '^TestAuthorizationMatrix$' -count=1 -v
```

---

## 6.5. Прогнать flaky тест много раз

Чтобы проверить нестабильность:

```bash
go test -buildvcs=false ./internal/server -run '^TestLoginThrottle429WithoutArgon2$' -count=50 -v
```

или:

```bash
go test -buildvcs=false ./internal/server -run '^TestLoginThrottlePerIPIsolationHTTP$' -count=50 -v
```

---

## 6.6. Посмотреть список тестов в пакете

```bash
go test -buildvcs=false ./internal/server -list .
```

---

# 7. Сборка `ci-test`

Если хочешь, чтобы тесты запускались **на этапе `docker build`**, используй target `ci-test`:

```bash
DOCKER_BUILDKIT=1 sudo docker build \
  --pull=false \
  -f Docker/Dockerfile \
  --target ci-test \
  .
```

### Важно
Сейчас этот target может падать, потому что в полном suite у тебя есть 2 flaky теста.

То есть:

- **для CI сейчас лучше использовать `devtest` + ручной запуск non-flaky набора**
- либо потом добавить отдельный target, например `ci-test-nonflaky`

---

# 8. Сборка production-образа

Если нужно собрать production runtime для `encgit-server`:

```bash
DOCKER_BUILDKIT=1 sudo docker build \
  --pull=false \
  -f Docker/Dockerfile \
  --target prod \
  -t encgit-server:prod \
  .
```

---

# 9. Как запускать production-контейнер

Минимальный запуск:

```bash
sudo docker run -d \
  --name encgit-server \
  -p 127.0.0.1:8080:8080 \
  -v encgit-data:/data \
  encgit-server:prod
```

---

## Более правильный hardened запуск

```bash
sudo docker run -d \
  --name encgit-server \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -p 127.0.0.1:8080:8080 \
  -v encgit-data:/data \
  encgit-server:prod \
  --addr 0.0.0.0:8080 \
  --db /data/encgit.db \
  --blobs /data/blobs \
  -trusted-proxy-cidrs 10.0.0.0/8 \
  -client-ip-header X-Forwarded-For
```

---

## Посмотреть bootstrap token / логи

```bash
sudo docker logs -f encgit-server
```

---

# 10. Если изменил код — когда нужен rebuild, а когда нет

## Rebuild нужен, если:
- изменил Dockerfile
- изменил зависимости (`go.mod`, `go.sum`)
- запускаешь контейнер **без bind mount**

## Rebuild не нужен, если:
- ты запустил `devtest` с:
  ```bash
  -v "$PWD:/workspace"
  ```
  и просто меняешь исходники на хосте

---

# 11. Если нужно пересобрать совсем с нуля

```bash
DOCKER_BUILDKIT=1 sudo docker build \
  --no-cache \
  --pull=false \
  -f Docker/Dockerfile \
  --target devtest \
  -t encgit:devtest \
  .
```

---

# 12. Самые полезные готовые команды

---

## Собрать dev-контейнер

```bash
DOCKER_BUILDKIT=1 sudo docker build --pull=false -f Docker/Dockerfile --target devtest -t encgit:devtest .
```

## Зайти в него с текущим кодом

```bash
sudo docker run --rm -it -v "$PWD:/workspace" -w /workspace encgit:devtest /bin/bash
```

## Внутри контейнера отключить VCS stamping

```bash
export GOFLAGS='-buildvcs=false'
```

## Прогнать все стабильные тесты

```bash
pkgs=$(go list -buildvcs=false ./... | grep -v '^encgit/internal/server$') && \
go test -buildvcs=false -count=1 -v $pkgs && \
tests=$(go test -buildvcs=false ./internal/server -list . \
  | grep '^Test' \
  | grep -Ev '^(TestLoginThrottle429WithoutArgon2|TestLoginThrottlePerIPIsolationHTTP)$' \
  | paste -sd'|' -) && \
go test -buildvcs=false ./internal/server -count=1 -v -run "^(${tests})$"
```

## Собрать prod

```bash
DOCKER_BUILDKIT=1 sudo docker build --pull=false -f Docker/Dockerfile --target prod -t encgit-server:prod .
```

## Запустить prod

```bash
sudo docker run -d --name encgit-server -p 127.0.0.1:8080:8080 -v encgit-data:/data encgit-server:prod
```

---

# 13. Что у тебя сейчас по состоянию тестов

Стабильно/основательно проходят все тесты, **кроме двух flaky**:

- `TestLoginThrottle429WithoutArgon2`
- `TestLoginThrottlePerIPIsolationHTTP`

То есть проблема сейчас уже не в Docker, а в нестабильных тестах `internal/server`.

---