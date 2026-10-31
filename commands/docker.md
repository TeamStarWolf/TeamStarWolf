# Docker Command Reference

Docker packages an application and its dependencies into an image, then runs that image as an isolated container. The `docker` CLI talks to a local or remote daemon over a socket. This page covers the container lifecycle, image building, and the Dockerfile basics developers touch daily. Security notes cover the footguns that turn a container into host access.

## What it is and where it runs

Docker is a container engine. The `docker` client sends commands to the `dockerd` daemon, which pulls images, builds them, and runs containers using Linux namespaces and cgroups. The daemon usually runs as root, so access to it is effectively host-level access. On Linux the client reaches the daemon through `/var/run/docker.sock`. On Windows and macOS a lightweight Linux VM hosts the daemon behind Docker Desktop.

## Core commands

Run and inspect containers:

```bash
docker run -d --name web -p 8080:80 nginx:1.27
docker ps -a
docker logs -f web
docker exec -it web sh
docker inspect web
```

| Command | Purpose |
| --- | --- |
| `docker run` | Create and start a container from an image |
| `docker ps` | List running containers (`-a` for all) |
| `docker exec` | Run a command inside a running container |
| `docker logs` | Show a container's stdout and stderr |
| `docker inspect` | Print low-level JSON config for an object |
| `docker stop` / `docker rm` | Stop a container, then remove it |

Build and move images:

```bash
docker build -t myapp:1.0 .
docker images
docker pull alpine:3.20
docker push registry.example.com/myapp:1.0
docker rmi myapp:1.0
```

| Command | Purpose |
| --- | --- |
| `docker build` | Build an image from a Dockerfile |
| `docker images` | List local images |
| `docker pull` / `docker push` | Fetch from or send to a registry |
| `docker rmi` | Remove a local image |
| `docker cp` | Copy files between host and container |

Manage data and connectivity:

```bash
docker volume create appdata
docker volume ls
docker network create backend
docker network connect backend web
```

Compose multi-container apps from a `compose.yaml`:

```bash
docker compose up -d
docker compose ps
docker compose logs -f
docker compose down
```

Dockerfile essentials:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER 1000:1000
EXPOSE 8000
CMD ["python", "app.py"]
```

`FROM` sets the base image. `RUN` executes build steps. `COPY` adds files. `USER` drops to a non-root account. `EXPOSE` documents the listening port. `CMD` sets the default process.

## Common workflows

Build, run, and ship a service:

```bash
docker build -t registry.example.com/api:1.4 .
docker run -d --name api -p 3000:3000 registry.example.com/api:1.4
docker logs -f api
docker push registry.example.com/api:1.4
```

Debug a failing container without disturbing it:

```bash
docker ps -a
docker logs --tail 100 api
docker exec -it api sh
docker inspect api --format '{{.State.ExitCode}}'
```

Copy a config in and restart:

```bash
docker cp ./nginx.conf web:/etc/nginx/nginx.conf
docker restart web
docker exec web nginx -t
```

Clean up unused resources to reclaim disk:

```bash
docker container prune
docker image prune -a
docker volume prune
docker system df
```

## Flags and options worth knowing

| Flag | Applies to | Effect |
| --- | --- | --- |
| `-d`, `--detach` | `run` | Run in the background |
| `-it` | `run`, `exec` | Interactive terminal session |
| `-p host:container` | `run` | Publish a port to the host |
| `-v name:/path` | `run` | Mount a volume or bind mount |
| `-e KEY=value` | `run` | Set an environment variable |
| `--rm` | `run` | Delete the container on exit |
| `--restart` | `run` | Restart policy, for example `unless-stopped` |
| `--read-only` | `run` | Mount the root filesystem read-only |
| `--cap-drop` / `--cap-add` | `run` | Remove or grant Linux capabilities |
| `--memory`, `--cpus` | `run` | Cap resource usage |
| `-f`, `--file` | `build` | Point to a named Dockerfile |
| `--no-cache` | `build` | Rebuild without cached layers |

## Security notes

Run as a non-root user. A container process running as root maps to host UID 0 in many setups, so a breakout is a root breakout. Add a `USER` instruction and avoid default root (CWE-250: Execution with Unnecessary Privileges).

Never bake secrets into image layers. Tokens or keys added with `COPY` or `ENV` persist in the layer history even after a later `RM`, so anyone who pulls the image can extract them (CWE-540: Inclusion of Sensitive Information in Source Code). Pass secrets at runtime with mounted files, build secrets (`--secret`), or an external secret store.

Avoid `--privileged`. It disables most isolation and grants the container nearly all host capabilities. Prefer `--cap-drop=ALL` plus a minimal `--cap-add` set for only the capabilities a workload needs.

Mounting `/var/run/docker.sock` into a container gives that container full control of the daemon, and therefore the host. Treat any request to mount the socket as a privilege grant, not a convenience.

Harden the runtime. Use `--read-only` for the root filesystem with explicit writable `tmpfs` or volumes, set `--memory` and `--cpus` limits, and add `--security-opt no-new-privileges`. Scan images with a scanner such as Trivy or Grype, pin base images by digest (`FROM image@sha256:...`) rather than a mutable tag, and rebuild on a cadence to pick up patches. See /SECURE_CODING_REFERENCE.md for secret handling and least-privilege guidance.

## Resources

- Docker official documentation and the Dockerfile reference.
- Open Container Initiative (OCI) image and runtime specifications.
- CIS Docker Benchmark for host and daemon hardening.

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/kubectl.md
- /commands/linux-commands.md
- /commands/systemctl.md
