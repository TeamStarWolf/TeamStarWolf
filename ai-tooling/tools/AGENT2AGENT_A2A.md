# Agent2Agent Protocol (A2A)

> In one minute: Agent2Agent (A2A) is an open protocol that lets AI agents built on different frameworks, by different vendors, discover each other and work together on tasks without exposing their internal memory, logic, or tools. Each agent publishes an Agent Card describing its skills, endpoints, and authentication needs, and clients send messages and track stateful tasks over HTTP(S). Google introduced it in April 2025 and it is now a Linux Foundation project; it complements MCP, which connects an agent to tools rather than to other agents.

| | |
|---|---|
| Category | Protocol |
| Maintainer | Linux Foundation (Agent2Agent project, launched June 2025 with the specification, SDKs, and tooling contributed by Google) |
| License / access | Open source (Apache 2.0) for the specification and SDKs |
| Official docs | [a2a-protocol.org](https://a2a-protocol.org/latest/) |
| Repository | [a2aproject/A2A](https://github.com/a2aproject/A2A) (SDKs include [a2aproject/a2a-python](https://github.com/a2aproject/a2a-python)) |
| Checked | 8 Oct 2026, specification 1.0 (repository release v1.0.1); Python `a2a-sdk` 1.2.2 |

## What it is for

- Let an orchestrator agent delegate work to specialist agents run by other teams or vendors.
- Connect agents built with different frameworks, for example ADK, LangGraph, or BeeAI, by exposing each one as an A2A server.
- Run long tasks with streaming status updates or push notifications to a webhook.
- Discover agents through Agent Cards at a well-known URL, a registry, or direct configuration.
- Exchange text, files, and structured JSON results as task artifacts.

## Quick start

This follows the official Python tutorial, which uses the `helloworld` echo agent from the samples repository. No model API key is needed.

1. Clone the samples repository.

   ```bash
   git clone https://github.com/a2aproject/a2a-samples.git -b main --depth 1
   cd a2a-samples
   ```

2. Create and activate a virtual environment (Python 3.10 or later), then install the SDK and sample dependencies.

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r samples/python/requirements.txt
   ```

3. Look at how the server declares a skill and its public Agent Card in `samples/python/agents/helloworld/__main__.py`:

   ```python
   skill = AgentSkill(
       id='echo_bot',
       name='Echo Bot',
       description='An example agent that acknowledges client request and responds with a "Hello World" message.',
       input_modes=['text/plain'],
       output_modes=['text/plain'],
       tags=['a2a', 'echo-example'],
       examples=['hi', 'how are you'],
   )

   public_agent_card = AgentCard(
       name='Hello World Agent',
       description='Just a hello world agent',
       version='0.0.1',
       default_input_modes=['text/plain'],
       default_output_modes=['text/plain'],
       capabilities=AgentCapabilities(streaming=True, extended_agent_card=True),
       supported_interfaces=[
           AgentInterface(
               protocol_binding='JSONRPC',
               url='http://127.0.0.1:9999',
               protocol_version='1.0',
           )
       ],
       skills=[skill],
   )
   ```

   The same file wires a `DefaultRequestHandler` (your agent executor plus an `InMemoryTaskStore`) into Starlette routes from `create_agent_card_routes` and `create_jsonrpc_routes`, then serves them with Uvicorn on `127.0.0.1:9999`.

4. Start the server.

   ```bash
   python samples/python/agents/helloworld/__main__.py
   ```

5. In a second terminal, activate the same virtual environment and run the test client. It fetches the Agent Card from `/.well-known/agent-card.json`, then sends a normal message and a streaming message.

   ```bash
   python samples/python/agents/helloworld/test_client.py
   ```

## Key concepts

- **A2A client and A2A server**: the client starts requests for a user or system; the server, also called the remote agent, exposes an A2A endpoint.
- **Agent Card**: a JSON document that describes an agent's identity, skills, service endpoints, and authentication requirements. Cards can be signed with JSON Web Signature (JWS).
- **Extended Agent Card**: a richer card, possibly with extra skills, returned only to authenticated clients.
- **Task**: the stateful unit of work, with a unique ID and a defined lifecycle. A context ID can group related tasks.
- **Message and Part**: a message is one turn with a role (user or agent); parts carry text, file references, or structured data.
- **Artifact**: an output the agent produces for a task, made of parts.
- **Streaming and push notifications**: incremental updates over a stream, or server-initiated HTTP POSTs to a client webhook.
- **Protocol bindings**: JSON-RPC 2.0, gRPC, and HTTP+JSON/REST, each declared in the Agent Card.

## Security notes

- Treat every remote agent as untrusted. Its messages and artifacts enter your model's context and can carry prompt injection, and A2A deliberately hides the remote agent's internals, so you cannot inspect what it runs. Authenticate it, limit what you delegate, and validate what comes back.
- The specification requires encrypted transport in production (HTTPS, or TLS for gRPC) and tells clients to verify the server's TLS certificate. The Agent Card declares the required authentication schemes (API key, HTTP auth, OAuth 2.0, OpenID Connect, mutual TLS). Clients obtain credentials out of band and send them in protocol headers or metadata, and servers must authenticate every request.
- Servers must check authorization on every operation and scope task listings to the caller. Implementations have gotten this wrong: [GHSA-qw47-mcm5-934w](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-qw47-mcm5-934w) was a fail-open default task authorization in the a2a-java server SDK (fixed in 1.3.0.Final).
- Push notifications create an SSRF path. The specification tells agents to validate webhook URLs, reject private, localhost, and link-local addresses, and use allowlists. a2a-java had exactly this flaw ([GHSA-q78c-5jjq-57g8](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-q78c-5jjq-57g8), fixed in 1.3.0.Final). Webhook receivers must verify that each notification is authentic.
- Discovery can be abused: a spoofed or altered Agent Card can point clients at a hostile endpoint. Verify card signatures where they are offered, pin the agents you trust, and keep internal URLs and credentials out of extended cards.
- Logs must not contain credentials or personal data; log authentication failures and rate-limit clients.
- Background reading: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [A2A documentation home](https://a2a-protocol.org/latest/)
- [A2A specification](https://a2a-protocol.org/latest/specification/)
- [Python tutorial](https://a2a-protocol.org/latest/tutorials/python/1-introduction/)
- [A2A and MCP](https://a2a-protocol.org/latest/topics/a2a-and-mcp/)
- [Enterprise-ready features](https://a2a-protocol.org/latest/topics/enterprise-ready/)
- [A2A short course (DeepLearning.AI)](https://www.deeplearning.ai/courses/a2a-the-agent2agent-protocol)
