# mcp

MCP client for Looprig: protocol-neutral client (`pkg/client`), auth (`pkg/auth`), transports (`pkg/transport/{stdio,streamablehttp,sse}`), and the optional Harness adapter (`pkg/harness`). Wraps the official go-sdk without leaking its types.

Design doc: `../harness/docs/plans/2026-07-16-mcp-client-module-design.md`
