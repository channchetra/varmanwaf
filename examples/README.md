# Examples

- [static-serve](./static-serve/README.md)
- [api-gateway](./api-gateway/README.md)
- [web-socket](./web-socket/README.md)
- [grpc-web](./grpc-web/README.md)
- [transparent-proxy](./transparent-proxy/README.md)

## Grpc-Web

- Insecure grpc-server
- Commonjs example static
- Locally trusted development certificates for 127.0.0.1

The key points of configuration are as follows:

- [upstreams.grpc-server] should choose h2 alpn
- [servers.grpc-web] should select grpc-web module
- [locations.grpc-server] should enable grpc_web

```bash
cargo run -- -c=~/github/pingap/examples/grpc-web.toml --admin=pingap:123123@127.0.0.1:3018
```

`--admin` builds a listener that requires credentials. Percent-encode the
characters that are special in a URL (`@` → `%40`, `:` → `%3A`, space → `%20`),
e.g. `--admin='user:p%40ss@127.0.0.1:3018'`. To serve the admin API without
authentication on purpose, declare the plugin with `allow_unauthenticated = true`
instead of omitting the credentials: an empty `authorizations` list now fails
startup.

## Transparent Proxy

- Upstream discovery should be `transparent`
- Upstream sni should be `$host` for https
- Certificate should be set as default for all domains

```bash
sudo cargo run -- -c=~/github/pingap/examples/transparent-proxy.toml --admin=pingap:123123@127.0.0.1:3018
```

```bash
curl -kv --resolve '*:443:127.0.0.1' 'https://cn.bing.com/'
```

