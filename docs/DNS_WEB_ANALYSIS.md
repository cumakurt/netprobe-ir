# DNS and web access analysis

The **DNS Queries** and **Web Access** navigation items show independently retained observations from the capture pipeline. The active view refreshes every second, including when the main WebSocket is unavailable. Search matches all supplied whitespace-separated terms against record metadata (case insensitive). Older/Newer uses a stable observation cursor; browsing history stops automatic refresh. Pause affects the display only. Resume returns to the latest records.

DNS records include UDP and framed TCP messages, transaction IDs, query/response direction, all decoded questions and their types, response codes, and decoded A/AAAA answers. Repeated queries remain separate observations. TCP retransmissions and ACKs do not produce duplicate messages.

Web records distinguish HTTP/1 requests, HTTP/1 responses, TLS handshakes, and port-based encrypted connection hints. HTTP headers expose host, path, method, status and user agent when captured. Sequential HTTP/1 messages are framed using their bodies; encrypted connections do not represent individual HTTPS requests. TLS SNI, version and ALPN are displayed when decoded. Connection hints are explicitly labelled with classification confidence.

## Capture and retention limits

Only traffic visible to the selected capture interfaces can be analyzed. Each category retains the latest 10,000 observations in memory, independently of the general packet/flow window. The screen reports lifetime observed, retained, matching and evicted counts. Restarting the daemon clears these records. This is not a persistent, exhaustive audit archive.

Encrypted DNS (DoH/DoT) does not expose query contents. HTTPS, QUIC/HTTP3 and encrypted HTTP/2 do not expose paths, methods, response codes or bodies without decryption. Generic TLS handshakes can also belong to non-web applications. HTTP/2 stream headers are not decoded into individual requests here.

TCP reconstruction is bounded by `dpi.max_stream_bytes`. Missing capture segments, captures started mid-stream, oversized incomplete messages and ambiguous HTTP response framing can prevent later messages from being decoded. HTTP headers are recorded before waiting for the body; close-delimited responses cannot be advanced until connection closure. Existing TLS parsing limits still apply. DNS answers currently expose decoded A/AAAA values.

## Read API

- `GET /api/v1/access/dns`
- `GET /api/v1/access/web`

Both require `read:packets`. Parameters: `q` (maximum 512 bytes), `limit` (1–500, default 100), `before` (exclusive unsigned observation ID). Responses contain `items`, `total`, `retained`, `matched`, `evicted`, `capacity`, and `next`. Pass a nonzero `next` as `before` to get the next older page. IDs are category-local; each item carries its flow ID for correlation. The read API rejects mutation methods and invalid parameters.
