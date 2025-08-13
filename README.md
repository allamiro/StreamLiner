# StreamLiner

A universal log parser that normalizes and converts logs for any SIEM—Elastic, OpenSearch, Splunk, ArcSight, QRadar, and more.

## Features
- **Deterministic parsing:** ECS/CEE/CLS mappings for consistent dashboards.
- **Tiny pipelines:** `input → parser → output` in a few lines.
- **Broad I/O:** Syslog, HTTP, Kafka in; Elastic/OpenSearch/Splunk/ArcSight/QRadar/S3 out.
- **Edge enrichment:** GeoIP, ASN, basic threat tagging, dedup.
- **No lock-in:** Swap outputs without changing pipelines.

## Quick Start
```bash
docker run -p 514:514/udp \
  -v $(pwd)/streamliner.ini:/etc/streamliner.ini \
  ghcr.io/allamiro/streamliner:latest


## Contributing

Issues and PRs are welcome. Please open a discussion before large changes.

## License

* MIT