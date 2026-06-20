# virelia masking MCP proxy. stdio is the MCP protocol channel, so run with -i:
#   docker run -i --rm -v ~/.virelia:/config virelia \
#     proxy --config /config/upstreams.json --policy ngo-default
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN uv pip install --system --no-cache '.[proxy]'

RUN useradd --create-home virelia
USER virelia

ENTRYPOINT ["virelia"]
CMD ["version"]
