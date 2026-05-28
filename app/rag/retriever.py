from app.rag.chroma_client import ChromaService

def retrieve_context(query: str, n_results: int = 5) -> str:
    chroma = ChromaService()
    results = chroma.query("kb_articles", query, n_results=n_results)

    if not results:
        return ""

    parts = []
    for r in results:
        title = r["metadata"].get("title", "Untitled")
        parts.append(f"--- {title} ---\n{r['content']}")

    return "\n\n".join(parts)

def retrieve_context_structured(query: str, n_results: int = 5) -> list[dict]:
    chroma = ChromaService()
    return chroma.query("kb_articles", query, n_results=n_results)
