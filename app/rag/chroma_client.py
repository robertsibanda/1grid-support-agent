import chromadb
from chromadb.config import Settings as ChromaSettings
from app.config import settings

class ChromaService:
    def __init__(self):
        self.client = chromadb.PersistentClient(
            path=settings.chroma_db_path,
            settings=ChromaSettings(anonymized_telemetry=False)
        )

    def get_or_create_collection(self, name: str):
        return self.client.get_or_create_collection(name)

    def delete_collection(self, name: str):
        try:
            self.client.delete_collection(name)
        except ValueError:
            pass

    def list_collections(self):
        return self.client.list_collections()

    def add_documents(self, collection_name: str, documents: list[str],
                      metadatas: list[dict], ids: list[str]):
        collection = self.get_or_create_collection(collection_name)
        collection.add(documents=documents, metadatas=metadatas, ids=ids)

    def query(self, collection_name: str, query_text: str, n_results: int = 5):
        collection = self.get_or_create_collection(collection_name)
        results = collection.query(query_texts=[query_text], n_results=n_results)
        if not results["documents"] or not results["documents"][0]:
            return []
        output = []
        for i, doc in enumerate(results["documents"][0]):
            output.append({
                "content": doc,
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else None
            })
        return output
