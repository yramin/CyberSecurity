"""
RAG Engine for semantic search over security knowledge base.
Uses ChromaDB for vector storage and sentence-transformers for embeddings.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)


class RAGEngine:
    """RAG Engine for semantic search over security knowledge base."""

    def __init__(
        self,
        persist_directory: Optional[str] = None,
        collection_name: str = "security_knowledge",
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        """
        Initialize RAG Engine.

        Args:
            persist_directory: Directory to persist ChromaDB data
            collection_name: Name of the ChromaDB collection
            embedding_model: Model name for embeddings
        """
        self.persist_directory = persist_directory or os.path.join(
            os.getcwd(), "data", "chroma_db"
        )
        self.collection_name = collection_name
        self.embedding_model_name = embedding_model

        # Create persist directory if it doesn't exist
        Path(self.persist_directory).mkdir(parents=True, exist_ok=True)

        # Initialize embedding function
        try:
            self.embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=embedding_model
            )
            logger.info(f"Loaded embedding model: {embedding_model}")
        except Exception as e:
            logger.warning(f"Failed to load sentence-transformers, using default: {e}")
            self.embedding_function = embedding_functions.DefaultEmbeddingFunction()

        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=self.persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            ),
        )

        # Get or create collection
        try:
            self.collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self.embedding_function,
            )
            logger.info(f"Loaded existing collection: {collection_name}")
        except Exception:
            self.collection = self.client.create_collection(
                name=collection_name,
                embedding_function=self.embedding_function,
            )
            logger.info(f"Created new collection: {collection_name}")

    def add_documents(
        self,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None,
    ) -> None:
        """
        Add documents to the knowledge base.

        Args:
            documents: List of document texts
            metadatas: Optional list of metadata dictionaries
            ids: Optional list of document IDs
        """
        if not documents:
            return

        if ids is None:
            ids = [f"doc_{i}" for i in range(len(documents))]

        if metadatas is None:
            metadatas = [{}] * len(documents)

        try:
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
            )
            logger.info(f"Added {len(documents)} documents to knowledge base")
        except Exception as e:
            logger.error(f"Failed to add documents: {str(e)}")
            raise

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None,
        similarity_threshold: float = 0.7,
    ) -> List[Dict[str, Any]]:
        """
        Search the knowledge base.

        Args:
            query: Search query
            n_results: Number of results to return
            filter_metadata: Optional metadata filter
            similarity_threshold: Minimum similarity score

        Returns:
            List of search results with documents, metadata, and distances
        """
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                where=filter_metadata,
            )

            # Format results
            formatted_results = []
            if results["documents"] and len(results["documents"]) > 0:
                documents = results["documents"][0]
                metadatas = results["metadatas"][0] if results["metadatas"] else [{}] * len(documents)
                distances = results["distances"][0] if results["distances"] else [1.0] * len(documents)

                for doc, metadata, distance in zip(documents, metadatas, distances):
                    # Convert distance to similarity (ChromaDB uses cosine distance)
                    similarity = 1.0 - distance
                    if similarity >= similarity_threshold:
                        formatted_results.append(
                            {
                                "document": doc,
                                "metadata": metadata,
                                "similarity": similarity,
                                "distance": distance,
                            }
                        )

            return formatted_results

        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return []

    def get_context(
        self,
        query: str,
        max_context_length: int = 4000,
        n_results: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Get formatted context for LLM prompt.

        Args:
            query: Search query
            max_context_length: Maximum context length in characters
            n_results: Number of results to retrieve
            filter_metadata: Optional metadata filter

        Returns:
            Formatted context string
        """
        results = self.search(
            query=query,
            n_results=n_results,
            filter_metadata=filter_metadata,
        )

        if not results:
            return ""

        context_parts = []
        current_length = 0

        for result in results:
            doc = result["document"]
            metadata = result["metadata"]
            similarity = result["similarity"]

            # Format context entry
            source = metadata.get("source", "Unknown")
            doc_type = metadata.get("type", "document")
            entry = f"[Source: {source}, Type: {doc_type}, Similarity: {similarity:.2f}]\n{doc}\n\n"

            entry_length = len(entry)
            if current_length + entry_length > max_context_length:
                break

            context_parts.append(entry)
            current_length += entry_length

        return "".join(context_parts)

    def delete_collection(self) -> None:
        """Delete the collection (use with caution)."""
        try:
            self.client.delete_collection(name=self.collection_name)
            logger.warning(f"Deleted collection: {self.collection_name}")
        except Exception as e:
            logger.error(f"Failed to delete collection: {str(e)}")

    def reset_collection(self) -> None:
        """Reset the collection (delete and recreate)."""
        try:
            self.delete_collection()
            self.collection = self.client.create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_function,
            )
            logger.info(f"Reset collection: {self.collection_name}")
        except Exception as e:
            logger.error(f"Failed to reset collection: {str(e)}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get collection statistics.

        Returns:
            Dictionary with stats
        """
        try:
            count = self.collection.count()
            return {
                "collection_name": self.collection_name,
                "document_count": count,
                "embedding_model": self.embedding_model_name,
                "persist_directory": self.persist_directory,
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {str(e)}")
            return {
                "collection_name": self.collection_name,
                "document_count": 0,
                "error": str(e),
            }

