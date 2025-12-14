"""Tests for RAG engine."""

import pytest
import tempfile
import shutil
from pathlib import Path

from core.rag_engine import RAGEngine


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def rag_engine(temp_dir):
    """Create RAG engine with temporary directory."""
    return RAGEngine(persist_directory=temp_dir)


def test_rag_engine_initialization(rag_engine):
    """Test RAG engine initialization."""
    assert rag_engine.collection_name == "security_knowledge"
    assert rag_engine.persist_directory is not None


def test_add_documents(rag_engine):
    """Test adding documents to knowledge base."""
    documents = [
        "This is a test document about security.",
        "Another document about vulnerabilities.",
    ]
    metadatas = [
        {"source": "test", "type": "document"},
        {"source": "test", "type": "document"},
    ]
    ids = ["doc1", "doc2"]

    rag_engine.add_documents(documents, metadatas, ids)

    stats = rag_engine.get_stats()
    assert stats["document_count"] == 2


def test_search(rag_engine):
    """Test searching the knowledge base."""
    documents = [
        "SQL injection is a common vulnerability.",
        "Cross-site scripting (XSS) attacks are dangerous.",
    ]
    metadatas = [
        {"source": "test", "type": "vulnerability"},
        {"source": "test", "type": "vulnerability"},
    ]
    ids = ["doc1", "doc2"]

    rag_engine.add_documents(documents, metadatas, ids)

    results = rag_engine.search("SQL injection", n_results=2)
    assert len(results) > 0
    assert "SQL" in results[0]["document"] or "injection" in results[0]["document"]


def test_get_context(rag_engine):
    """Test getting formatted context."""
    documents = [
        "Security best practices include strong passwords.",
        "Regular updates are important for security.",
    ]
    metadatas = [
        {"source": "test", "type": "guide"},
        {"source": "test", "type": "guide"},
    ]
    ids = ["doc1", "doc2"]

    rag_engine.add_documents(documents, metadatas, ids)

    context = rag_engine.get_context("security practices", n_results=2)
    assert len(context) > 0
    assert "security" in context.lower() or "Security" in context

