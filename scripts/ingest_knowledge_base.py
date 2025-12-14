"""
Script to ingest security knowledge base into ChromaDB.
"""

import json
import logging
from pathlib import Path

from core.rag_engine import RAGEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def ingest_knowledge_base():
    """Ingest knowledge base documents into ChromaDB."""
    rag_engine = RAGEngine()

    knowledge_base_path = Path("data/knowledge_base")

    documents = []
    metadatas = []
    ids = []

    # Ingest MITRE ATT&CK
    mitre_file = knowledge_base_path / "mitre_attack.json"
    if mitre_file.exists():
        with open(mitre_file, "r") as f:
            mitre_data = json.load(f)
            for technique in mitre_data.get("techniques", []):
                doc_text = f"MITRE ATT&CK Technique {technique['id']}: {technique['name']}\n{technique['description']}"
                documents.append(doc_text)
                metadatas.append({
                    "source": "MITRE ATT&CK",
                    "type": "technique",
                    "technique_id": technique["id"],
                    "tactics": ", ".join(technique.get("tactics", [])),
                })
                ids.append(f"mitre_{technique['id']}")

    # Ingest OWASP Top 10
    owasp_file = knowledge_base_path / "owasp_top10.md"
    if owasp_file.exists():
        with open(owasp_file, "r") as f:
            content = f.read()
            # Split by sections
            sections = content.split("##")
            for section in sections[1:]:  # Skip title
                lines = section.strip().split("\n")
                if len(lines) > 0:
                    title = lines[0].strip()
                    description = "\n".join(lines[1:]).strip()
                    doc_text = f"{title}\n{description}"
                    documents.append(doc_text)
                    metadatas.append({
                        "source": "OWASP",
                        "type": "risk",
                        "category": title.split(":")[0] if ":" in title else title,
                    })
                    ids.append(f"owasp_{len(ids)}")

    # Ingest CWE Top 25
    cwe_file = knowledge_base_path / "cwe_top25.md"
    if cwe_file.exists():
        with open(cwe_file, "r") as f:
            content = f.read()
            sections = content.split("##")
            for section in sections[1:]:
                lines = section.strip().split("\n")
                if len(lines) > 0:
                    title = lines[0].strip()
                    description = "\n".join(lines[1:]).strip()
                    doc_text = f"{title}\n{description}"
                    documents.append(doc_text)
                    metadatas.append({
                        "source": "CWE",
                        "type": "weakness",
                        "cwe_id": title.split(":")[0] if ":" in title else "",
                    })
                    ids.append(f"cwe_{len(ids)}")

    # Add documents to RAG engine
    if documents:
        rag_engine.add_documents(documents, metadatas, ids)
        logger.info(f"Ingested {len(documents)} documents into knowledge base")
    else:
        logger.warning("No documents found to ingest")

    # Print stats
    stats = rag_engine.get_stats()
    logger.info(f"Knowledge base stats: {stats}")


if __name__ == "__main__":
    ingest_knowledge_base()

