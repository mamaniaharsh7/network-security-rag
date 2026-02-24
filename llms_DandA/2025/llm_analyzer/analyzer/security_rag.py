#!/usr/bin/env python3
"""
Security RAG (Retrieval-Augmented Generation) Base Class
Reusable RAG system for security log analysis - Updated for modular structure
"""

import os
import json
import glob
import pickle
import sys
from typing import List, Dict, Tuple, Optional
import numpy as np

# Handle imports for both standalone and modular usage
try:
    from sentence_transformers import SentenceTransformer
    import faiss
except ImportError as e:
    print(f"❌ Missing required dependencies: {e}")
    print("💡 Install with: pip install sentence-transformers faiss-cpu")
    sys.exit(1)

class SecurityRAG:
    """
    Reusable RAG system for security document analysis
    Handles document chunking, embedding, indexing, and retrieval
    """
   
    def __init__(self, embedding_model: str = "all-mpnet-base-v2"):
        """
        Initialize the RAG system
        
        Args:
            embedding_model: HuggingFace model name for embeddings
        """
        print(f"🔧 Loading embedding model: {embedding_model}")
        try:
            self.embedding_model = SentenceTransformer(embedding_model)
            self.embedding_dimension = self.embedding_model.get_sentence_embedding_dimension()
        except Exception as e:
            print(f"❌ Error loading embedding model: {e}")
            print("💡 Falling back to smaller model...")
            try:
                self.embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
                self.embedding_dimension = self.embedding_model.get_sentence_embedding_dimension()
                print("✅ Loaded fallback model: all-MiniLM-L6-v2")
            except Exception as e2:
                print(f"❌ Failed to load any embedding model: {e2}")
                raise
        
        # Initialize empty vector store
        self.index = faiss.IndexFlatIP(self.embedding_dimension)
        self.chunks = []
        self.metadata = []
        
    def chunk_json_document(self, content: str, filename: str, chunk_size: int = 1000, overlap: int = 200) -> List[Dict]:
        """
        Intelligently chunk JSON security documents
        
        Args:
            content: Raw file content
            filename: Source filename
            chunk_size: Maximum words per chunk
            overlap: Overlapping words between chunks
            
        Returns:
            List of chunk dictionaries with text and metadata
        """
        chunks = []
        
        try:
            data = json.loads(content)
            
            # Process aggregations (most important for security analysis)
            if 'response' in data and 'aggregations' in data['response']:
                for agg_name, agg_data in data['response']['aggregations'].items():
                    chunk_text = f"Query: {filename}\nAggregation: {agg_name}\nData: {json.dumps(agg_data, indent=2)}"
                    chunks.append({
                        "text": chunk_text,
                        "filename": filename,
                        "section": f"aggregation_{agg_name}",
                        "type": "aggregation",
                        "importance": "high"  # Aggregations are usually most important
                    })
            
            # Process search hits (individual log entries)
            if 'response' in data and 'hits' in data['response']:
                hits = data['response']['hits']['hits']
                # Process all hits, not just top 10
                for i, hit in enumerate(hits):
                    chunk_text = f"Query: {filename}\nLog Entry {i+1}: {json.dumps(hit, indent=2)}"
                    chunks.append({
                        "text": chunk_text,
                        "filename": filename,
                        "section": f"hit_{i}",
                        "type": "hit",
                        "importance": "medium"
                    })
            """ 
            # Process metadata (query context)
            if 'metadata' in data:
                chunk_text = f"Query: {filename}\nQuery Metadata: {json.dumps(data['metadata'], indent=2)}"
                chunks.append({
                    "text": chunk_text,
                    "filename": filename,
                    "section": "metadata",
                    "type": "metadata",
                    "importance": "low"
                })
             
            # Process any other top-level keys that might contain useful data
            for key, value in data.items():
                if key not in ['response', 'metadata'] and isinstance(value, (dict, list)):
                    chunk_text = f"Query: {filename}\n{key.title()}: {json.dumps(value, indent=2)}"
                    chunks.append({
                        "text": chunk_text,
                        "filename": filename,
                        "section": f"data_{key}",
                        "type": "data",
                        "importance": "low"
                    })
            """
                
        except json.JSONDecodeError:
            # Fallback to text chunking for non-JSON files
            words = content.split()
            for i in range(0, len(words), chunk_size - overlap):
                chunk_words = words[i:i + chunk_size]
                chunk_text = " ".join(chunk_words)
                chunks.append({
                    "text": chunk_text,
                    "filename": filename,
                    "section": f"text_chunk_{i//chunk_size}",
                    "type": "text",
                    "importance": "medium"
                })
        except Exception as e:
            print(f"⚠️  Error processing {filename}: {e}")
            # Still try to create a basic chunk with the raw content
            chunks.append({
                "text": f"Raw content from {filename}:\n{content[:2000]}...",
                "filename": filename,
                "section": "raw_content",
                "type": "raw",
                "importance": "low"
            })
        
        return chunks
    
    def load_documents(self, directory: str, file_pattern: str = "*_result.json", recursive: bool = True) -> int:
        """
        Load and chunk all documents from directory (with recursive support)
        
        Args:
            directory: Directory path containing files
            file_pattern: Glob pattern for files to load
            recursive: Whether to search subdirectories
            
        Returns:
            Number of chunks created
        """
        print(f"🔍 Scanning directory: {directory} (recursive: {recursive})")
        
        if not os.path.exists(directory):
            print(f"❌ Directory does not exist: {directory}")
            return 0
        
        if recursive:
            # Search recursively using **/ pattern
            pattern = os.path.join(directory, "**", file_pattern)
            files = glob.glob(pattern, recursive=True)
        else:
            pattern = os.path.join(directory, file_pattern)
            files = glob.glob(pattern)
        
        if not files:
            print(f"❌ No files matching '{file_pattern}' found in {directory}")
            if recursive:
                # Try to list what files are actually there
                all_files = glob.glob(os.path.join(directory, "**", "*"), recursive=True)
                if all_files:
                    print(f"💡 Found {len(all_files)} total files. First few:")
                    for f in all_files[:5]:
                        if os.path.isfile(f):
                            print(f"   • {f}")
            return 0
        
        print(f"📁 Found {len(files)} files:")
        for file in files[:10]:  # Show first 10 files
            print(f"   {file}")
        if len(files) > 10:
            print(f"   ... and {len(files) - 10} more files")
        
        all_chunks = []
        files_processed = 0
        files_skipped = 0
        
        # Process each file
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    filename = os.path.basename(file_path)
                    relative_path = os.path.relpath(file_path, directory)
                    
                    # Check if file has meaningful data
                    if self._should_skip_file(content, filename):
                        print(f"⏭️  Skipped {relative_path}: No meaningful data")
                        files_skipped += 1
                        continue
                    
                    chunks = self.chunk_json_document(content, relative_path)  # Use relative path for context
                    all_chunks.extend(chunks)
                    files_processed += 1
                    print(f"✅ Processed {relative_path}: {len(chunks)} chunks")
                    
            except UnicodeDecodeError:
                try:
                    # Try different encoding
                    with open(file_path, 'r', encoding='latin1') as f:
                        content = f.read()
                        chunks = self.chunk_json_document(content, os.path.relpath(file_path, directory))
                        all_chunks.extend(chunks)
                        files_processed += 1
                        print(f"✅ Processed {file_path} (latin1 encoding): {len(chunks)} chunks")
                except Exception as e:
                    print(f"❌ Error processing {file_path}: {e}")
                    files_skipped += 1
            except Exception as e:
                print(f"❌ Error processing {file_path}: {e}")
                files_skipped += 1
        
        # Store chunks
        self.chunks = all_chunks
        print(f"📊 Summary: {files_processed} files processed, {files_skipped} files skipped, {len(all_chunks)} total chunks")
        return len(all_chunks)
    
    def _should_skip_file(self, content: str, filename: str) -> bool:
        """
        Determine if a file should be skipped based on content
        
        Args:
            content: Raw file content
            filename: Filename for context
            
        Returns:
            True if file should be skipped
        """
        try:
            # Skip very small files
            if len(content.strip()) < 50:
                return True
            
            data = json.loads(content)
            
            # Check if query returned no results
            if 'response' in data and 'hits' in data['response']:
                total_hits = data['response']['hits'].get('total', {})
                
                # Handle different total formats
                if isinstance(total_hits, dict):
                    hit_count = total_hits.get('value', 0)
                else:
                    hit_count = total_hits
                
                if hit_count == 0:
                    return True  # Skip files with no hits
            
            # Check if aggregations are empty
            if 'response' in data and 'aggregations' in data['response']:
                aggregations = data['response']['aggregations']
                
                # Check if all aggregations are empty
                all_empty = True
                for agg_name, agg_data in aggregations.items():
                    if isinstance(agg_data, dict):
                        # Check for buckets with data
                        if 'buckets' in agg_data and agg_data['buckets']:
                            all_empty = False
                            break
                        # Check for doc_count > 0
                        if 'doc_count' in agg_data and agg_data['doc_count'] > 0:
                            all_empty = False
                            break
                        # Check for value > 0 (for metric aggregations)
                        if 'value' in agg_data and agg_data['value'] > 0:
                            all_empty = False
                            break
                
                if all_empty:
                    return True  # Skip if all aggregations are empty
            
            # Always include files with errors (might be important)
            if 'error' in data or 'failures' in data.get('response', {}):
                return False
            
            return False  # Don't skip by default
            
        except json.JSONDecodeError:
            # For non-JSON files, check size
            return len(content.strip()) < 100  # Skip very small files
        except Exception:
            return False  # Don't skip on errors
    
    def build_index(self, cache_file: Optional[str] = None, force_rebuild: bool = False) -> bool:
        """
        Build FAISS vector index from loaded chunks
        
        Args:
            cache_file: Path to cache embeddings
            force_rebuild: Force rebuild even if cache exists
            
        Returns:
            True if successful
        """
        # Check for cached embeddings
        if cache_file and os.path.exists(cache_file) and not force_rebuild:
            return self._load_cached_index(cache_file)
        
        if not self.chunks:
            print("❌ No chunks available. Run load_documents first.")
            return False
        
        # Create embeddings
        print(f"🧠 Creating embeddings for {len(self.chunks)} chunks...")
        texts = [chunk['text'] for chunk in self.chunks]
        
        try:
            embeddings = self.embedding_model.encode(texts, show_progress_bar=True)
        except Exception as e:
            print(f"❌ Error creating embeddings: {e}")
            return False
        
        # Build FAISS index
        print("🔍 Building FAISS index...")
        try:
            self.index = faiss.IndexFlatIP(self.embedding_dimension)
            self.index.add(embeddings.astype('float32'))
        except Exception as e:
            print(f"❌ Error building FAISS index: {e}")
            return False
        
        # Store metadata
        self.metadata = [{
            "filename": chunk['filename'], 
            "section": chunk['section'], 
            "type": chunk['type'],
            "importance": chunk.get('importance', 'medium')
        } for chunk in self.chunks]
        
        # Cache embeddings
        if cache_file:
            self._save_cached_index(cache_file, embeddings)
        
        print(f"✅ Vector index built: {len(self.chunks)} chunks indexed")
        return True
    
    def _load_cached_index(self, cache_file: str) -> bool:
        """Load cached embeddings and rebuild index"""
        try:
            print(f"📦 Loading cached embeddings from {cache_file}")
            with open(cache_file, 'rb') as f:
                cache_data = pickle.load(f)
                self.chunks = cache_data['chunks']
                self.metadata = cache_data['metadata']
                embeddings = cache_data['embeddings']
                
                # Rebuild FAISS index
                self.index = faiss.IndexFlatIP(self.embedding_dimension)
                self.index.add(embeddings.astype('float32'))
                print(f"✅ Loaded {len(self.chunks)} cached chunks")
                return True
        except Exception as e:
            print(f"❌ Error loading cache: {e}")
            return False
    
    def _save_cached_index(self, cache_file: str, embeddings: np.ndarray):
        """Save embeddings to cache file"""
        try:
            # Ensure cache directory exists
            cache_dir = os.path.dirname(cache_file)
            if cache_dir and not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
            
            print(f"💾 Caching embeddings to {cache_file}")
            with open(cache_file, 'wb') as f:
                pickle.dump({
                    'chunks': self.chunks,
                    'metadata': self.metadata,
                    'embeddings': embeddings
                }, f)
        except Exception as e:
            print(f"❌ Error saving cache: {e}")
    
    def search(self, query: str, top_k: int = 10, importance_boost: Dict[str, float] = None) -> List[Tuple[str, float, Dict]]:
        """
        Search for relevant chunks using semantic similarity
        
        Args:
            query: Search query
            top_k: Number of results to return
            importance_boost: Boost scores by chunk importance
            
        Returns:
            List of (text, score, metadata) tuples
        """
        if len(self.chunks) == 0:
            return []
        
        try:
            # Create query embedding
            query_embedding = self.embedding_model.encode([query])
            
            # Search FAISS index
            scores, indices = self.index.search(query_embedding.astype('float32'), min(top_k * 2, len(self.chunks)))
            
            # Apply importance boosting
            if importance_boost is None:
                importance_boost = {"high": 1.2, "medium": 1.0, "low": 0.8}
            
            # Score and rank results
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(self.chunks):
                    metadata = self.metadata[idx]
                    importance = metadata.get('importance', 'medium')
                    boosted_score = float(score) * importance_boost.get(importance, 1.0)
                    
                    results.append((
                        self.chunks[idx]['text'],
                        boosted_score,
                        metadata
                    ))
            
            # Sort by boosted score and return top_k
            results.sort(key=lambda x: x[1], reverse=True)
            return results[:top_k]
        
        except Exception as e:
            print(f"❌ Error during search: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Get statistics about the loaded data"""
        if not self.chunks:
            return {"total_chunks": 0}
        
        stats = {
            "total_chunks": len(self.chunks),
            "files": len(set(chunk['filename'] for chunk in self.chunks)),
            "chunk_types": {},
            "importance_levels": {}
        }
        
        for chunk in self.chunks:
            chunk_type = chunk.get('type', 'unknown')
            importance = chunk.get('importance', 'unknown')
            
            stats["chunk_types"][chunk_type] = stats["chunk_types"].get(chunk_type, 0) + 1
            stats["importance_levels"][importance] = stats["importance_levels"].get(importance, 0) + 1
        
        return stats
    
    def clear(self):
        """Clear all data and reset the RAG system"""
        self.index = faiss.IndexFlatIP(self.embedding_dimension)
        self.chunks = []
        self.metadata = []
        print("🧹 RAG system cleared")

# Example usage and testing
if __name__ == "__main__":
    # Simple test
    print("🧪 Testing SecurityRAG...")
    
    rag = SecurityRAG()
    
    # Check if we have a results directory
    test_dirs = [".", "results", "../results", "../../results"]
    results_dir = None
    
    for test_dir in test_dirs:
        if os.path.exists(test_dir):
            files = glob.glob(os.path.join(test_dir, "*_result.json"))
            if files:
                results_dir = test_dir
                break
    
    if results_dir:
        print(f"📂 Found results directory: {results_dir}")
        
        # Load documents
        chunks_loaded = rag.load_documents(results_dir, "*_result.json")
        
        if chunks_loaded > 0:
            # Build index
            cache_file = "test_security_embeddings.pkl"
            success = rag.build_index(cache_file)
            
            if success:
                # Show stats
                stats = rag.get_stats()
                print(f"\n📊 RAG Stats: {stats}")
                
                # Test search
                test_queries = [
                    "infected host IP address",
                    "malware family",
                    "command and control",
                    "suspicious activity"
                ]
                
                for query in test_queries:
                    results = rag.search(query, top_k=3)
                    print(f"\n🔍 Search results for '{query}': {len(results)} found")
                    
                    for i, (text, score, meta) in enumerate(results, 1):
                        print(f"\n{i}. Score: {score:.3f} | {meta['filename']} | {meta['section']}")
                        print(f"Text preview: {text[:200]}...")
                        
                print(f"\n✅ Test complete! Cache saved to: {cache_file}")
            else:
                print("❌ Failed to build index")
        else:
            print("❌ No documents loaded")
    else:
        print("⚠️  No results directory found for testing")
        print("💡 Place some *_result.json files in a 'results' directory to test")
