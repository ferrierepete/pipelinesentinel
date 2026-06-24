"""Known AI/ML package names for dependency filtering."""

AI_ML_PACKAGES: set[str] = {
    # LLM Frameworks
    "langchain", "langgraph", "langchain-core", "langchain-community",
    "langchain-openai", "langchain-anthropic", "langchain-google-genai",
    "langchain-text-splitters", "langchain-cohere", "langchain-fireworks",
    "langchain-huggingface", "langchain-mistralai", "langchain-pinecone",
    "langchain-qdrant", "langchain-chroma", "langchain-unstructured",
    "langchain-experimental", "langgraph-sdk", "langgraph-checkpoint",
    "langgraph-checkpoint-sqlite", "langgraph-cli",
    "litellm", "llamaindex", "llama-index", "llama-index-core",
    "llama-index-readers", "llama-index-vector-stores",
    # ML/Deep Learning
    "torch", "torchvision", "torchaudio", "tensorflow", "tensorflow-cpu",
    "jax", "jaxlib", "numpy", "pandas", "scikit-learn", "scipy",
    "transformers", "datasets", "huggingface-hub", "accelerate",
    "diffusers", "peft", "trl", "safetensors", "tokenizers",
    "sentence-transformers", "timm", "albumentations",
    # AI Provider SDKs
    "openai", "anthropic", "google-generativeai",
    "cohere", "mistralai", "fireworks-ai",
    # Vector Databases
    "chromadb", "faiss-cpu", "faiss-gpu", "pinecone-client",
    "qdrant-client", "weaviate-client", "milvus", "pymilvus",
    "langchain-chroma", "pgvector",
    # AI Agent Frameworks
    "crewai", "autogen-agentchat", "smolagents",
    "instructor", "guidance", "marvin", "phidata",
    "agno", "camel-ai", "pydantic-ai",
    # Tokenization & Embedding
    "tiktoken", "sentencepiece", "onnxruntime",
    # Inference
    "vllm", "xformers", "triton", "deepspeed",
    "bitsandbytes", "flash-attn",
    # MLOps
    "mlflow", "wandb", "optuna", "ray", "dvc",
    "tensorboard", "clearml", "neptune-client",
    # AI Security
    "llm-guard", "prompt-guard", "garak",
    # AI Data
    "dvc", "datasets",
}


def is_ai_ml_package(name: str) -> bool:
    """Check if a package name is a known AI/ML package."""
    normalized = name.lower().replace("-", "").replace("_", "").replace(".", "")
    for pkg in AI_ML_PACKAGES:
        norm_pkg = pkg.replace("-", "").replace("_", "").replace(".", "")
        if normalized == norm_pkg or normalized.startswith(norm_pkg):
            return True
    return False
