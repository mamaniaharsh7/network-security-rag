#!/usr/bin/env python3
"""
Memory-Optimized Cisco Foundation Client
Specifically optimized for Apple Silicon memory constraints
"""

import os
import sys
import platform
from typing import Optional
import torch

# Add paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from base_llm_client import BaseLLMClient

class CiscoFoundationLocalClient(BaseLLMClient):
    """
    Memory-optimized Cisco Foundation-Sec-8B client for Apple Silicon
    """
    
    def __init__(self, model: str = "fdtn-ai/Foundation-Sec-8B-Instruct", 
                 device: str = "auto", force_cpu: bool = False, **kwargs):
        """
        Initialize with memory optimization for Apple Silicon
        
        Args:
            model: Model name
            device: Device preference
            force_cpu: Force CPU usage (avoids MPS memory issues)
            **kwargs: Additional configuration
        """
        super().__init__(model=model, device=device, force_cpu=force_cpu, **kwargs)
        self.model_name = model
        self.device = device
        self.force_cpu = force_cpu
        
        # Initialize model and tokenizer as None (lazy loading)
        self.model = None
        self.tokenizer = None
        self.loaded = False
        self.actual_device = None
        self.os_type = platform.system()
        self.cpu_arch = platform.machine()
        
        print(f"🛡️  Cisco Foundation-Sec-8B (Memory Optimized)")
        print(f"💻 System: {self.os_type} ({self.cpu_arch})")
        print(f"💾 Memory optimization: Enabled for Apple Silicon")
        
        # Check available memory
        if self.os_type == "Darwin" and self.cpu_arch == "arm64":
            print(f"🍎 Apple Silicon detected - using CPU to avoid MPS memory limits")
            self.force_cpu = True
    
    def _get_optimal_device(self):
        """Get optimal device considering memory constraints"""
        
        # Force CPU if requested (recommended for Apple Silicon due to memory limits)
        if self.force_cpu:
            print(f"🖥️  Using CPU (recommended for memory efficiency)")
            return "cpu"
        
        # Check CUDA first (Linux/Windows)
        if torch.cuda.is_available():
            gpu_memory = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            print(f"🚀 CUDA available: {gpu_memory:.1f}GB VRAM")
            if gpu_memory >= 8:  # Need at least 8GB for this model
                return "cuda"
            else:
                print(f"⚠️  GPU has only {gpu_memory:.1f}GB, using CPU")
                return "cpu"
        
        # Check MPS (macOS) but be cautious about memory
        elif (self.os_type == "Darwin" and 
              hasattr(torch.backends, 'mps') and 
              torch.backends.mps.is_available()):
            print(f"🍎 Apple MPS available but may have memory limits")
            print(f"💡 Using CPU for stability (model needs ~7GB)")
            return "cpu"
        
        # CPU fallback
        else:
            print(f"🖥️  Using CPU optimization")
            return "cpu"
    
    def _load_model(self):
        """Load model with memory optimization"""
        if self.loaded:
            return True
        
        try:
            print(f"📥 Loading Cisco Foundation-Sec-8B (memory optimized)...")
            
            # Import transformers
            from transformers import AutoTokenizer, AutoModelForCausalLM
            
            # Load tokenizer
            print(f"🔤 Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Determine device
            if self.device == "auto":
                self.actual_device = self._get_optimal_device()
            else:
                self.actual_device = self.device
            
            # Memory-optimized loading
            print(f"🧠 Loading model with memory optimization...")
            print(f"💾 Target device: {self.actual_device}")
            
            # Use memory-efficient loading
            model_kwargs = {
                "torch_dtype": torch.float16,     # Half precision
                "low_cpu_mem_usage": True,        # Reduce loading memory
                "trust_remote_code": False        # Security
            }
            
            # Load model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                **model_kwargs
            )
            
            # Move to device carefully
            try:
                self.model = self.model.to(self.actual_device)
                print(f"📱 Model successfully moved to {self.actual_device}")
            except RuntimeError as e:
                if "MPS" in str(e) or "memory" in str(e).lower():
                    print(f"⚠️  {self.actual_device} memory error, using CPU")
                    self.actual_device = "cpu"
                    self.model = self.model.to("cpu")
                else:
                    raise e
            
            # Set to eval mode and optimize
            self.model.eval()
            
            # Clear cache to free memory
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                torch.mps.empty_cache()
            
            self.loaded = True
            print(f"✅ Model loaded successfully on {self.actual_device}!")
            print(f"🛡️  Ready for cybersecurity analysis")
            
            return True
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
    
    def query(self, prompt: str, max_tokens: int = 800, temperature: float = 0.1, **kwargs) -> str:
        """Memory-optimized query generation"""
        
        # Load model if needed
        if not self._load_model():
            return "❌ Failed to load model"
        
        try:
            # Use shorter max_tokens by default to save memory
            max_tokens = min(max_tokens, 800)
            
            # Simple prompt format (more memory efficient)
            formatted_prompt = f"<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n{prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
            
            # Tokenize with length limit
            inputs = self.tokenizer(
                formatted_prompt, 
                return_tensors="pt",
                max_length=2048,  # Limit input length
                truncation=True
            )
            
            # Move to device
            inputs = {k: v.to(self.actual_device) for k, v in inputs.items()}
            
            # Generate with memory optimization
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_tokens,
                    temperature=temperature,
                    do_sample=True if temperature > 0 else False,
                    pad_token_id=self.tokenizer.eos_token_id,
                    use_cache=False,  # Disable KV cache to save memory
                    **kwargs
                )
            
            # Decode response
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Clean response
            if formatted_prompt in response:
                response = response.replace(formatted_prompt, "").strip()
            
            # Clear memory after generation
            del outputs
            if self.actual_device == "mps":
                torch.mps.empty_cache()
            elif self.actual_device == "cuda":
                torch.cuda.empty_cache()
            
            return response.strip()
            
        except RuntimeError as e:
            if "memory" in str(e).lower():
                return f"❌ Memory error: Try smaller max_tokens or restart Python to free memory"
            else:
                return f"❌ Runtime error: {e}"
        except Exception as e:
            return f"❌ Generation error: {e}"
    
    def test_connection(self) -> bool:
        """Test with memory-optimized approach"""
        
        print(f"🔌 Testing memory-optimized Cisco Foundation model...")
        
        if not self._load_model():
            return False
        
        # Use shorter test to save memory
        test_response = self.query(
            "What is malware?", 
            max_tokens=50  # Very short test
        )
        
        success = (
            "❌" not in test_response and
            len(test_response) > 10 and
            "malware" in test_response.lower()
        )
        
        if success:
            print(f"✅ Memory-optimized Cisco model working!")
            print(f"🛡️  Ready for cybersecurity analysis")
            print(f"💾 Running on: {self.actual_device}")
        else:
            print(f"❌ Test failed: {test_response}")
        
        return success

# Test functionality
if __name__ == "__main__":
    print("🛡️  Memory-Optimized Cisco Foundation Client")
    print("🍎 Specifically tuned for Apple Silicon memory limits")
    print("=" * 55)
    
    # Auto-detect and recommend
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        print("🍎 Apple Silicon detected - memory optimization enabled")
        print("💡 Will use CPU to avoid MPS memory limits")
    
    # Test the client
    client = CiscoFoundationLocalClient(force_cpu=True)  # Force CPU for Apple Silicon
    
    if client.test_connection():
        print("\n🎯 Memory-optimized setup successful!")
        print("💡 Model will use CPU but should work reliably")
    else:
        print("\n❌ Setup failed - try alternatives:")
        print("  ollama pull deepseek-r1:8b  # Much lighter model")
