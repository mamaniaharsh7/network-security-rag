#!/usr/bin/env python3
"""
Default Configuration Generator
Handles creation of default questions, network context, and other configuration files
"""

import os
import json
from typing import List, Dict

class DefaultConfigs:
    """
    Generator for default configuration files and settings
    """
    
    @staticmethod
    def get_default_questions() -> List[str]:
        """
        Get default incident response questions
        
        Returns:
            List of default security incident questions
        """
        return [
            "What is the IP address of the infected host?",
            "What is the hostname of the infected machine?", 
            "What is the Windows user account name?",
            "What is the likely fake domain for initial infection?",
            "What are the C2 server IP addresses and ports?",
            "What malware family was deployed?",
            "What is the time range of malicious activity?",
            "What are the attack sequence phases?"
        ]
    
    @staticmethod
    def get_advanced_questions() -> List[str]:
        """
        Get advanced incident response questions
        
        Returns:
            List of advanced security analysis questions
        """
        return [
            "What lateral movement techniques were used?",
            "What data exfiltration occurred?",
            "What persistence mechanisms were established?",
            "What privilege escalation methods were used?",
            "What network reconnaissance was performed?",
            "What defense evasion techniques were employed?",
            "What impact did the attack have on business operations?",
            "What recommendations exist for preventing similar attacks?",
            "What are the indicators of compromise (IOCs)?",
            "What timeline can be established for the attack progression?"
        ]
    
    @staticmethod
    def get_default_network_context() -> str:
        """
        Get default network environment context
        
        Returns:
            Default network context string
        """
        return """# Network Environment Context
# This information helps the AI understand your network environment

## Network Information
- LAN segment range: 10.1.17.0/24 (10.1.17.0 through 10.1.17.255)
- Domain: bluemoontuesday.com
- Active Directory domain controller: 10.1.17.2 - WIN-GSH54QLW48D
- AD environment name: BLUEMOONTUESDAY
- LAN segment gateway: 10.1.17.1
- LAN segment broadcast address: 10.1.17.255

## Security Tools
- SIEM: [Your SIEM platform - e.g., Splunk, ELK, QRadar]
- EDR: [Your EDR solution - e.g., CrowdStrike, SentinelOne, Microsoft Defender]
- Network monitoring: [Your network monitoring tools - e.g., Wireshark, ntopng]
- Firewall: [Your firewall solution - e.g., pfSense, Cisco ASA, Palo Alto]

## Business Context
- Critical assets: [List critical systems/data - e.g., Domain Controllers, File Servers, Databases]
- Business hours: [Your business hours - e.g., 8:00 AM - 6:00 PM EST]
- Key contacts: [Emergency contact information - e.g., SOC, IT Manager, CISO]
- Compliance requirements: [e.g., PCI DSS, HIPAA, SOX]

## Environment Details
- Operating systems: [e.g., Windows 10/11, Windows Server 2019/2022, Linux]
- Key applications: [e.g., Exchange, SharePoint, Custom applications]
- Network segments: [e.g., DMZ, Internal LAN, Management network]
"""
    
    @staticmethod
    def get_minimal_network_context() -> str:
        """
        Get minimal network context for quick setup
        
        Returns:
            Minimal network context string
        """
        return """# Network Environment (Minimal)
- LAN range: 10.1.17.0/24
- Domain: bluemoontuesday.com  
- Domain Controller: 10.1.17.2 - WIN-GSH54QLW48D
- Gateway: 10.1.17.1
"""
    
    @staticmethod
    def save_default_questions_file(questions_file: str, include_advanced: bool = False):
        """
        Create a default questions file
        
        Args:
            questions_file: Path to save questions file
            include_advanced: Whether to include advanced questions
        """
        try:
            questions_dir = os.path.dirname(questions_file)
            if questions_dir and not os.path.exists(questions_dir):
                os.makedirs(questions_dir, exist_ok=True)
            
            with open(questions_file, 'w', encoding='utf-8') as f:
                f.write("# Security Incident Response Questions\n")
                f.write("# One question per line\n")
                f.write("# Lines starting with # are ignored\n\n")
                
                f.write("# === BASIC INCIDENT QUESTIONS ===\n")
                for question in DefaultConfigs.get_default_questions():
                    f.write(f"{question}\n")
                
                if include_advanced:
                    f.write("\n# === ADVANCED ANALYSIS QUESTIONS ===\n")
                    f.write("# Uncomment the questions below for deeper analysis\n")
                    for question in DefaultConfigs.get_advanced_questions():
                        f.write(f"# {question}\n")
                else:
                    f.write("\n# === ADVANCED QUESTIONS (OPTIONAL) ===\n")
                    f.write("# To enable advanced questions, use:\n")
                    f.write("# python analyzer/modular_cli.py --create-questions-file config/questions.txt --advanced\n")
            
            print(f"📝 Default questions file created: {questions_file}")
            if include_advanced:
                print("   ✅ Advanced questions included")
            else:
                print("   💡 Advanced questions available as comments")
            
        except Exception as e:
            print(f"❌ Error creating questions file: {e}")
    
    @staticmethod
    def save_default_network_context(context_file: str, minimal: bool = False):
        """
        Create a default network context file
        
        Args:
            context_file: Path to save context file
            minimal: Whether to use minimal context
        """
        try:
            context_dir = os.path.dirname(context_file)
            if context_dir and not os.path.exists(context_dir):
                os.makedirs(context_dir, exist_ok=True)
            
            if minimal:
                content = DefaultConfigs.get_minimal_network_context()
            else:
                content = DefaultConfigs.get_default_network_context()
            
            with open(context_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"🌐 Default network context file created: {context_file}")
            if minimal:
                print("   ⚡ Minimal context for faster processing")
            else:
                print("   📋 Full context template created")
            
        except Exception as e:
            print(f"❌ Error creating network context file: {e}")
    
    @staticmethod
    def save_llm_config_file(config_file: str):
        """
        Create a default LLM configuration file
        
        Args:
            config_file: Path to save LLM config file
        """
        try:
            config_dir = os.path.dirname(config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            
            llm_config = {
                "default_provider": "ollama",
                "providers": {
                    "ollama": {
                        "model": "qwen2.5:7b",
                        "base_url": "http://localhost:11434",
                        "description": "Local model - no API key needed"
                    },
                    "deepseek": {
                        "api_key_file": "config/keys/deepseek_key.txt",
                        "model": "deepseek-chat",
                        "description": "DeepSeek API - excellent reasoning"
                    },
                    "openai": {
                        "api_key_file": "config/keys/openai_key.txt",
                        "model": "gpt-3.5-turbo",
                        "description": "OpenAI API - reliable and fast"
                    },
                    "anthropic": {
                        "api_key_file": "config/keys/anthropic_key.txt",
                        "model": "claude-3-sonnet-20240229",
                        "description": "Anthropic API - superior analysis"
                    }
                },
                "analysis_settings": {
                    "cache_file": "cache/security_embeddings.pkl",
                    "output_directory": "reports",
                    "default_questions_file": "config/questions.txt",
                    "default_context_file": "config/network_context.txt"
                }
            }
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(llm_config, f, indent=2)
            
            print(f"⚙️  LLM configuration file created: {config_file}")
            
        except Exception as e:
            print(f"❌ Error creating LLM config file: {e}")
    
    @staticmethod
    def create_api_key_templates(keys_directory: str):
        """
        Create API key template files
        
        Args:
            keys_directory: Directory to create key template files
        """
        try:
            if not os.path.exists(keys_directory):
                os.makedirs(keys_directory, exist_ok=True)
            
            key_templates = {
                "deepseek_key.txt": {
                    "content": "# Put your DeepSeek API key here\n# Get it from: https://platform.deepseek.com/\n# Example: your-deepseek-api-key-here",
                    "url": "https://platform.deepseek.com/"
                },
                "openai_key.txt": {
                    "content": "# Put your OpenAI API key here\n# Get it from: https://platform.openai.com/\n# Example: sk-your-openai-key-here",
                    "url": "https://platform.openai.com/"
                },
                "anthropic_key.txt": {
                    "content": "# Put your Anthropic API key here\n# Get it from: https://console.anthropic.com/\n# Example: sk-ant-your-anthropic-key-here",
                    "url": "https://console.anthropic.com/"
                }
            }
            
            print("🔑 Creating API key template files...")
            for filename, info in key_templates.items():
                filepath = os.path.join(keys_directory, filename)
                with open(filepath, "w") as f:
                    f.write(info["content"])
                print(f"   ✅ {filepath}")
                print(f"      💡 Get key from: {info['url']}")
            
        except Exception as e:
            print(f"❌ Error creating API key templates: {e}")
    
    @staticmethod
    def load_questions_from_file(questions_file: str) -> List[str]:
        """
        Load questions from file with error handling
        
        Args:
            questions_file: Path to questions file
            
        Returns:
            List of questions
        """
        try:
            with open(questions_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                if content.startswith('[') or content.startswith('{'):
                    # JSON format
                    data = json.loads(content)
                    if isinstance(data, list):
                        questions = data
                    elif isinstance(data, dict) and 'questions' in data:
                        questions = data['questions']
                    else:
                        raise ValueError("JSON format should be array or object with 'questions' key")
                else:
                    # Plain text format - one question per line, ignore comments
                    lines = content.split('\n')
                    questions = [line.strip() for line in lines 
                               if line.strip() and not line.strip().startswith('#')]
                
                if not questions:
                    raise ValueError("No questions found in file")
                
                print(f"📋 Loaded {len(questions)} questions from: {questions_file}")
                return questions
                
        except FileNotFoundError:
            print(f"❌ Questions file not found: {questions_file}")
            print(f"💡 Create default with: DefaultConfigs.save_default_questions_file('{questions_file}')")
            raise
        except Exception as e:
            print(f"❌ Error reading questions file {questions_file}: {e}")
            raise
    
    @staticmethod
    def load_network_context_from_file(context_file: str) -> str:
        """
        Load network context from file with error handling
        
        Args:
            context_file: Path to context file
            
        Returns:
            Network context string
        """
        try:
            with open(context_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                if content.startswith('{'):
                    # JSON format
                    data = json.loads(content)
                    if 'network_context' in data:
                        context = data['network_context']
                    elif 'context' in data:
                        context = data['context']
                    else:
                        # Convert JSON to readable format
                        context_parts = []
                        for key, value in data.items():
                            context_parts.append(f"- {key.replace('_', ' ').title()}: {value}")
                        context = "\n".join(context_parts)
                else:
                    # Plain text format
                    context = content
                
                print(f"🌐 Loaded network context ({len(context)} chars) from: {context_file}")
                return context
                
        except FileNotFoundError:
            print(f"⚠️  Network context file not found: {context_file}")
            print(f"💡 Create default with: DefaultConfigs.save_default_network_context('{context_file}')")
            return ""
        except Exception as e:
            print(f"⚠️  Error reading network context file {context_file}: {e}")
            return ""

# Simple test and utility functionality
if __name__ == "__main__":
    import sys
    
    print("🔧 Default Configuration Generator")
    print("=" * 40)
    
    if len(sys.argv) == 1:
        print("\nUsage:")
        print("  python default_configs.py questions [advanced]     # Show default questions")
        print("  python default_configs.py network [minimal]       # Show network context")
        print("  python default_configs.py create-all <directory>  # Create all config files")
        print("  python default_configs.py api-keys <directory>    # Create API key templates")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command == "questions":
        print("\n📋 Default Questions:")
        for i, question in enumerate(DefaultConfigs.get_default_questions(), 1):
            print(f"  {i}. {question}")
        
        if len(sys.argv) > 2 and sys.argv[2].lower() == "advanced":
            print("\n📋 Advanced Questions:")
            for i, question in enumerate(DefaultConfigs.get_advanced_questions(), 1):
                print(f"  {i}. {question}")
    
    elif command == "network":
        minimal = len(sys.argv) > 2 and sys.argv[2].lower() == "minimal"
        print("\n🌐 Network Context:")
        if minimal:
            print(DefaultConfigs.get_minimal_network_context())
        else:
            print(DefaultConfigs.get_default_network_context())
    
    elif command == "create-all":
        if len(sys.argv) < 3:
            print("❌ Error: Please specify directory")
            print("💡 Usage: python default_configs.py create-all config")
            sys.exit(1)
        
        config_dir = sys.argv[2]
        print(f"\n🔧 Creating all configuration files in: {config_dir}")
        
        # Create questions file
        questions_file = os.path.join(config_dir, "questions.txt")
        DefaultConfigs.save_default_questions_file(questions_file, include_advanced=True)
        
        # Create network context file
        context_file = os.path.join(config_dir, "network_context.txt")
        DefaultConfigs.save_default_network_context(context_file)
        
        # Create LLM config file
        llm_config_file = os.path.join(config_dir, "llm_config.json")
        DefaultConfigs.save_llm_config_file(llm_config_file)
        
        # Create API key templates
        keys_dir = os.path.join(config_dir, "keys")
        DefaultConfigs.create_api_key_templates(keys_dir)
        
        print("\n✅ All configuration files created!")
    
    elif command == "api-keys":
        if len(sys.argv) < 3:
            print("❌ Error: Please specify keys directory")
            print("💡 Usage: python default_configs.py api-keys config/keys")
            sys.exit(1)
        
        keys_dir = sys.argv[2]
        DefaultConfigs.create_api_key_templates(keys_dir)
    
    else:
        print(f"❌ Unknown command: {command}")
        print("💡 Use: python default_configs.py for usage information")
