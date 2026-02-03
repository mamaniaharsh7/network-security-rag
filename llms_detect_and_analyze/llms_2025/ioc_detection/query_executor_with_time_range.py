import json
import sys
import os
import glob
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from datetime import datetime
import argparse
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# GLOBAL CONFIGURATION - UPDATE THESE VALUES FOR YOUR ENVIRONMENT
# =============================================================================

# Elasticsearch connection settings
# ELASTICSEARCH_HOST = "https://localhost:9200"
# ELASTICSEARCH_USERNAME = "admin@castlecf.test.com"
# ELASTICSEARCH_PASSWORD = "7q749kGq8trNgW84WQ7y"

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration from .env
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'https://localhost:9200')
ELASTICSEARCH_USERNAME = os.getenv('ELASTICSEARCH_USERNAME')
ELASTICSEARCH_PASSWORD = os.getenv('ELASTICSEARCH_PASSWORD')

# Default index pattern for queries
DEFAULT_INDEX = "logs-*"

# Default time field for time range filtering
DEFAULT_TIME_FIELD = "@timestamp"

# Request timeout in seconds
REQUEST_TIMEOUT = 300

# =============================================================================
# END CONFIGURATION
# =============================================================================

def parse_time_range(start_date, end_date, time_field=DEFAULT_TIME_FIELD):
    """Parse start and end dates into Elasticsearch format"""
    try:
        time_range = {"field": time_field}
        
        if start_date:
            # Handle different date formats
            if re.match(r'^\d{4}-\d{2}-\d{2}$', start_date):
                # YYYY-MM-DD format, add time
                time_range["gte"] = f"{start_date}T00:00:00"
            elif re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', start_date):
                # Already has time
                time_range["gte"] = start_date
            else:
                print(f"❌ Invalid start date format: {start_date}")
                return None
        else:
            time_range["gte"] = "1970-01-01T00:00:00"
        
        if end_date:
            # Handle different date formats
            if re.match(r'^\d{4}-\d{2}-\d{2}$', end_date):
                # YYYY-MM-DD format, add end of day time
                time_range["lte"] = f"{end_date}T23:59:59"
            elif re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', end_date):
                # Already has time
                time_range["lte"] = end_date
            else:
                print(f"❌ Invalid end date format: {end_date}")
                return None
        else:
            time_range["lte"] = "2030-12-31T23:59:59"
        
        return time_range
        
    except Exception as e:
        print(f"❌ Error parsing time range: {e}")
        return None

class BatchQueryExecutor:
    def __init__(self, host=None, username=None, password=None, time_range=None):
        # Use global config if not overridden
        self.host = host or ELASTICSEARCH_HOST
        self.username = username or ELASTICSEARCH_USERNAME
        self.password = password or ELASTICSEARCH_PASSWORD
        
        self.auth = HTTPBasicAuth(self.username, self.password)
        self.headers = {"Content-Type": "application/json"}
        self.time_range = time_range
        
        # Print configuration being used
        print(f"🔧 Configuration:")
        print(f"   Host: {self.host}")
        print(f"   Username: {self.username}")
        print(f"   Default Index: {DEFAULT_INDEX}")
        if self.time_range:
            print(f"   Time Range: {self.time_range['gte']} to {self.time_range['lte']}")
        
    def apply_time_filter(self, query_data):
        """Apply time range filter to query"""
        if not self.time_range:
            return query_data
        
        # Create a copy to avoid modifying the original
        modified_query = query_data.copy()
        
        # Create time range filter
        time_filter = {
            "range": {
                self.time_range["field"]: {
                    "gte": self.time_range["gte"],
                    "lte": self.time_range["lte"]
                }
            }
        }
        
        # Add time filter to the query
        if "query" not in modified_query:
            modified_query["query"] = {"match_all": {}}
        
        original_query = modified_query["query"]
        
        # If the query is already a bool query, add to must clause
        if isinstance(original_query, dict) and "bool" in original_query:
            if "must" not in original_query["bool"]:
                original_query["bool"]["must"] = []
            elif not isinstance(original_query["bool"]["must"], list):
                # Convert single must clause to list
                original_query["bool"]["must"] = [original_query["bool"]["must"]]
            
            original_query["bool"]["must"].append(time_filter)
        else:
            # Wrap existing query in bool with time filter
            modified_query["query"] = {
                "bool": {
                    "must": [
                        original_query,
                        time_filter
                    ]
                }
            }
        
        return modified_query
        
    def execute_query_file(self, query_file, output_file):
        """Execute a single query file and save response"""
        try:
            print(f"🔍 Processing: {os.path.basename(query_file)}")
            
            # Load the entire query structure
            with open(query_file, 'r') as f:
                query_data = json.load(f)
            
            # Extract index if specified, otherwise use global default
            index = query_data.pop('index', DEFAULT_INDEX)
            
            # Apply time filter if specified
            if self.time_range:
                query_data = self.apply_time_filter(query_data)
                print(f"   🕐 Applied time filter: {self.time_range['gte']} to {self.time_range['lte']}")
            
            # Execute query
            url = f"{self.host}/{index}/_search"
            start_time = datetime.now()
            
            response = requests.post(
                url,
                auth=self.auth,
                headers=self.headers,
                json=query_data,
                verify=False,
                timeout=REQUEST_TIMEOUT
            )
            
            end_time = datetime.now()
            duration_ms = (end_time - start_time).total_seconds() * 1000
            
            # Prepare result data
            result_data = {
                "metadata": {
                    "query_file": os.path.basename(query_file),
                    "query_file_path": query_file,
                    "execution_time": start_time.isoformat(),
                    "completion_time": end_time.isoformat(),
                    "elasticsearch_url": url,
                    "elasticsearch_host": self.host,
                    "elasticsearch_username": self.username,
                    "status_code": response.status_code,
                    "execution_duration_ms": duration_ms,
                    "elasticsearch_took_ms": None,
                    "index_used": index,
                    "time_range_applied": self.time_range
                },
                "query": query_data,
                "response": None,
                "success": False
            }
            
            if response.status_code == 200:
                elasticsearch_result = response.json()
                result_data["response"] = elasticsearch_result
                result_data["success"] = True
                result_data["metadata"]["elasticsearch_took_ms"] = elasticsearch_result.get('took', 0)
                
                # Brief summary
                total_hits = elasticsearch_result['hits']['total']['value']
                took_ms = elasticsearch_result.get('took', 0)
                returned_hits = len(elasticsearch_result['hits']['hits'])
                
                print(f"   ✅ Success: {total_hits:,} total hits, {returned_hits} returned (ES: {took_ms}ms, Total: {duration_ms:.0f}ms)")
                
                # Show aggregation summary if present
                if 'aggregations' in elasticsearch_result:
                    agg_count = len(elasticsearch_result['aggregations'])
                    print(f"   📊 Aggregations: {agg_count} computed")
                    
            else:
                # Save error response
                result_data["response"] = {
                    "error": response.text,
                    "status_code": response.status_code
                }
                print(f"   ❌ Failed: HTTP {response.status_code}")
                if response.status_code == 400:
                    print(f"      Bad Request - Check query syntax")
                elif response.status_code == 401:
                    print(f"      Authentication failed - Check credentials")
            
            # Save result
            with open(output_file, 'w') as f:
                json.dump(result_data, f, indent=2, default=str)
            
            return result_data["success"], result_data["metadata"]
            
        except json.JSONDecodeError as e:
            print(f"   ❌ Invalid JSON: {e}")
            error_data = self._create_error_response(query_file, f"Invalid JSON: {e}")
            with open(output_file, 'w') as f:
                json.dump(error_data, f, indent=2, default=str)
            return False, error_data["metadata"]
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            error_data = self._create_error_response(query_file, str(e))
            with open(output_file, 'w') as f:
                json.dump(error_data, f, indent=2, default=str)
            return False, error_data["metadata"]

    def _create_error_response(self, query_file, error_message):
        """Create standardized error response"""
        return {
            "metadata": {
                "query_file": os.path.basename(query_file),
                "query_file_path": query_file,
                "execution_time": datetime.now().isoformat(),
                "elasticsearch_host": self.host,
                "elasticsearch_username": self.username,
                "error": error_message,
                "time_range_applied": self.time_range
            },
            "query": None,
            "response": {"error": error_message},
            "success": False
        }

    def process_directory(self, input_dir, output_dir, file_pattern="*.json"):
        """Process all query files in input directory"""
        
        # Validate input directory
        if not os.path.exists(input_dir):
            print(f"❌ Input directory not found: {input_dir}")
            return False
        
        # Create output directory
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"📁 Created output directory: {output_dir}")
        
        # Find query files
        query_pattern = os.path.join(input_dir, file_pattern)
        query_files = glob.glob(query_pattern)
        
        if not query_files:
            print(f"❌ No query files found matching: {query_pattern}")
            return False
        
        query_files.sort()  # Process in consistent order
        
        print(f"\n🚀 Found {len(query_files)} query files to process")
        print(f"📂 Input: {input_dir}")
        print(f"📂 Output: {output_dir}")
        if self.time_range:
            print(f"🕐 Time range: {self.time_range['gte']} to {self.time_range['lte']}")
        print("=" * 60)
        
        # Process each file
        results = {
            "successful": [],
            "failed": [],
            "metadata": {
                "start_time": datetime.now().isoformat(),
                "input_directory": input_dir,
                "output_directory": output_dir,
                "file_pattern": file_pattern,
                "total_files": len(query_files),
                "elasticsearch_host": self.host,
                "elasticsearch_username": self.username,
                "default_index": DEFAULT_INDEX,
                "time_range_applied": self.time_range
            }
        }
        
        for query_file in query_files:
            # Generate output filename
            base_name = os.path.splitext(os.path.basename(query_file))[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(output_dir, f"{base_name}_result.json")
            
            # Execute query
            success, metadata = self.execute_query_file(query_file, output_file)
            
            if success:
                results["successful"].append({
                    "query_file": query_file,
                    "output_file": output_file,
                    "metadata": metadata
                })
            else:
                results["failed"].append({
                    "query_file": query_file,
                    "output_file": output_file,
                    "metadata": metadata
                })
        
        # Save execution summary
        results["metadata"]["end_time"] = datetime.now().isoformat()
        results["metadata"]["success_count"] = len(results["successful"])
        results["metadata"]["failure_count"] = len(results["failed"])
        
        #summary_file = os.path.join(output_dir, f"execution_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        #with open(summary_file, 'w') as f:
        #    json.dump(results, f, indent=2, default=str)
        
        # Print summary
        self.print_execution_summary(results)
        #print(f"📋 Detailed summary saved to: {summary_file}")
        
        return len(results["failed"]) == 0
    
    def print_execution_summary(self, results):
        """Print execution summary"""
        print("\n" + "=" * 60)
        print("📊 EXECUTION SUMMARY")
        print("=" * 60)
        
        total = results["metadata"]["total_files"]
        successful = results["metadata"]["success_count"]
        failed = results["metadata"]["failure_count"]
        
        print(f"📄 Total queries: {total}")
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        print(f"📈 Success rate: {(successful/total*100):.1f}%")
        print(f"🌐 Host: {results['metadata']['elasticsearch_host']}")
        
        if results["metadata"]["time_range_applied"]:
            tr = results["metadata"]["time_range_applied"]
            print(f"🕐 Time range: {tr['gte']} to {tr['lte']}")
        
        # Show successful queries
        if results["successful"]:
            print(f"\n✅ Successful queries:")
            for item in results["successful"]:
                query_name = os.path.basename(item["query_file"])
                output_name = os.path.basename(item["output_file"])
                duration = item["metadata"].get("execution_duration_ms", 0)
                print(f"   - {query_name} → {output_name} ({duration:.0f}ms)")
        
        # Show failed queries
        if results["failed"]:
            print(f"\n❌ Failed queries:")
            for item in results["failed"]:
                query_name = os.path.basename(item["query_file"])
                print(f"   - {query_name}")
    
    def test_connection(self):
        """Test Elasticsearch connection using search endpoint"""
        try:
            # Use a simple complete query structure like your files
            test_query = {
                "query": {"match_all": {}},
                "size": 0
            }
            
            # Apply time filter to test query if specified
            if self.time_range:
                test_query = self.apply_time_filter(test_query)
            
            response = requests.post(
                f"{self.host}/{DEFAULT_INDEX}/_search",
                auth=self.auth,
                headers=self.headers,
                json=test_query,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                total_docs = result['hits']['total']['value']
                print(f"✅ Connected to Elasticsearch successfully")
                print(f"   Available documents in {DEFAULT_INDEX}: {total_docs:,}")
                if self.time_range:
                    print(f"   (within specified time range: {self.time_range['gte']} to {self.time_range['lte']})")
                return True
            elif response.status_code == 401:
                print(f"❌ Authentication failed: Invalid credentials")
                return False
            else:
                print(f"❌ Connection test failed: {response.status_code}")
                print(f"Response: {response.text[:200]}")
                return False
                
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description="Execute Elasticsearch queries from directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Global Configuration (edit at top of script):
  Host: {ELASTICSEARCH_HOST}
  Username: {ELASTICSEARCH_USERNAME}
  Default Index: {DEFAULT_INDEX}

Examples:
  python3 batch_executor.py queries/ results/
  python3 batch_executor.py queries/ results/ --start-date 2025-01-01 --end-date 2025-01-31
  python3 batch_executor.py queries/ results/ --start-date "2025-01-22T15:00:00" --end-date "2025-01-22T16:00:00"
  
Override global config:
  python3 batch_executor.py queries/ results/ --host https://remote:9200 --username myuser --password mypass
        """
    )
    
    parser.add_argument("input_dir", help="Directory containing query JSON files")
    parser.add_argument("output_dir", help="Directory to save result files")
    parser.add_argument("--pattern", default="*.json", help="File pattern to match (default: *.json)")
    
    # Optional overrides for global config
    parser.add_argument("--host", help=f"Elasticsearch host (default: {ELASTICSEARCH_HOST})")
    parser.add_argument("--username", help=f"Elasticsearch username (default: {ELASTICSEARCH_USERNAME})")
    parser.add_argument("--password", help="Elasticsearch password (default: from global config)")
    parser.add_argument("--skip-test", action="store_true", help="Skip connection test")
    
    # Time range parameters
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
    parser.add_argument("--end-date", help="End date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
    parser.add_argument("--time-field", default=DEFAULT_TIME_FIELD, help=f"Time field name (default: {DEFAULT_TIME_FIELD})")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not os.path.exists(args.input_dir):
        print(f"❌ Input directory not found: {args.input_dir}")
        sys.exit(1)
    
    # Parse time range
    time_range = None
    if args.start_date or args.end_date:
        time_range = parse_time_range(args.start_date, args.end_date, args.time_field)
        if time_range:
            print(f"🕐 Time range filter: {time_range['gte']} to {time_range['lte']}")
        else:
            sys.exit(1)
    
    # Initialize executor (using global config unless overridden)
    executor = BatchQueryExecutor(
        host=args.host,  # Will use global config if None
        username=args.username,  # Will use global config if None
        password=args.password,  # Will use global config if None
        time_range=time_range
    )
    
    # Test connection (unless skipped)
    if not args.skip_test:
        print("\n🔗 Testing Elasticsearch connection...")
        if not executor.test_connection():
            print("❌ Connection test failed, but proceeding anyway...")
            print("💡 Use --skip-test to skip this check")
    else:
        print("⏭️  Skipping connection test")
    
    print(f"\n🎯 Starting batch execution at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Process directory
    success = executor.process_directory(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        file_pattern=args.pattern
    )
    
    if success:
        print("\n🎉 All queries executed successfully!")
        sys.exit(0)
    else:
        print("\n⚠️  Some queries failed - check individual result files for details")
        sys.exit(1)

if __name__ == "__main__":
    main()


