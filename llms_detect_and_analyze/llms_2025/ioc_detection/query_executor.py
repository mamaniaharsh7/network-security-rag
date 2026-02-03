import json
import sys
import os
import glob
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from datetime import datetime
import argparse


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Use localhost because of SSH tunnel
SO_HOST = "https://localhost:9200"
USERNAME = "admin@castlecf.test.com"
PASSWORD = "7q749kGq8trNgW84WQ7y"

LOGS_INDEX = 'logs-*' 
#LOGS_INDEX = 'logs-2025*'

class BatchQueryExecutor:
    def __init__(self, host=SO_HOST, username=USERNAME, password=PASSWORD):
        self.host = host
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {"Content-Type": "application/json"}
       
    def execute_query_file(self, query_file, output_file):
        """Execute a single query file and save response"""
        try:
            print(f"🔍 Processing: {os.path.basename(query_file)}")
        
            # Load the entire query structure
            with open(query_file, 'r') as f:
                query_data = json.load(f)
        
            # Extract index if specified, otherwise use default
            index = query_data.pop('index', LOGS_INDEX)
        
            # The query_data now contains the complete Elasticsearch query
            # (query, aggs, _source, size, etc.)
        
            # Execute query
            url = f"{self.host}/{index}/_search"
            start_time = datetime.now()
        
            response = requests.post(
                url,
                auth=self.auth,
                headers=self.headers,
                json=query_data,  # Send the entire query structure
                verify=False,
                timeout=300
            )

            print(f"Response Status: {response.status_code}")
        
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
                    "status_code": response.status_code,
                    "execution_duration_ms": duration_ms,
                    "elasticsearch_took_ms": None,
                    "index_used": index
                },
                "query": query_data,  # Store the complete query that was sent
                "response": None,
                "success": False
            }

            print(result_data)
        
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
                "error": error_message
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
        
        print(f"🚀 Found {len(query_files)} query files to process")
        print(f"📂 Input: {input_dir}")
        print(f"📂 Output: {output_dir}")
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
                "total_files": len(query_files)
            }
        }
        
        for query_file in query_files:
            # Generate output filename
            base_name = os.path.splitext(os.path.basename(query_file))[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            #output_file = os.path.join(output_dir, f"{base_name}_result_{timestamp}.json")

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
        
        summary_file = os.path.join(output_dir, f"execution_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Print summary
        self.print_execution_summary(results)
        print(f"📋 Detailed summary saved to: {summary_file}")
        
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
        """Test Elasticsearch connection"""
        try:
            response = requests.get(
                f"{self.host}/_cluster/health",
                auth=self.auth,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                health = response.json()
                print(f"✅ Connected to Elasticsearch: {health.get('cluster_name')}")
                print(f"   Status: {health.get('status')} | Nodes: {health.get('number_of_nodes')}")
                return True
            else:
                print(f"❌ Connection failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description="Execute Elasticsearch queries from directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 batch_executor.py queries/ results/
  python3 batch_executor.py queries/ results/ --pattern "forensic_*.json"
  python3 batch_executor.py /path/to/queries /path/to/results --host https://remote:9200
        """
    )
    
    parser.add_argument("input_dir", help="Directory containing query JSON files")
    parser.add_argument("output_dir", help="Directory to save result files")
    parser.add_argument("--pattern", default="*.json", help="File pattern to match (default: *.json)")
    parser.add_argument("--host", default="https://localhost:9200", help="Elasticsearch host")
    parser.add_argument("--username", default=USERNAME, help="Elasticsearch username")
    parser.add_argument("--password", default=PASSWORD, help="Elasticsearch password")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not os.path.exists(args.input_dir):
        print(f"❌ Input directory not found: {args.input_dir}")
        sys.exit(1)
    
    # Initialize executor
    executor = BatchQueryExecutor(
        host=args.host,
        username=args.username,
        password=args.password
    )
    
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

