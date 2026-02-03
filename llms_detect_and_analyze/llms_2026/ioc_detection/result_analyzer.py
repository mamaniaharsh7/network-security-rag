import json
import os
import glob
import sys
from datetime import datetime
import argparse

class BatchResultAnalyzer:
    def __init__(self, results_dir):
        self.results_dir = results_dir
        
    def analyze_all_results(self):
        """Analyze all result files in directory"""
        
        # Find all result files
        #result_pattern = os.path.join(self.results_dir, "*_result_*.json")

        result_pattern = os.path.join(self.results_dir, "*_result*.json")
        result_files = glob.glob(result_pattern)
        
        if not result_files:
            print(f"❌ No result files found in: {self.results_dir}")
            return
        
        result_files.sort()
        
        print(f"📊 Analyzing {len(result_files)} result files")
        print(f"📂 Directory: {self.results_dir}")
        print("=" * 60)
        
        successful_results = []
        failed_results = []
        
        for result_file in result_files:
            analysis = self.analyze_single_result(result_file)
            if analysis:
                if analysis["success"]:
                    successful_results.append(analysis)
                else:
                    failed_results.append(analysis)
        
        # Generate summary report
        self.generate_summary_report(successful_results, failed_results)
    
    def analyze_single_result(self, result_file):
        """Analyze a single result file"""
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
            
            metadata = data.get('metadata', {})
            response = data.get('response', {})
            success = data.get('success', False)
            
            analysis = {
                "file": os.path.basename(result_file),
                "query_file": metadata.get('query_file', 'Unknown'),
                "success": success,
                "execution_time": metadata.get('execution_time', 'Unknown'),
                "duration_ms": metadata.get('execution_duration_ms', 0),
                "total_hits": 0,
                "aggregations_count": 0,
                "error": None
            }
            
            if success and 'hits' in response:
                analysis["total_hits"] = response['hits']['total']['value']
                analysis["elasticsearch_took_ms"] = response.get('took', 0)
                analysis["aggregations_count"] = len(response.get('aggregations', {}))
                
                print(f"✅ {analysis['query_file']}: {analysis['total_hits']:,} hits")
            else:
                error_msg = "Unknown error"
                if 'error' in response:
                    error_msg = str(response['error'])[:100]
                elif 'error' in metadata:
                    error_msg = str(metadata['error'])[:100]
                
                analysis["error"] = error_msg
                print(f"❌ {analysis['query_file']}: {error_msg}")
            
            return analysis
            
        except Exception as e:
            print(f"⚠️  Error analyzing {result_file}: {e}")
            return None
    
    def generate_summary_report(self, successful_results, failed_results):
        """Generate comprehensive summary report"""
        
        print("\n" + "=" * 60)
        print("📋 BATCH ANALYSIS SUMMARY")
        print("=" * 60)
        
        total_results = len(successful_results) + len(failed_results)
        
        print(f"📄 Total result files: {total_results}")
        print(f"✅ Successful: {len(successful_results)}")
        print(f"❌ Failed: {len(failed_results)}")
        
        if successful_results:
            total_hits = sum(r["total_hits"] for r in successful_results)
            avg_duration = sum(r["duration_ms"] for r in successful_results) / len(successful_results)
            
            print(f"\n📊 Success Statistics:")
            print(f"   Total hits across all queries: {total_hits:,}")
            print(f"   Average execution time: {avg_duration:.0f}ms")
            
            print(f"\n🏆 Top queries by hit count:")
            sorted_results = sorted(successful_results, key=lambda x: x["total_hits"], reverse=True)
            for i, result in enumerate(sorted_results[:5]):
                print(f"   {i+1}. {result['query_file']}: {result['total_hits']:,} hits")
        
        if failed_results:
            print(f"\n❌ Failed queries:")
            for result in failed_results:
                print(f"   - {result['query_file']}: {result['error']}")
        
        # Save detailed report
        report_file = os.path.join(self.results_dir, f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "results_directory": self.results_dir,
            "summary": {
                "total_files": total_results,
                "successful": len(successful_results),
                "failed": len(failed_results)
            },
            "successful_results": successful_results,
            "failed_results": failed_results
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"\n📝 Detailed report saved to: {report_file}")

def main():
    parser = argparse.ArgumentParser(description="Analyze batch query results")
    parser.add_argument("results_dir", help="Directory containing result files")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.results_dir):
        print(f"❌ Results directory not found: {args.results_dir}")
        sys.exit(1)
    
    analyzer = BatchResultAnalyzer(args.results_dir)
    analyzer.analyze_all_results()

if __name__ == "__main__":
    main()


