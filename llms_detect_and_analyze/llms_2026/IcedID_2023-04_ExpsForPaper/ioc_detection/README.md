# Query Module


## How to run

Open an ssh tunnel:

```bash
ssh -i <ssh_key_name> -L 9200:localhost:9200 onion@3.19.237.113 -N
```

Run your REST API queries via ElasticSearch.

```bash
python3 -u query_executor_with_time_range.py queries_minimal ex1_resp_minimal_aug7/ --start-date=2025-01-01 --end-date=2025-01-30
python3 -u query_executor_with_time_range.py queries_minimal ex2_resp_minimal_aug7/ --start-date=2024-11-01 --end-date=2024-11-30
python3 -u query_executor_with_time_range.py queries_minimal ex3_resp_minimal_aug7/ --start-date=2024-08-01 --end-date=2024-09-30
```

