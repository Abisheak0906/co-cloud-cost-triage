# My Solution

### How to run
Install dependencies using `pip install -r requirements.txt`, start Moto with `moto_server -p 4566`, then run:

```bash
python scripts/setup_data.py
pytest
python -m triage.main --date 2026-10-20
```

### Approach
The tool reads usage data from S3 and matches it with resource metadata in DynamoDB. It checks for forgotten EBS volumes, publicly exposed databases, and unusual database costs. I used `Decimal` for cost calculations and deterministic IDs to prevent duplicate findings when the same analysis is run again.

Missing or invalid data is reported rather than silently ignored. Monthly savings are estimated using the daily cost multiplied by 30.

### Notes
I tested the application locally using Moto, including running the same analysis twice to verify that findings were not duplicated.

For a real deployment, I would consider EventBridge with Lambda or ECS Fargate, along with restricted IAM permissions and CloudWatch monitoring.

ChatGPT was used to help understand the requirements, discuss implementation choices, and develop test cases. I reviewed and ran the code and can explain the implementation.

**Time spent:** Approximately 3 hours.