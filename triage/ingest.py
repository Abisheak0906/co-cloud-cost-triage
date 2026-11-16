"""Read the daily usage file and resource metadata."""

import json
from decimal import Decimal


def load_usage_report(s3, bucket: str, key: str) -> dict:
    """Download and parse the report, preserving decimal precision."""
    response = s3.get_object(Bucket=bucket, Key=key)
    text = response["Body"].read().decode("utf-8")
    return json.loads(text, parse_float=Decimal)


def load_metadata(table, resource_ids: list[str]) -> dict[str, dict]:
    """Batch-read metadata and return it indexed by resource_id."""
    unique_ids = list(dict.fromkeys(resource_ids))
    result: dict[str, dict] = {}

    # DynamoDB BatchGetItem accepts at most 100 keys per request.
    for start in range(0, len(unique_ids), 100):
        keys = [{"resource_id": resource_id} for resource_id in unique_ids[start:start + 100]]
        response = table.meta.client.batch_get_item(
            RequestItems={
                table.name: {
                    "Keys": keys,
                    "ConsistentRead": True,
                }
            }
        )
        result.update({item["resource_id"]: item for item in response.get("Responses", {}).get(table.name, [])})

        # Retry unprocessed keys rather than silently losing metadata.
        while response.get("UnprocessedKeys", {}).get(table.name, {}).get("Keys"):
            response = table.meta.client.batch_get_item(RequestItems=response["UnprocessedKeys"])
            result.update({item["resource_id"]: item for item in response.get("Responses", {}).get(table.name, [])})

    return result
