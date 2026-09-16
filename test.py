import boto3
import json

client = boto3.client(
    "bedrock-runtime",
    region_name="ap-south-1"
)

response = client.invoke_model(
    modelId="google.gemma-3-27b-it",
    body=json.dumps({
        "messages": [
            {
                "role": "user",
                "content": "Hello"
            }
        ],
        "max_tokens": 100
    })
)

result = json.loads(response["body"].read())

print(json.dumps(result, indent=2))