import boto3
import json

client = boto3.client('bedrock-runtime', region_name='us-west-2')

response = client.invoke_model(
    modelId='anthropic.claude-haiku-4-5-20251001-v1:0',
    body=json.dumps({
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 100
    })
)

print(json.loads(response['body'].read()))