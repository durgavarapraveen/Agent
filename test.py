from langchain_aws import ChatBedrockConverse
import os
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("AWS_BEARER_TOKEN_BEDROCK")

model = os.getenv("AWS_BEDROCK_LARGE_MODEL", "us.anthropic.claude-sonnet-4-20250514-v1:0")
region = "us-west-2"

llm = ChatBedrockConverse(
    model=model,
    region_name=region
)

query = "Hello, How are you?"

res = llm.invoke(query)

print(res.content)