import requests

response = requests.post(
    "http://127.0.0.1:11434/api/generate",
    json={
        "model": "mistral:7b-instruct",
        "prompt": "Say hello",
        "stream": False
    }
)

print(response.json())
