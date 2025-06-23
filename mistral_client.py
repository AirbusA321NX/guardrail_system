import requests

prompt = "List all running background processes and their commands."

response = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": "mistral:7b-instruct",
        "prompt": prompt,
        "stream": False
    }
)

print(response.json()["response"])
