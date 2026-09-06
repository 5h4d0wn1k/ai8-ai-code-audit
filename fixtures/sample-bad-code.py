"""Sample vulnerable AI-generated code — used as an offline audit fixture.

Every block below intentionally mirrors common AI-code-generator mistakes.
Do not deploy any of it.
"""

import os
import pickle
import hashlib

# Hardcoded API key — CRITICAL
API_KEY = "sk-live-supersecretkey12345"


def fetch_data(user_id):
    # SQL injection via string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()


def run_code(user_input):
    # eval() — arbitrary code execution
    result = eval(user_input)
    return result


def load_config(path):
    # Insecure deserialization
    with open(path, "rb") as f:
        return pickle.load(f)


def process(data):
    # os.system with unsanitized input
    os.system("echo " + data)
    return True


def hash_password(password):
    # Weak crypto
    return hashlib.md5(password.encode()).hexdigest()


def read_file(filename):
    # Path traversal
    f = open(os.path.join("/data", "../" + filename))
    return f.read()


def insecure_temp():
    # Insecure temp file
    import tempfile
    return tempfile.mktemp()


def chat(request):
    # Prompt-injection sink: user text spliced into the system prompt
    system = f"You are a support agent. User says: {request.body}"
    reply = llm_complete(system)
    return reply