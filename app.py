from flask import Flask
import google.generativeai as genai
import re
from flask import request, jsonify

genai.configure(api_key="AIzaSyDcB8q3jVebPH5oGyzYq4EoBP1qPRAhuPA")

app = Flask(__name__,)

@app.route('/query', methods=["POST"])
def generate_sql():
    natural_language_query = request.json.get("query", "")
    if not natural_language_query:
        return jsonify({"error": "Query is required"}), 400

    prompt = f"Generate only the SQL query for the following natural language request without any explanation:\n\nQuery: \"{natural_language_query}\""
    
    model = genai.GenerativeModel("gemini-2.0-flash")
    response = model.generate_content(prompt)
    
    if response and hasattr(response, "text"):
        sql_query = response.text.strip()
        sql_query = re.sub(r"```(sql)?", "", sql_query).strip()
        return jsonify({"sql_query": sql_query})
    else:
        return jsonify({"error": "Failed to generate SQL query"}), 500

if __name__ == "__main__":
    natural_language_query = input()
    sql_query = generate_sql(natural_language_query)
    print(sql_query)
