from fastapi import FastAPI
from pydantic import BaseModel
import os
from dotenv import load_dotenv
from main import send_slack_alert, log_to_google_sheets
from openai import OpenAI
from openai import OpenAIError


# Load environment variables
load_dotenv()

# OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = FastAPI()

class UserMessage(BaseModel):
    message: str

@app.post("/chat/")
async def chat_with_langsec(msg: UserMessage):
    question = msg.message

    try:
        response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You're a cybersecurity assistant."},
            {"role": "user", "content": question}
        ]
    )
        answer = response.choices[0].message.content

    except OpenAIError as e:
        # Simulate fallback if quota exceeded or any OpenAI error occurs
        answer = (
            "⚠️ LangSec is running in mock mode due to OpenAI issues. "
            "This is a simulated response."
        )
        print("⚠️ OpenAI fallback triggered:", e)

    except Exception as e:
        return {"error": f"🤖 Unexpected AI error: {str(e)}"}

    # Logging and Alerts (still functional!)
    if "phishing" in answer.lower():
        send_slack_alert(f"🚨 Suspicious message: {question}")
    log_to_google_sheets(question, answer)

    return {"response": answer}
