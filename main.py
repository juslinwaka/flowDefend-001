import os
from langchain.vectorstores import FAISS
from langchain.embeddings import OpenAIEmbeddings
from langchain.document_loaders import PyPDFLoader, TextLoader
from langchain.text_splitter import CharacterTextSplitter
import requests
import gspread
from oauth2client.service_account import ServiceAccountCredentials

DOCS_PATH = "./docs"
INDEX_PATH = "./rag_index"

def send_slack_alert(message):
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        print("⚠️ Slack webhook not configured.")
        return
    payload = {
        "text": f"🚨 *LangSec Alert!*\n\n{message}"
    }
    response = requests.post(webhook, json=payload)
    print("📣 Slack alert sent." if response.status_code == 200 else "❌ Slack alert failed.")


def load_documents():
    docs = []
    for filename in os.listdir(DOCS_PATH):
        path = os.path.join(DOCS_PATH, filename)
        if filename.endswith(".pdf"):
            loader = PyPDFLoader(path)
        elif filename.endswith(".txt"):
            loader = TextLoader(path)
        else:
            continue
        docs.extend(loader.load())
    return docs

def build_vector_index():
    print("📚 Loading documents...")
    raw_docs = load_documents()
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    docs = text_splitter.split_documents(raw_docs)
    embeddings = OpenAIEmbeddings()
    vectorstore = FAISS.from_documents(docs, embeddings)
    vectorstore.save_local(INDEX_PATH)
    print("✅ RAG index saved to:", INDEX_PATH)

def log_to_google_sheets(question, answer):
    try:
        scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        creds = ServiceAccountCredentials.from_json_keyfile_name("path/to/creds.json", scope)
        client = gspread.authorize(creds)

        sheet_id = os.getenv("GOOGLE_SHEET_ID")
        sheet = client.open_by_key(sheet_id).sheet1
        sheet.append_row([question, answer])
        print("✅ Logged to Google Sheets.")
    except Exception as e:
        print("❌ Sheet logging failed:", e)

def scan_url_with_virustotal(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("⚠️ VirusTotal key missing.")
        return

    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        response = requests.post(endpoint, headers=headers, data={"url": url})
        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]
            print(f"🦠 URL submitted to VirusTotal. Scan ID: {scan_id}")
        else:
            print("❌ VT scan failed:", response.text)
    except Exception as e:
        print("💥 VT error:", e)


if __name__ == "__main__":
    build_vector_index()
