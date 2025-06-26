from dotenv import load_dotenv
import os

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
