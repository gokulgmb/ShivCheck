import openai
import pdfplumber
import tiktoken
import os
import time


OPENAI_API_KEY = ''  # Set in your system before running



openai.api_key = OPENAI_API_KEY  


pdf_path = input("Enter the full path of the PDF file: ").strip()


if not os.path.isfile(pdf_path):
    print(f"Error: The file '{pdf_path}' does not exist. Please check the path and try again.")
    exit(1)


def extract_text_from_pdf(pdf_file):
    text = ""
    with pdfplumber.open(pdf_file) as pdf:
        for page in pdf.pages:
            extracted_text = page.extract_text()
            if extracted_text:
                text += extracted_text + "\n"
    return text


def split_text_into_chunks(text, max_tokens=1500):
    enc = tiktoken.encoding_for_model("gpt-4")  
    tokens = enc.encode(text)
    chunks = [tokens[i:i+max_tokens] for i in range(0, len(tokens), max_tokens)]
    return [enc.decode(chunk) for chunk in chunks]


def call_openai_with_retry(messages, model="gpt-4", max_retries=5):
    retries = 0
    wait_time = 10  

    while retries < max_retries:
        try:
            response = openai.ChatCompletion.create(
                model=model,
                messages=messages,
                max_tokens=200  
            )
            return response["choices"][0]["message"]["content"].strip()

        except openai.error.RateLimitError:
            print(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
            wait_time *= 2  
            retries += 1

        except openai.error.Timeout:
            print(f"Request timed out. Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
            retries += 1

        except openai.error.AuthenticationError:
            print("Invalid API key. Check your OpenAI API key and try again.")
            return "Error: Invalid API key."

        except openai.error.OpenAIError as e:
            print(f"OpenAI API Error: {e}")
            return "Error: API request failed."
    
    print("Max retries reached. Please try again later.")
    return "Error: API quota exceeded."


def analyze_pdf_with_chatgpt(chunks):
    responses = []
    for idx, chunk in enumerate(chunks):
        print(f"Processing chunk {idx+1}/{len(chunks)}...")  

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity expert analyzing a Static Analysis Report for a mobile application. "
                    "Your task is to extract and verify security protections based on the following conditions: "
                    "1. **Check if Memory NX (No-Execute) protection is enabled.** "
                    "2. **Check if the application is properly signed. Provide details about the signing scheme used (v1, v2, v3).** "
                    "3. **Check if anti-VM protection is enabled. Identify techniques like fingerprinting or emulator detection.** "
                    "4. **Check if obfuscation is enabled. Look for mentions of ProGuard, R8, DexGuard, or Arxan.** "
		    "5. **Check if there are any profanity words, if there are any profanity words notify me. **"
		    "6. **Check if there are any opcodes and if there more than 10 opcode entry notify me. **"
		    "7. **Check if there any unexpected files entry reported and if there are any notify me. **"
                    "If all protections are enabled, respond with: 'The binary application is accepted to be released.' "
                    "If any protections are missing, respond with: 'The binary application is rejected to be released.' "
                    "Provide clear details on missing protections."
                )
            },
            {
                "role": "user",
                "content": chunk
            }
        ]

        response = call_openai_with_retry(messages)
        responses.append(response)


    summary_messages = [
        {
            "role": "system",
            "content": "Summarize the following analysis in one line: "
        },
        {
            "role": "user",
            "content": " ".join(responses)
        }
    ]

    return call_openai_with_retry(summary_messages)


pdf_text = extract_text_from_pdf(pdf_path)

if pdf_text.strip():
    chunks = split_text_into_chunks(pdf_text)
    final_decision = analyze_pdf_with_chatgpt(chunks)
    

    print("\n### Final Decision ###")
    print(final_decision)
else:
    print("No extractable text found in the PDF.")
