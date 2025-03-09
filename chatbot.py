import streamlit as st
import ollama

st.set_page_config(
    #page_title=" RHEL Chatbot",
    #page_icon="💬",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("RHEL Chatbot")

if "messages" not in st.session_state:
    st.session_state["messages"] = [{"role": "assistant", "content": "How can I help you?"}]

### Write Message History
for msg in st.session_state.messages:
    if msg["role"] == "user":
        st.chat_message(msg["role"], avatar="👨‍💼").write(msg["content"])
    else:
        st.chat_message(msg["role"], avatar="🎩").write(msg["content"])

## Generator for Streaming Tokens
def generate_response():
    response = ollama.chat(model='huggingface.co/ibm-research/granite-3.2-8b-instruct-GGUF:latest', stream=True, messages=st.session_state.messages)
    for partial_resp in response:
        token = partial_resp["message"]["content"]
        st.session_state["full_message"] += token
        yield token

if prompt := st.chat_input():
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.chat_message("user", avatar="👨‍💼").write(prompt)
    st.session_state["full_message"] = ""
    st.chat_message("assistant", avatar="🎩").write_stream(generate_response)
    st.session_state.messages.append({"role": "assistant", "content": st.session_state["full_message"]})
    