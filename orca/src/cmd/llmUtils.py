from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import OllamaLLM
from langchain_openai import ChatOpenA
from stsaticsss
from pathlib import Path
import json
import os

path = Path(__file__).parent
prompts_dir = path/"prompts"
#sys_prompt = path/"system_prompt.md"
class LlmUtils:
    def __init__(self, use_ollama=True):
        self.use_ollama = use_ollama
        self.model_id = "llama3.1:latest"
        self.llm = None
        self.strings_system_prompt = open(prompts_dir/"strings_api_system_prompt.md", 'r').read()
        self.strings_user_prompt = "{strings}"
        #self.system_prompt = open(str(sys_prompt)).read()
        self.tool_system_prompt = ""
        self.initiate_model()

    def initiate_model(self):
        if self.use_ollama:
            self.llm = OllamaLLM(model=self.model_id)
        else:
            creds = json.load(open(os.environ['AGENTCONFIG']))
            os.environ['OPENAI_API_KEY'] = creds['OPENAI_API_KEY']
            self.llm = ChatOpenAI()


    def get_chain(self, sys_template, h_template):
        chat_prompt = ChatPromptTemplate.from_messages([
            ("system", sys_template),
            ("user", h_template)
        ])
        chain  = chat_prompt | self.llm
        return chain
    
    def str_processor(self, strlist):
        chain = self.get_chain(self.strings_system_prompt, self.strings_user_prompt)
        results = chain.invoke({"strings":strlist})
        return results if self.use_ollama else results.content
    
    def invoke_func_2(self,query):
        chain = self.get_chain(self.tool_system_prompt, "{query}")
        return chain.invoke({"query":query})
