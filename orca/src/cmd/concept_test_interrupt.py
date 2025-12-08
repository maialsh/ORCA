from typing import Annotated, Literal
import os
from langchain.chat_models import init_chat_model
# from langchain_tavily import TavilySearch
from langchain_core.tools import tool
from typing_extensions import TypedDict
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import Command, interrupt
import json

creds = json.load(open(os.environ['AGENTCONFIG']))
os.environ['OPENAI_API_KEY'] = creds['OPENAI_API_KEY']
memory = MemorySaver()
llm = init_chat_model("openai:gpt-4.1")

class AgentState(TypedDict):
    """State for the agent"""
    messages: Annotated[list, add_messages]
    llm_output: str

@tool
def human_assistant(state: AgentState) -> Command[Literal["dynamic_analysis", "static_analysis"]]:
    """Request assistance from a human on the type of analysis to perform."""
    is_approved = interrupt(
        {
            "question": "Is this correct?",
            # Surface the output that should be
            # reviewed and approved by the human.
            "llm_output": state["llm_output"]
        }
    )
    if is_approved:
        return Command(goto="dynamic_analysis")
    else:
        return Command(goto="static_analysis")

tools = [human_assistant]
llm_with_tools = llm.bind_tools(tools)

def dynamic_analysis(state: AgentState) -> AgentState:
    """Perform dynamic analysis on the provided binary file."""
    # Placeholder for dynamic analysis logic
    # This should return a state with the results of the analysis
    return {**state, "dynamic_analysis": {"status": "completed", "details": "Dynamic analysis results here"}}

def static_analysis(state: AgentState) -> AgentState:
    """Perform static analysis on the provided binary file."""
    # Placeholder for static analysis logic
    # This should return a state with the results of the analysis
    return {**state, "static_analysis": {"status": "completed", "details": "Static analysis results here"}}

def chatbot(state: AgentState) -> AgentState:
    message = llm_with_tools.invoke(state["messages"])
    state["llm_output"] = message.content
    # Because we will be interrupting during tool execution,
    # we disable parallel tool calling to avoid repeating any
    # tool invocations when we resume.
    assert len(message.tool_calls) <= 1
    return {"messages": [message]}

graph_builder = StateGraph(AgentState)
graph_builder.add_node("chatbot", chatbot)

tool_node = ToolNode(tools=tools)
graph_builder.add_node("tools", tool_node)

graph_builder.add_conditional_edges(
    "chatbot",
    tools_condition,
)
graph_builder.add_edge("tools", "chatbot")
graph_builder.add_edge(START, "chatbot")
graph = graph_builder.compile(checkpointer=memory)

user_input = "Can you perform analysis on the binary? Ask the human on the type of analysis to perform"
config = {"configurable": {"thread_id": "1"}}

graph.invoke(
    {"messages": [{"role": "user", "content": user_input}]},
    config,
    stream_mode="values",
)
# for event in events:
#     if "messages" in event:
#         event["messages"][-1].pretty_print()