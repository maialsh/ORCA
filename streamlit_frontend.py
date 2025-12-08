#!/usr/bin/env python3
"""
ORCA Streamlit Frontend
A comprehensive web interface for binary analysis using the ORCA framework
"""

import streamlit as st
import os
import sys
import json
import time
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from io import StringIO
import hashlib

# Add the ORCA source directory to Python path
ORCA_PATH = Path(__file__).parent / "orca" / "src" / "cmd"
if ORCA_PATH.exists():
    sys.path.insert(0, str(ORCA_PATH))

# Import ORCA modules
try:
    from workflow import run_workflow
    from enhanced_chatbot_complete import EnhancedOrcaChatbot
    from enhanced_string_analysis import EnhancedStringAnalyzer
    ORCA_AVAILABLE = True
except ImportError as e:
    st.error(f"Failed to import ORCA modules: {e}")
    ORCA_AVAILABLE = False

# Configure Streamlit page
st.set_page_config(
    page_title="ORCA - Binary Analysis Platform",
    page_icon="⚪",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        animation: fadeInDown 1s ease-in-out;
    }
    .section-header {
        font-size: 1.5rem;
        color: #2c3e50;
        border-bottom: 2px solid #3498db;
        padding-bottom: 0.5rem;
        margin: 1rem 0;
        animation: slideInLeft 0.8s ease-out;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        animation: fadeInUp 0.6s ease-out;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
    }
    @keyframes fadeInDown {
        from { opacity: 0; transform: translateY(-30px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes slideInLeft {
        from { opacity: 0; transform: translateX(-30px); }
        to { opacity: 1; transform: translateX(0); }
    }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    .pulse-animation {
        animation: pulse 2s infinite;
    }
    .analysis-status {
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 5px solid #3498db;
    }
    .chatbot-container {
        background: #f8f9fa;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .trace-container {
        background: #2c3e50;
        color: #ecf0f1;
        padding: 1rem;
        border-radius: 5px;
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
        max-height: 400px;
        overflow-y: auto;
    }
    .results-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1rem;
        margin: 1rem 0;
    }
    .result-card {
        background: white;
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .binary-info {
        background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    .api-analysis {
        background: linear-gradient(135deg, #fd79a8 0%, #e84393 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    .crossref-analysis {
        background: linear-gradient(135deg, #fdcb6e 0%, #e17055 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    .cluster-analysis {
        background: linear-gradient(135deg, #55a3ff 0%, #003d82 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
def initialize_session_state():
    """Initialize Streamlit session state variables"""
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = []
    if 'current_analysis' not in st.session_state:
        st.session_state.current_analysis = None
    if 'analysis_running' not in st.session_state:
        st.session_state.analysis_running = False
    if 'analysis_traces' not in st.session_state:
        st.session_state.analysis_traces = []
    if 'chatbot' not in st.session_state:
        st.session_state.chatbot = None
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    if 'uploaded_file_path' not in st.session_state:
        st.session_state.uploaded_file_path = None

def save_uploaded_file(uploaded_file) -> str:
    """Save uploaded file to temporary directory and return path"""
    if uploaded_file is not None:
        # Create uploads directory if it doesn't exist
        uploads_dir = Path("uploads")
        uploads_dir.mkdir(exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = uploads_dir / f"{timestamp}_{uploaded_file.name}"
        
        # Save file
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        return str(file_path)
    return None

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of file"""
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "unknown"

def add_trace(message: str):
    """Add trace message to analysis traces"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    trace_msg = f"[{timestamp}] {message}"
    st.session_state.analysis_traces.append(trace_msg)

def run_analysis_workflow(binary_path: str, binary_name: str, binary_functionality: str, analysis_goal: str):
    """Run the ORCA analysis workflow"""
    if not ORCA_AVAILABLE:
        st.error("ORCA modules not available. Please check installation.")
        return None
    
    try:
        add_trace("Starting comprehensive binary analysis...")
        add_trace(f"Binary: {binary_name}")
        add_trace(f"Functionality: {binary_functionality}")
        add_trace(f"Goal: {analysis_goal}")
        
        # Run the workflow
        add_trace("Initializing analysis workflow...")
        results = run_workflow(
            binary_path=binary_path,
            binary_functionality=binary_functionality,
            goal=analysis_goal
        )
        
        add_trace("Analysis workflow completed successfully!")
        
        # Create analysis record
        analysis_record = {
            'timestamp': datetime.now().isoformat(),
            'binary_name': binary_name,
            'binary_path': binary_path,
            'binary_functionality': binary_functionality,
            'analysis_goal': analysis_goal,
            'file_hash': calculate_file_hash(binary_path),
            'results': results,
            'status': 'completed'
        }
        
        return analysis_record
        
    except Exception as e:
        add_trace(f"Analysis failed: {str(e)}")
        st.error(f"Analysis failed: {str(e)}")
        return None

def display_dashboard():
    """Display the main dashboard with analysis history and statistics"""
    st.markdown('<h1 class="main-header"> ORCA Dashboard</h1>', unsafe_allow_html=True)
    
    # Add circular image under the title with enhanced effects
    try:
        import base64
        
        # Read and encode the image
        with open("image.png", "rb") as img_file:
            img_data = base64.b64encode(img_file.read()).decode()
        
        # Display circular image with creative styling and floating animation
        st.markdown(f"""
        <div style="display: flex; justify-content: center; margin: 2rem 0;">
            <div style="
                width: 250px;
                height: 250px;
                border-radius: 50%;
                background-image: url(data:image/png;base64,{img_data});
                background-size: cover;
                background-position: center;
                border: 6px solid #8e44ad;
                box-shadow: 0 8px 32px rgba(142, 68, 173, 0.4);
                transition: all 0.3s ease;
                animation: float 3s ease-in-out infinite;
                position: relative;
            " onmouseover="this.style.transform='scale(1.05) rotate(5deg)'" onmouseout="this.style.transform='scale(1) rotate(0deg)'">
            </div>
        </div>
        <p style="text-align: center; color: #666; font-style: italic; margin-top: 1rem; animation: fadeIn 2s ease-in;">
             Advanced Binary Analysis Platform for Security Professionals
        </p>
        <style>
            @keyframes float {{
                0%, 100% {{ transform: translateY(0px); }}
                50% {{ transform: translateY(-10px); }}
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; }}
                to {{ opacity: 1; }}
            }}
        </style>
        """, unsafe_allow_html=True)
    except Exception as e:
        st.info("Image not found or could not be loaded")
    
    # Add a welcome message with typing effect
    st.markdown("""
    <div style="text-align: center; margin: 2rem 0; padding: 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 15px; color: white;">
        <h3 style="margin: 0; animation: slideInLeft 1s ease-out;"> Welcome to ORCA</h3>
        <p style="margin: 0.5rem 0 0 0; animation: slideInRight 1s ease-out;">Advanced platform for comprehensive binary capability and malware analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Statistics section
    col1, col2, col3, col4 = st.columns(4)
    
    total_analyses = len(st.session_state.analysis_history)
    completed_analyses = len([a for a in st.session_state.analysis_history if a.get('status') == 'completed'])
    unique_binaries = len(set([a.get('file_hash') for a in st.session_state.analysis_history]))
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{total_analyses}</h3>
            <p>Total Analyses</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{completed_analyses}</h3>
            <p>Completed</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{unique_binaries}</h3>
            <p>Unique Binaries</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        success_rate = (completed_analyses / total_analyses * 100) if total_analyses > 0 else 0
        st.markdown(f"""
        <div class="metric-card">
            <h3>{success_rate:.1f}%</h3>
            <p>Success Rate</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Analysis history
    if st.session_state.analysis_history:
        st.markdown('<div class="section-header"> Analysis History</div>', unsafe_allow_html=True)
        
        # Create DataFrame for history
        history_data = []
        for analysis in st.session_state.analysis_history:
            history_data.append({
                'Timestamp': analysis.get('timestamp', ''),
                'Binary Name': analysis.get('binary_name', ''),
                'Functionality': analysis.get('binary_functionality', ''),
                'Goal': analysis.get('analysis_goal', ''),
                'Status': analysis.get('status', ''),
                'File Hash': analysis.get('file_hash', '')[:16] + '...' if analysis.get('file_hash') else ''
            })
        
        df = pd.DataFrame(history_data)
        st.dataframe(df, use_container_width=True)
        
        # Analysis over time chart
        if len(history_data) > 1:
            st.markdown('<div class="section-header"> Analysis Timeline</div>', unsafe_allow_html=True)
            
            # Convert timestamps for plotting
            timestamps = [datetime.fromisoformat(a['timestamp']) for a in st.session_state.analysis_history]
            dates = [t.date() for t in timestamps]
            
            # Count analyses per day
            date_counts = {}
            for date in dates:
                date_counts[date] = date_counts.get(date, 0) + 1
            
            fig = px.line(
                x=list(date_counts.keys()),
                y=list(date_counts.values()),
                title="Analyses Over Time",
                labels={'x': 'Date', 'y': 'Number of Analyses'}
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No analysis history available. Upload and analyze a binary to get started!")

def display_upload_section():
    """Display binary upload and analysis configuration section"""
    st.markdown('<div class="section-header">Binary Upload & Analysis</div>', unsafe_allow_html=True)
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a binary file to analyze",
        # type=['exe', 'dll', 'so', 'bin', 'elf',"Mach-O"],
        help="Upload executable files for analysis"
    )
    
    if uploaded_file is not None:
        # Save uploaded file
        file_path = save_uploaded_file(uploaded_file)
        st.session_state.uploaded_file_path = file_path
        
        # Display file information
        file_size = len(uploaded_file.getbuffer())
        file_hash = calculate_file_hash(file_path)
        
        st.success(f" File uploaded successfully: {uploaded_file.name}")
        
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**File Size:** {file_size:,} bytes")
        with col2:
            st.info(f"**SHA256:** {file_hash[:32]}...")
        
        # Analysis configuration
        st.markdown("### Analysis Configuration")
        
        binary_name = st.text_input(
            "Binary Name",
            value=uploaded_file.name,
            help="Descriptive name for the binary"
        )
        
        binary_functionality = st.text_area(
            "Binary Functionality Description",
            placeholder="Describe what this binary is supposed to do (e.g., 'Text editor application', 'System utility for file management')",
            help="Provide a detailed description of the binary's intended functionality"
        )
        
        analysis_goal = st.selectbox(
            "Analysis Goal",
            options=[
                "capabilities",
                "malware analysis",
                "capabilities and malware analysis",
                "comprehensive analysis"
            ],
            index=2,
            help="Select the type of analysis to perform"
        )
        
        # Analysis button
        if st.button(" Start Analysis", type="primary", disabled=st.session_state.analysis_running):
            if not binary_functionality.strip():
                st.error("Please provide a description of the binary's functionality.")
            else:
                st.session_state.analysis_running = True
                st.session_state.analysis_traces = []
                
                # Run analysis in a separate thread (simulated for demo)
                with st.spinner("Running comprehensive analysis..."):
                    analysis_result = run_analysis_workflow(
                        file_path, binary_name, binary_functionality, analysis_goal
                    )
                    
                    if analysis_result:
                        st.session_state.analysis_history.append(analysis_result)
                        st.session_state.current_analysis = analysis_result
                        st.success(" Analysis completed successfully!")
                        st.rerun()
                    
                st.session_state.analysis_running = False

def display_analysis_traces():
    """Display real-time analysis traces"""
    if st.session_state.analysis_traces:
        st.markdown('<div class="section-header"> Analysis Traces</div>', unsafe_allow_html=True)
        
        traces_text = "\n".join(st.session_state.analysis_traces[-20:])  # Show last 20 traces
        st.markdown(f"""
        <div class="trace-container">
            {traces_text.replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)
        
        # Auto-refresh during analysis
        if st.session_state.analysis_running:
            time.sleep(1)
            st.rerun()

def display_analysis_results():
    """Display comprehensive analysis results in 4 segments"""
    if not st.session_state.current_analysis:
        st.info("No analysis results available. Please upload and analyze a binary first.")
        return
    
    results = st.session_state.current_analysis.get('results', {})
    
    st.markdown('<div class="section-header"> Analysis Results</div>', unsafe_allow_html=True)
    
    # Create 4 result segments
    col1, col2 = st.columns(2)
    
    with col1:
        # Segment 1: Binary Information
        display_binary_information_segment(results)
        
        # Segment 3: Cross-Reference Analysis
        display_crossref_analysis_segment(results)
    
    with col2:
        # Segment 2: API Analysis
        display_api_analysis_segment(results)
        
        # Segment 4: Cluster Analysis
        display_cluster_analysis_segment(results)

def display_binary_information_segment(results: Dict[str, Any]):
    """Display binary information segment"""
    st.markdown("""
    <div class="binary-info">
        <h3> Binary Information</h3>
    </div>
    """, unsafe_allow_html=True)
    
    static_results = results.get('static_analysis_results', {})
    file_info = static_results.get('file_info', {})
    
    if file_info:
        st.write("**File Details:**")
        st.write(f"- **Name:** {file_info.get('name', 'Unknown')}")
        st.write(f"- **Size:** {file_info.get('size', 'Unknown')} bytes")
        st.write(f"- **Type:** {file_info.get('type', 'Unknown')}")
        st.write(f"- **SHA256:** {file_info.get('sha256', 'Unknown')}")
    
    # Imports summary
    imports = static_results.get('imports', [])
    if imports:
        st.write(f"**Imported Functions:** {len(imports)}")
        with st.expander("View Imports"):
            for imp in imports[:50]:  # Show first 50
                st.write(f"- {imp}")
            if len(imports) > 50:
                st.write(f"... and {len(imports) - 50} more")
    
    # Functions summary
    functions = static_results.get('functions', [])
    if functions:
        st.write(f"**Functions Found:** {len(functions)}")
        with st.expander("View Functions"):
            for func in functions[:20]:  # Show first 20
                st.write(f"- {func.get('name', 'unknown')} @ {func.get('address', 'unknown')}")
            if len(functions) > 20:
                st.write(f"... and {len(functions) - 20} more")

def display_api_analysis_segment(results: Dict[str, Any]):
    """Display API analysis segment"""
    st.markdown("""
    <div class="api-analysis">
        <h3> API Analysis</h3>
    </div>
    """, unsafe_allow_html=True)
    
    api_analysis = results.get('api_analysis_results', {})
    
    if api_analysis:
        referenced_apis = api_analysis.get('referenced_apis', [])
        filtered_functions = api_analysis.get('filtered_functions', [])
        
        st.write(f"**Referenced APIs:** {len(referenced_apis)}")
        st.write(f"**Functions with API calls:** {len(filtered_functions)}")
        
        if referenced_apis:
            with st.expander("View Referenced APIs"):
                for api in referenced_apis[:30]:
                    st.write(f"- {api}")
                if len(referenced_apis) > 30:
                    st.write(f"... and {len(referenced_apis) - 30} more")
        
        # API relevance
        api_relevance = api_analysis.get('api_relevance', {})
        if api_relevance:
            with st.expander("API Relevance Analysis"):
                st.json(api_relevance)
    else:
        st.write("No API analysis results available.")

def display_crossref_analysis_segment(results: Dict[str, Any]):
    """Display cross-reference analysis segment"""
    st.markdown("""
    <div class="crossref-analysis">
        <h3> Cross-Reference Analysis</h3>
    </div>
    """, unsafe_allow_html=True)
    
    crossref_results = results.get('api_crossrefs_results', {})
    
    if crossref_results:
        st.write("**Cross-Reference Summary:**")
        
        # Count total references
        total_refs = 0
        for api_name, api_data in crossref_results.items():
            if isinstance(api_data, dict) and 'references' in api_data:
                total_refs += len(api_data['references'])
        
        st.write(f"- **Total API References:** {total_refs}")
        st.write(f"- **APIs with References:** {len(crossref_results)}")
        
        with st.expander("View Cross-References"):
            for api_name, api_data in list(crossref_results.items())[:10]:
                if isinstance(api_data, dict) and 'references' in api_data:
                    refs = api_data['references']
                    st.write(f"**{api_name}:** {len(refs)} references")
                    for ref in refs[:3]:
                        if isinstance(ref, dict):
                            func_name = ref.get('function', 'unknown')
                            st.write(f"  - Function: {func_name}")
            if len(crossref_results) > 10:
                st.write(f"... and {len(crossref_results) - 10} more APIs")
    else:
        st.write("No cross-reference analysis results available.")

def display_cluster_analysis_segment(results: Dict[str, Any]):
    """Display cluster analysis segment"""
    st.markdown("""
    <div class="cluster-analysis">
        <h3> Cluster Analysis</h3>
    </div>
    """, unsafe_allow_html=True)
    
    clustering_results = results.get('api_clustering_results', {})
    
    if clustering_results and clustering_results.get('clusters'):
        clusters = clustering_results['clusters']
        st.write(f"**API Clusters Found:** {len(clusters)}")
        
        # Cluster summary
        for i, cluster in enumerate(clusters[:5]):
            cluster_name = cluster.get('name', f'Cluster {i+1}')
            cluster_apis = cluster.get('apis', [])
            security = cluster.get('security_assessment', 'unknown')
            
            st.write(f"**{cluster_name}** ({security})")
            st.write(f"- APIs: {len(cluster_apis)}")
            st.write(f"- Description: {cluster.get('description', 'No description')}")
        
        if len(clusters) > 5:
            st.write(f"... and {len(clusters) - 5} more clusters")
        
        with st.expander("View Detailed Clusters"):
            for cluster in clusters:
                st.write(f"**{cluster.get('name', 'Unknown')}**")
                st.write(f"Security: {cluster.get('security_assessment', 'unknown')}")
                st.write(f"Description: {cluster.get('description', 'No description')}")
                apis = cluster.get('apis', [])
                if apis:
                    st.write("APIs:")
                    for api in apis[:10]:
                        st.write(f"  - {api}")
                    if len(apis) > 10:
                        st.write(f"  ... and {len(apis) - 10} more")
                st.write("---")
    else:
        st.write("No cluster analysis results available.")

def display_chatbot_interface():
    """Display interactive chatbot interface"""
    st.markdown('<div class="section-header"> Interactive Chatbot</div>', unsafe_allow_html=True)
    
    if not st.session_state.current_analysis:
        st.info("Please complete an analysis first to use the chatbot.")
        return
    
    # Initialize chatbot if not already done
    if st.session_state.chatbot is None:
        try:
            results = st.session_state.current_analysis.get('results', {})
            st.session_state.chatbot = EnhancedOrcaChatbot(
                analysis_context=results,
                analysis_state=results.get('binary_view')
            )
        except Exception as e:
            st.error(f"Failed to initialize chatbot: {e}")
            return
    
    # Chat interface
    st.markdown("""
    <div class="chatbot-container">
        <h4> Enhanced ORCA Assistant</h4>
        <p>Ask questions about your binary analysis results. Try commands like:</p>
        <ul>
            <li><code>list apis</code> - Show all APIs used</li>
            <li><code>how is CreateFile used?</code> - Analyze specific API usage</li>
            <li><code>analyze function main</code> - Detailed function analysis</li>
            <li><code>malware analysis</code> - Security assessment</li>
            <li><code>find string "example"</code> - Search for specific strings</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Chat history
    if st.session_state.chat_history:
        st.markdown("### Chat History")
        for i, (user_msg, bot_response) in enumerate(st.session_state.chat_history):
            with st.container():
                st.markdown(f"**You:** {user_msg}")
                st.markdown(f"**ORCA:** {bot_response}")
                st.markdown("---")
    
    # Chat input
    user_input = st.text_input(
        "Ask a question about your binary:",
        placeholder="e.g., What are the main capabilities of this binary?",
        key="chat_input"
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        send_button = st.button("Send", type="primary")
    
    if send_button and user_input.strip():
        with st.spinner("Processing your question..."):
            try:
                response = st.session_state.chatbot.chat(user_input)
                st.session_state.chat_history.append((user_input, response))
                st.rerun()
            except Exception as e:
                st.error(f"Chatbot error: {e}")

def display_function_analysis():
    """Display function analysis component"""
    st.markdown('<div class="section-header"> Function Analysis</div>', unsafe_allow_html=True)
    
    if not st.session_state.current_analysis:
        st.info("Please complete an analysis first to use function analysis.")
        return
    
    results = st.session_state.current_analysis.get('results', {})
    static_results = results.get('static_analysis_results', {})
    functions = static_results.get('functions', [])
    
    if not functions:
        st.warning("No functions found in the analysis results.")
        return
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1rem; border-radius: 10px; margin: 1rem 0;">
        <h4> Function Analysis</h4>
        <p>Select a function from the list below to get detailed analysis including assembly instructions and LLM-powered insights.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Function selection
    st.subheader("Select Function to Analyze")
    
    # Create function options with name and address
    function_options = []
    function_map = {}
    
    for i, func in enumerate(functions):
        func_name = func.get('name', f'function_{i}')
        func_addr = func.get('address', 'unknown')
        display_name = f"{func_name} @ {func_addr}"
        function_options.append(display_name)
        function_map[display_name] = func_name
    
    # Function selector
    selected_function_display = st.selectbox(
        "Choose a function:",
        options=function_options,
        help="Select a function to analyze its assembly code and behavior"
    )
    
    if selected_function_display:
        selected_function_name = function_map[selected_function_display]
        
        # Analysis button
        if st.button(" Analyze Function", type="primary"):
            if st.session_state.chatbot is None:
                st.error("Chatbot not initialized. Please ensure analysis is complete.")
                return
            
            with st.spinner(f"Analyzing function '{selected_function_name}'..."):
                try:
                    # Use the enhanced chatbot to analyze the function
                    response = st.session_state.chatbot.chat(f"analyze function {selected_function_name}")
                    
                    # Display the analysis results
                    st.markdown("###  Function Analysis Results")
                    
                    # Create an expandable section for the full analysis
                    with st.expander(" Detailed Analysis", expanded=True):
                        st.markdown(response)
                    
                    # Try to extract specific information if available
                    st.markdown("###  Function Information")
                    
                    # Find the selected function details
                    selected_func_details = None
                    for func in functions:
                        if func.get('name', '') == selected_function_name:
                            selected_func_details = func
                            break
                    
                    if selected_func_details:
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Function Name:** {selected_func_details.get('name', 'Unknown')}")
                            st.write(f"**Address:** {selected_func_details.get('address', 'Unknown')}")
                            st.write(f"**Size:** {selected_func_details.get('size', 'Unknown')} bytes")
                        
                        with col2:
                            # Show behavior patterns if available
                            behaviors = selected_func_details.get('behavior', [])
                            if behaviors:
                                st.write("**Behavior Patterns:**")
                                for behavior in behaviors[:5]:  # Show first 5 behaviors
                                    behavior_type = behavior.get('type', 'unknown')
                                    st.write(f"- {behavior_type}")
                                if len(behaviors) > 5:
                                    st.write(f"... and {len(behaviors) - 5} more")
                            else:
                                st.write("**Behavior Patterns:** None detected")
                    
                    # Additional analysis options
                    st.markdown("###  Additional Analysis")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button(" Find API Usage"):
                            api_response = st.session_state.chatbot.chat(f"What APIs does function {selected_function_name} use?")
                            st.info(api_response)
                    
                    with col2:
                        if st.button(" Security Analysis"):
                            security_response = st.session_state.chatbot.chat(f"What are the security implications of function {selected_function_name}?")
                            st.warning(security_response)
                    
                    with col3:
                        if st.button(" Purpose Analysis"):
                            purpose_response = st.session_state.chatbot.chat(f"What is the purpose of function {selected_function_name}?")
                            st.success(purpose_response)
                    
                except Exception as e:
                    st.error(f"Error analyzing function: {str(e)}")
        
        # Show function preview
        if selected_function_display:
            st.markdown("###  Function Preview")
            
            # Find and display basic function info
            for func in functions:
                if func.get('name', '') == selected_function_name:
                    with st.expander("Function Details", expanded=False):
                        st.json(func)
                    break

def display_search_components():
    """Display search and analysis components"""
    st.markdown('<div class="section-header"> Search & Analysis Tools</div>', unsafe_allow_html=True)
    
    if not st.session_state.current_analysis:
        st.info("Please complete an analysis first to use search tools.")
        return
    
    results = st.session_state.current_analysis.get('results', {})
    static_results = results.get('static_analysis_results', {})
    
    # Search tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([" String Search", " API Search", " Function Search", " Suspicious Analysis", " Function Analysis"])
    
    with tab1:
        st.subheader("String Search")
        search_string = st.text_input("Search for string:", placeholder="Enter string to search for")
        
        if search_string and st.button("Search Strings"):
            strings_data = static_results.get('strings', {})
            found_strings = []
            
            for category, strings_list in strings_data.items():
                if isinstance(strings_list, list):
                    for s in strings_list:
                        if search_string.lower() in s.lower():
                            found_strings.append((category, s))
            
            if found_strings:
                st.success(f"Found {len(found_strings)} matching strings:")
                for category, string in found_strings:
                    st.write(f"**{category}:** `{string}`")
            else:
                st.warning("No matching strings found.")
    
    with tab2:
        st.subheader("API Search")
        search_api = st.text_input("Search for API:", placeholder="Enter API name to search for")
        
        if search_api and st.button("Search APIs"):
            imports = static_results.get('imports', [])
            matching_apis = [api for api in imports if search_api.lower() in api.lower()]
            
            if matching_apis:
                st.success(f"Found {len(matching_apis)} matching APIs:")
                for api in matching_apis:
                    st.write(f"- `{api}`")
            else:
                st.warning("No matching APIs found.")
    
    with tab3:
        st.subheader("Function Search")
        search_function = st.text_input("Search for function:", placeholder="Enter function name to search for")
        
        if search_function and st.button("Search Functions"):
            functions = static_results.get('functions', [])
            matching_functions = [func for func in functions if search_function.lower() in func.get('name', '').lower()]
            
            if matching_functions:
                st.success(f"Found {len(matching_functions)} matching functions:")
                for func in matching_functions:
                    st.write(f"- `{func.get('name', 'unknown')}` @ `{func.get('address', 'unknown')}`")
            else:
                st.warning("No matching functions found.")
    
    with tab4:
        st.subheader("Suspicious Analysis")
        if st.button("Analyze Suspicious Patterns"):
            try:
                # Get all strings for analysis
                strings_data = static_results.get('strings', {})
                all_strings = []
                for category, strings_list in strings_data.items():
                    if isinstance(strings_list, list):
                        all_strings.extend(strings_list)
                
                if all_strings:
                    analyzer = EnhancedStringAnalyzer()
                    results = analyzer.find_suspicious_strings(all_strings)
                    
                    st.write(f"**Risk Score:** {results.get('risk_score', 0)}/100")
                    st.write(f"**Summary:** {results.get('summary', 'No summary available')}")
                    
                    suspicious_strings = results.get('suspicious_strings', {})
                    for category, strings in suspicious_strings.items():
                        if strings:
                            st.write(f"**{category.replace('_', ' ').title()}:**")
                            for string_info in strings[:10]:
                                st.write(f"- `{string_info['string']}` - {string_info['reason']}")
                else:
                    st.warning("No strings available for analysis.")
            except Exception as e:
                st.error(f"Suspicious analysis failed: {e}")
    
    with tab5:
        # Function Analysis Tab - call the dedicated function analysis component
        display_function_analysis()

def main():
    """Main Streamlit application"""
    initialize_session_state()
    
    # Sidebar navigation with buttons
    st.sidebar.title(" ORCA")
    st.sidebar.markdown("---")
    
    # Navigation buttons
    st.sidebar.markdown("###  Navigation")
    
    # Create navigation buttons
    nav_buttons = {
        " Dashboard": "Dashboard",
        "Upload & Analyze": "Upload & Analyze",
        " Analysis Results": "Analysis Results",
        " Chatbot": "Chatbot",
        " Search Tools": "Search Tools"
    }
    
    # Initialize page state if not exists
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "Dashboard"
    
    # Create button layout
    for button_text, page_name in nav_buttons.items():
        if st.sidebar.button(
            button_text, 
            key=f"nav_{page_name}",
            use_container_width=True,
            type="primary" if st.session_state.current_page == page_name else "secondary"
        ):
            st.session_state.current_page = page_name
            st.rerun()
    
    page = st.session_state.current_page
    
    # Display current analysis info in sidebar
    if st.session_state.current_analysis:
        st.sidebar.markdown("### Current Analysis")
        analysis = st.session_state.current_analysis
        st.sidebar.write(f"**Binary:** {analysis.get('binary_name', 'Unknown')}")
        st.sidebar.write(f"**Status:** {analysis.get('status', 'Unknown')}")
        st.sidebar.write(f"**Goal:** {analysis.get('analysis_goal', 'Unknown')}")
        st.sidebar.write(f"**Timestamp:** {analysis.get('timestamp', 'Unknown')[:19]}")
        
        # Quick actions
        st.sidebar.markdown("### Quick Actions")
        if st.sidebar.button(" New Analysis"):
            st.session_state.current_analysis = None
            st.session_state.chatbot = None
            st.session_state.chat_history = []
            st.rerun()
        
        if st.sidebar.button(" Export Results"):
            try:
                results_json = json.dumps(analysis, indent=2, default=str)
                st.sidebar.download_button(
                    label=" Download JSON",
                    data=results_json,
                    file_name=f"orca_analysis_{analysis.get('binary_name', 'unknown')}.json",
                    mime="application/json"
                )
            except Exception as e:
                st.sidebar.error(f"Export failed: {e}")
    
    # Display analysis traces in sidebar if running
    if st.session_state.analysis_running or st.session_state.analysis_traces:
        st.sidebar.markdown("### Analysis Status")
        if st.session_state.analysis_running:
            st.sidebar.info(" Analysis in progress...")
        
        if st.session_state.analysis_traces:
            with st.sidebar.expander("Recent Traces", expanded=st.session_state.analysis_running):
                for trace in st.session_state.analysis_traces[-5:]:
                    st.sidebar.text(trace)
    
    # Main content area
    if page == "Dashboard":
        display_dashboard()
    elif page == "Upload & Analyze":
        display_upload_section()
        if st.session_state.analysis_running or st.session_state.analysis_traces:
            display_analysis_traces()
    elif page == "Analysis Results":
        display_analysis_results()
    elif page == "Chatbot":
        display_chatbot_interface()
    elif page == "Search Tools":
        display_search_components()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 1rem;">
         <strong>ORCA</strong> - Advanced Binary Analysis Platform<br>    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
