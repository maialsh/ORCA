# BinSleuth Streamlit Frontend

A comprehensive web interface for the BinSleuth binary analysis platform, providing an intuitive dashboard for uploading, analyzing, and exploring binary files with advanced AI-powered insights.

## Features

### 🏠 Dashboard

- **Analysis History**: View all previously analyzed binaries with timestamps, functionality descriptions, and analysis goals
- **Statistics**: Real-time metrics showing total analyses, completion rates, and unique binaries processed
- **Timeline Visualization**: Interactive charts showing analysis activity over time
- **Quick Actions**: Easy access to start new analyses or export results

### 📁 Binary Upload & Analysis

- **File Upload**: Support for various binary formats (EXE, DLL, SO, BIN, ELF)
- **Analysis Configuration**:
  - Binary name and functionality description
  - Selectable analysis goals (capabilities, malware analysis, comprehensive analysis)
- **Real-time Traces**: Live monitoring of analysis progress with detailed step-by-step traces
- **Comprehensive Analysis**: Integrates with the full BinSleuth workflow including:
  - Static analysis
  - API cross-reference analysis
  - API clustering
  - Dynamic analysis (when available)
  - Malware detection
  - Capabilities identification

### 📊 Analysis Results (4 Segments)

1. **🔍 Binary Information**

   - File metadata (name, size, type, SHA256)
   - Imported functions summary
   - Functions discovered in the binary

2. **🔧 API Analysis**

   - Referenced APIs with usage context
   - Functions containing API calls
   - API relevance analysis based on declared functionality

3. **🔗 Cross-Reference Analysis**

   - API cross-references with code locations
   - Function-level API usage mapping
   - Call site analysis

4. **🎯 Cluster Analysis**
   - API clustering by functionality
   - Security assessment per cluster
   - Behavioral pattern identification

### 💬 Interactive Chatbot

- **Enhanced AI Assistant**: Powered by the same enhanced chatbot from the CLI version
- **Advanced Workflows**:
  - `list apis` - Show all APIs used with clustering
  - `how is <API> used?` - Comprehensive API usage analysis with ASM
  - `analyze function <name>` - Detailed function analysis with LLM insights
  - `malware analysis` - Security assessment and threat analysis
- **Natural Language Queries**: Ask questions about binary capabilities, security implications, and analysis results
- **Conversation History**: Persistent chat history during the session

### 🔍 Search & Analysis Tools

- **String Search**: Find specific strings within the binary with context
- **API Search**: Locate specific APIs and their usage patterns
- **Function Search**: Search for functions by name with address information
- **Suspicious Analysis**: AI-powered detection of potentially malicious string patterns with risk scoring

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenAI API key (set as `OPENAI_API_KEY` environment variable)
- Binary Ninja (optional, for enhanced analysis capabilities)

### Setup Instructions

1. **Clone the repository** (if not already done):

   ```bash
   git clone <repository-url>
   cd binsleuth
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements_frontend.txt
   ```

3. **Set up environment variables**:

   ```bash
   export OPENAI_API_KEY="your-openai-api-key-here"
   ```

4. **Ensure BinSleuth backend is properly configured**:
   - Verify that the `binsleuth/src/cmd/` directory contains all necessary modules
   - Check that Binary Ninja is installed (if using enhanced features)

## Usage

### Starting the Frontend

1. **Launch the Streamlit application**:

   ```bash
   streamlit run streamlit_frontend.py
   ```

2. **Access the web interface**:
   - Open your browser to `http://localhost:8501`
   - The application will automatically open in your default browser

### Basic Workflow

1. **Upload a Binary**:

   - Navigate to "Upload & Analyze" in the sidebar
   - Choose a binary file (EXE, DLL, SO, BIN, ELF)
   - Provide a descriptive name and functionality description
   - Select analysis goal (recommended: "capabilities and malware analysis")

2. **Monitor Analysis**:

   - Watch real-time traces showing analysis progress
   - Analysis typically takes 2-10 minutes depending on binary complexity
   - Progress is shown in both the main area and sidebar

3. **Explore Results**:

   - Navigate to "Analysis Results" to view the 4-segment analysis
   - Each segment provides different insights into the binary
   - Use expanders to view detailed information

4. **Interactive Analysis**:
   - Go to "Chatbot" to ask questions about your analysis
   - Try specific commands like `list apis` or `malware analysis`
   - Use "Search Tools" for targeted searches within the results

### Advanced Features

#### Enhanced Chatbot Commands

- **`list apis`**: Comprehensive API listing with clustering and categorization
- **`how is CreateFile used?`**: Deep dive into specific API usage with assembly analysis
- **`analyze function main`**: Detailed function analysis with LLM insights
- **`malware analysis`**: Security assessment and threat classification
- **`find string "suspicious"`**: Search for specific strings with context
- **`suspicious strings`**: AI-powered suspicious pattern detection

#### Search Tools

- **String Search**: Find specific text patterns within the binary
- **API Search**: Locate APIs by name with usage information
- **Function Search**: Find functions with address and context information
- **Suspicious Analysis**: Automated detection of potentially malicious indicators

#### Export and Sharing

- **Export Results**: Download complete analysis results as JSON
- **Analysis History**: Access previous analyses from the dashboard
- **Session Persistence**: Analysis results persist during the browser session

## Architecture

### Frontend Components

- **Streamlit Interface**: Modern web UI with responsive design
- **Session Management**: Persistent state management for analyses and chat history
- **Real-time Updates**: Live progress tracking during analysis
- **Interactive Visualizations**: Charts and graphs using Plotly

### Backend Integration

- **BinSleuth Workflow**: Direct integration with the comprehensive analysis pipeline
- **Enhanced Chatbot**: Full access to the AI-powered analysis assistant
- **Module System**: Seamless integration with all BinSleuth analysis modules

### Data Flow

1. **File Upload** → **Temporary Storage** → **Analysis Workflow**
2. **Analysis Results** → **Session State** → **UI Components**
3. **User Queries** → **Enhanced Chatbot** → **AI Responses**
4. **Search Requests** → **Analysis Data** → **Filtered Results**

## Configuration

### Environment Variables

- `OPENAI_API_KEY`: Required for AI-powered analysis and chatbot
- `DEBUG`: Set to '1' for detailed logging during analysis

### Customization

- **Analysis Goals**: Modify available options in the upload section
- **UI Styling**: Customize CSS in the `st.markdown()` sections
- **File Types**: Add support for additional binary formats in the file uploader

## Troubleshooting

### Common Issues

1. **"Failed to import BinSleuth modules"**:

   - Ensure the `binsleuth/src/cmd/` directory exists and contains all required modules
   - Check that all dependencies are installed: `pip install -r requirements_frontend.txt`

2. **Analysis fails with errors**:

   - Verify OpenAI API key is set correctly
   - Check that the binary file is valid and not corrupted
   - Review the analysis traces for specific error messages

3. **Chatbot not responding**:

   - Ensure an analysis has been completed first
   - Check OpenAI API key and network connectivity
   - Try refreshing the page and re-running the analysis

4. **Binary Ninja features not working**:
   - Install Binary Ninja and ensure it's in the expected path
   - Some features will work without Binary Ninja but with limited functionality

### Performance Optimization

- **Large Binaries**: Analysis time increases with binary size; consider using smaller test files initially
- **Memory Usage**: Close unused browser tabs and restart Streamlit if memory usage becomes high
- **API Rate Limits**: OpenAI API has rate limits; wait between analyses if you encounter limits

## Development

### Adding New Features

1. **New Analysis Components**: Add functions to display additional analysis results
2. **Enhanced Search**: Extend search capabilities in the `display_search_components()` function
3. **Custom Visualizations**: Add new charts and graphs using Plotly
4. **Additional File Types**: Extend file upload support for new binary formats

### Code Structure

- **`streamlit_frontend.py`**: Main application file with all UI components
- **Session State Management**: All persistent data stored in `st.session_state`
- **Modular Functions**: Each UI section implemented as a separate function
- **Error Handling**: Comprehensive try-catch blocks for robust operation

## Security Considerations

- **File Upload Security**: Uploaded files are stored temporarily and should be cleaned up
- **API Key Protection**: Never commit API keys to version control
- **Binary Analysis Safety**: Analysis is performed in isolated environments when possible
- **Data Privacy**: Analysis results are stored only in browser session state

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section above
2. Review the BinSleuth CLI documentation for backend-related issues
3. Ensure all dependencies are properly installed
4. Verify environment variables are set correctly

## License

This frontend is part of the BinSleuth project and follows the same licensing terms as the main project.
