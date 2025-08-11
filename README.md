# Domain Reviewer Tool

A Python tool to review domains against VirusTotal's OSINT database and WHOIS information. This tool queries VirusTotal's API to gather reputation information, security analysis results, and metadata for a list of domains, plus WHOIS data to identify newly registered domains.

## Features

- **Domain Reputation Analysis**: Check if domains are marked as malicious
- **Vendor Analysis**: Count how many security vendors flag domains as malicious/suspicious
- **Metadata Extraction**: Get tags, categories, and last scan dates
- **WHOIS Integration**: Fetch domain registration information
- **Newly Registered Domain Detection**: Automatically identify domains registered within the last 6 months
- **Rate Limiting**: Respects VirusTotal's free API rate limits (15 seconds between requests)
- **Excel Output**: Generates formatted Excel reports with all findings
- **Progress Tracking**: Real-time progress bar and status updates
- **GUI Interface**: User-friendly graphical interface with file selection
- **Account Type Support**: Personal (15s delay, max 500 domains) and Enterprise (1s delay, unlimited)

## Prerequisites

- Python 3.8 or higher
- VirusTotal API key (free tier available)

## Installation

### Option 1: Command Line Version

1. **Clone or download this repository**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Get a VirusTotal API key**:
   - Visit: https://www.virustotal.com/gui/join-us
   - Sign up for a free account
   - Get your API key from your profile

4. **Configure your API key**:
   - Copy `env_example.txt` to `.env`
   - Replace `your_api_key_here` with your actual VirusTotal API key
   ```bash
   cp env_example.txt .env
   # Edit .env file with your API key
   ```

### Option 2: GUI Executable (Recommended)

1. **Build the executable**:
   ```bash
   python build_exe.py
   ```

2. **Run the executable**:
   - Navigate to the `dist` folder
   - Double-click `DomainReviewer.exe`

## Usage

### GUI Version (Recommended)

1. **Launch the application**:
   - Double-click `DomainReviewer.exe` (after building)
   - Or run: `python gui_main.py`

2. **Configure settings**:
   - Enter your VirusTotal API key
   - Select account type:
     - **Personal**: 15-second delay between requests, maximum 500 domains
     - **Enterprise**: 1-second delay between requests, unlimited domains
   - Click "Browse" to select your domain list file

3. **Start the review**:
   - Click "Start Review"
   - Monitor progress in the GUI
   - Results will be saved as Excel file

### Command Line Version

1. **Prepare your domain list**:
   Create a text file named `blocked_domains.txt` with one domain per line:
   ```
   example.com
   google.com
   suspicious-site.net
   ```

2. **Run the tool**:
   ```bash
   python main.py
   ```

3. **Review results**:
   The tool will generate an Excel file with timestamp: `domain_review_results_YYYYMMDD_HHMMSS.xlsx`

## Building the Executable

To create a standalone executable:

1. **Install build dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the build script**:
   ```bash
   python build_exe.py
   ```

3. **Find the executable**:
   - Location: `dist/DomainReviewer.exe`
   - Size: Approximately 50-100 MB
   - No Python installation required to run

## Output Format

The Excel file contains the following columns:

| Column | Description |
|--------|-------------|
| Domain | The domain name |
| Reputation_Score | VirusTotal reputation score (negative = malicious) |
| Is_Malicious | Boolean indicating if domain is malicious |
| Malicious_Vendors | Number of vendors marking as malicious |
| Suspicious_Vendors | Number of vendors marking as suspicious |
| Harmless_Vendors | Number of vendors marking as harmless |
| Undetected_Vendors | Number of vendors with no detection |
| Total_Vendors | Total number of vendors analyzed |
| Last_Scanned | When VirusTotal last analyzed the domain |
| Tags | Security tags associated with the domain |
| Categories | Domain categories (e.g., "security vendor", "phishing") |
| Domain_Category | Combined category (Newly Registered, Malicious, etc.) |
| Creation_Date | Domain registration date from WHOIS |
| Expiration_Date | Domain expiration date from WHOIS |
| Registrar | Domain registrar information |
| Is_Newly_Registered | Boolean indicating if domain is less than 6 months old |
| WHOIS_Status | Status of WHOIS query |
| Query_Status | Success/Error status of the API query |

## WHOIS Features

### Newly Registered Domain Detection
- **Automatic Detection**: Domains registered within the last 6 months are flagged
- **Category Labeling**: "Newly Registered Domain" added to Domain_Category column
- **Creation Date**: Shows exact registration date from WHOIS data
- **Registrar Info**: Displays domain registrar information

### WHOIS Data Included
- **Creation Date**: When the domain was first registered
- **Expiration Date**: When the domain registration expires
- **Registrar**: Company that registered the domain
- **Status**: Success/error status of WHOIS query

## Rate Limiting

The tool automatically implements rate limiting based on account type:

**Personal Accounts**:
- 15-second delay between requests
- Maximum 500 domains per run
- 4 requests per minute limit
- 500 requests per day limit

**Enterprise Accounts**:
- 1-second delay between requests
- Unlimited domains
- Higher rate limits

## Error Handling

The tool handles various error scenarios:
- Invalid domains
- API rate limits
- Network connectivity issues
- Missing API keys
- File I/O errors
- Domain count validation
- WHOIS query failures

Failed queries are logged in the output with error details.

## Example Output

### GUI Version
```
Review completed!

Total domains: 6
Successfully queried: 6
Malicious domains found: 2
Newly registered domains: 1
Results saved to: domain_review_results_20241201_143022.xlsx
```

### Command Line Version
```
=== Domain Reviewer Tool ===
Reviews domains against VirusTotal OSINT database and WHOIS

Loaded 6 domains from blocked_domains.txt

Starting review of 6 domains...
Rate limit: 15 seconds between requests

Querying domain 1/6: example.com
  Getting WHOIS information...
  Querying VirusTotal...
✓ Successfully queried example.com
  📅 Creation date: 1995-08-14

Querying domain 2/6: suspicious-site.net
  Getting WHOIS information...
  Querying VirusTotal...
✓ Successfully queried suspicious-site.net
  ⚠️  NEWLY REGISTERED DOMAIN (less than 6 months old)
  📅 Creation date: 2024-10-15

...

=== Summary ===
Total domains: 6
Successfully queried: 6
Malicious domains found: 2
Newly registered domains: 1
Results saved to: domain_review_results_20241201_143022.xlsx
```

## API Limits

**Free VirusTotal API limits**:
- 4 requests per minute
- 500 requests per day
- 15-second delay between requests (automatically handled)

**Paid plans** offer higher limits and faster response times.

## Troubleshooting

### Common Issues

1. **"VIRUSTOTAL_API_KEY environment variable not set"**
   - Ensure you have a `.env` file with your API key
   - Check that the key is correctly formatted

2. **"File 'blocked_domains.txt' not found"**
   - Create the input file with your domain list
   - Ensure it's in the same directory as the script

3. **"Personal accounts are limited to 500 domains"**
   - Reduce the number of domains in your input file
   - Or upgrade to an enterprise account

4. **Rate limit errors**
   - The tool automatically handles rate limits
   - For large domain lists, consider upgrading to a paid VirusTotal plan

5. **Executable not working**
   - Ensure all dependencies are installed before building
   - Try running the Python version first: `python gui_main.py`

6. **WHOIS query failures**
   - Some domains may have restricted WHOIS information
   - The tool will continue processing with available data

### Getting Help

- Check VirusTotal API documentation: https://developers.virustotal.com/
- Verify your API key is valid and has sufficient quota
- Review the error messages in the console output

## Files Description

- `gui_main.py` - GUI version of the tool with WHOIS support
- `main.py` - Command line version with WHOIS support
- `build_exe.py` - Build script for creating executable
- `domain_reviewer.spec` - PyInstaller configuration
- `requirements.txt` - Python dependencies including python-whois
- `blocked_domains.txt` - Sample domain list
- `sample_domains.txt` - Additional sample domains

## License

This tool is provided as-is for educational and security research purposes.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the tool.

## 🎨 Custom Icon

The application includes a custom icon with "CDC" branding:

### **Icon Features**
- **Custom Design**: Blue circular icon with "CDC" text
- **Multiple Sizes**: 16x16 to 256x256 pixels for all Windows contexts
- **Professional Look**: Clean, modern design suitable for enterprise use

### **Icon Usage**
- **Executable Icon**: The .exe file displays the custom icon
- **Window Icon**: Application window shows the custom icon
- **Taskbar Icon**: Appears in Windows taskbar with custom icon
- **File Explorer**: Executable shows custom icon in file listings

### **Creating/Updating the Icon**
```bash
# Install Pillow for icon creation
pip install Pillow

# Generate the icon
python create_icon.py

# Rebuild the executable with new icon
python -m PyInstaller domain_reviewer.spec
```

### **Icon File**
- **Location**: `domain_reviewer_icon.ico`
- **Format**: Windows ICO format with multiple resolutions
- **Design**: Blue gradient circle with "CDC" text overlay

## 🚀 Quick Start
