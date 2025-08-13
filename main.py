import os
import time
import requests
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dotenv import load_dotenv
from tqdm import tqdm
import whois

# Load environment variables
load_dotenv()

class VirusTotalDomainReviewer:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        self.rate_limit_delay = 15  # 15 seconds delay between requests for free API
    
    def get_whois_info(self, domain: str) -> Dict:
        """
        Get WHOIS information for a domain
        """
        try:
            # Try to get WHOIS information
            w = whois.whois(domain)
            
            # Get creation date
            creation_date = None
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
            
            # Check if domain is newly registered (less than 6 months)
            is_newly_registered = False
            if creation_date:
                six_months_ago = datetime.now() - timedelta(days=180)
                is_newly_registered = creation_date > six_months_ago
            
            # Get registrar info
            registrar = w.registrar if w.registrar else 'N/A'
            
            # Get expiration date
            expiration_date = None
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = w.expiration_date[0]
                else:
                    expiration_date = w.expiration_date
            
            return {
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'registrar': registrar,
                'is_newly_registered': is_newly_registered,
                'whois_status': 'Success'
            }
            
        except Exception as e:
            return {
                'creation_date': None,
                'expiration_date': None,
                'registrar': 'N/A',
                'is_newly_registered': False,
                'whois_status': f'Error: {str(e)}'
            }
    
    def get_domain_info(self, domain: str) -> Optional[Dict]:
        """
        Query VirusTotal API for domain information
        """
        try:
            url = f"{self.base_url}/domains/{domain}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"Domain {domain} not found in VirusTotal")
                return None
            elif response.status_code == 429:
                print(f"Rate limit exceeded for domain {domain}")
                return None
            else:
                print(f"Error querying domain {domain}: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Exception while querying domain {domain}: {str(e)}")
            return None
    
    def parse_domain_data(self, domain: str, data: Dict, whois_data: Dict) -> Dict:
        """
        Parse VirusTotal response data into structured format
        """
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get reputation data
            reputation = attributes.get('reputation', 0)
            is_malicious = reputation < 0
            
            # Get last analysis stats
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            harmless_count = last_analysis_stats.get('harmless', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            
            # Get last analysis date
            last_analysis_date = attributes.get('last_analysis_date')
            if last_analysis_date:
                last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
            
            # Get tags
            tags = attributes.get('tags', [])
            tags_str = ', '.join(tags) if tags else 'N/A'
            
            # Get categories
            categories = attributes.get('categories', {})
            categories_str = ', '.join([f"{k}: {v}" for k, v in categories.items()]) if categories else 'N/A'
            
            # Get total vendors
            last_analysis_results = attributes.get('last_analysis_results', {})
            total_vendors = len(last_analysis_results) if last_analysis_results else 0
            
            # Process WHOIS data
            creation_date = whois_data.get('creation_date')
            creation_date_str = creation_date.strftime('%Y-%m-%d') if creation_date else 'N/A'
            
            expiration_date = whois_data.get('expiration_date')
            expiration_date_str = expiration_date.strftime('%Y-%m-%d') if expiration_date else 'N/A'
            
            registrar = whois_data.get('registrar', 'N/A')
            is_newly_registered = whois_data.get('is_newly_registered', False)
            whois_status = whois_data.get('whois_status', 'N/A')
            
            # Create domain category with high-risk detection
            domain_category = []
            is_high_risk = False
            
            # Check for high-risk conditions
            risk_words = ['malicious', 'phishing', 'abuse', 'scam', 'fraud', 'malware', 
                         'suspicious', 'dangerous', 'threat', 'attack', 'exploit']
            
            # High-risk condition 1: Category contains risk words
            has_risk_words = False
            if categories_str != 'N/A' and categories_str:
                categories_lower = categories_str.lower()
                for word in risk_words:
                    if word in categories_lower:
                        has_risk_words = True
                        break
            
            # High-risk condition 2: Reputation score greater than -5
            has_bad_reputation = False
            if reputation > -5 and reputation < 0:
                has_bad_reputation = True
            
            # High-risk condition 3: Newly registered domain
            is_newly_reg = bool(is_newly_registered)
            
            # Set high risk if any condition is met
            if has_risk_words or has_bad_reputation or is_newly_reg:
                is_high_risk = True
                domain_category.append("HIGH RISK")
            
            if is_newly_registered:
                domain_category.append("Newly Registered Domain")
            if is_malicious:
                domain_category.append("Malicious")
            if malicious_count > 0:
                domain_category.append(f"Flagged by {malicious_count} vendors")
            if has_risk_words:
                domain_category.append("Contains risk categories")
            if has_bad_reputation:
                domain_category.append("Poor reputation score")
            
            domain_category_str = ', '.join(domain_category) if domain_category else 'Normal'
            
            return {
                'Domain': domain,
                'Reputation_Score': reputation,
                'Is_Malicious': is_malicious,
                'Malicious_Vendors': malicious_count,
                'Suspicious_Vendors': suspicious_count,
                'Harmless_Vendors': harmless_count,
                'Undetected_Vendors': undetected_count,
                'Total_Vendors': total_vendors,
                'Last_Scanned': last_analysis_date,
                'Tags': tags_str,
                'Categories': categories_str,
                'Domain_Category': domain_category_str,
                'Creation_Date': creation_date_str,
                'Expiration_Date': expiration_date_str,
                'Registrar': registrar,
                'Is_Newly_Registered': is_newly_registered,
                'WHOIS_Status': whois_status,
                'Query_Status': 'Success'
            }
            
        except Exception as e:
            print(f"Error parsing data for domain {domain}: {str(e)}")
            return {
                'Domain': domain,
                'Reputation_Score': 'N/A',
                'Is_Malicious': 'N/A',
                'Malicious_Vendors': 'N/A',
                'Suspicious_Vendors': 'N/A',
                'Harmless_Vendors': 'N/A',
                'Undetected_Vendors': 'N/A',
                'Total_Vendors': 'N/A',
                'Last_Scanned': 'N/A',
                'Tags': 'N/A',
                'Categories': 'N/A',
                'Domain_Category': 'N/A',
                'Creation_Date': 'N/A',
                'Expiration_Date': 'N/A',
                'Registrar': 'N/A',
                'Is_Newly_Registered': 'N/A',
                'WHOIS_Status': 'N/A',
                'Query_Status': f'Error: {str(e)}'
            }
    
    def review_domains(self, domains: List[str]) -> List[Dict]:
        """
        Review a list of domains against VirusTotal and WHOIS
        """
        results = []
        
        print(f"Starting review of {len(domains)} domains...")
        print(f"Rate limit: {self.rate_limit_delay} seconds between requests")
        
        for i, domain in enumerate(tqdm(domains, desc="Reviewing domains")):
            # Clean domain (remove whitespace and newlines)
            domain = domain.strip()
            if not domain:
                continue
                
            print(f"\nQuerying domain {i+1}/{len(domains)}: {domain}")
            
            # Get WHOIS information first
            print(f"  Getting WHOIS information...")
            whois_data = self.get_whois_info(domain)
            
            # Query VirusTotal
            print(f"  Querying VirusTotal...")
            data = self.get_domain_info(domain)
            
            if data:
                parsed_data = self.parse_domain_data(domain, data, whois_data)
                results.append(parsed_data)
                print(f"✓ Successfully queried {domain}")
                
                # Show WHOIS info
                if whois_data.get('is_newly_registered'):
                    print(f"  ⚠️  NEWLY REGISTERED DOMAIN (less than 6 months old)")
                if whois_data.get('creation_date'):
                    print(f"  📅 Creation date: {whois_data['creation_date'].strftime('%Y-%m-%d')}")
            else:
                # Add error entry with WHOIS data
                creation_date = whois_data.get('creation_date')
                creation_date_str = creation_date.strftime('%Y-%m-%d') if creation_date else 'N/A'
                
                expiration_date = whois_data.get('expiration_date')
                expiration_date_str = expiration_date.strftime('%Y-%m-%d') if expiration_date else 'N/A'
                
                registrar = whois_data.get('registrar', 'N/A')
                is_newly_registered = whois_data.get('is_newly_registered', False)
                whois_status = whois_data.get('whois_status', 'N/A')
                
                # Create domain category for failed queries
                domain_category = []
                # Still check for newly registered domains from WHOIS data
                if is_newly_registered:
                    domain_category.append("HIGH RISK")
                    domain_category.append("Newly Registered Domain")
                domain_category_str = ', '.join(domain_category) if domain_category else 'Normal'
                
                results.append({
                    'Domain': domain,
                    'Reputation_Score': 'N/A',
                    'Is_Malicious': 'N/A',
                    'Malicious_Vendors': 'N/A',
                    'Suspicious_Vendors': 'N/A',
                    'Harmless_Vendors': 'N/A',
                    'Undetected_Vendors': 'N/A',
                    'Total_Vendors': 'N/A',
                    'Last_Scanned': 'N/A',
                    'Tags': 'N/A',
                    'Categories': 'N/A',
                    'Domain_Category': domain_category_str,
                    'Creation_Date': creation_date_str,
                    'Expiration_Date': expiration_date_str,
                    'Registrar': registrar,
                    'Is_Newly_Registered': is_newly_registered,
                    'WHOIS_Status': whois_status,
                    'Query_Status': 'Failed to query VirusTotal'
                })
                print(f"✗ Failed to query {domain}")
                
                # Show WHOIS info even for failed queries
                if whois_data.get('is_newly_registered'):
                    print(f"  ⚠️  NEWLY REGISTERED DOMAIN (less than 6 months old)")
                if whois_data.get('creation_date'):
                    print(f"  📅 Creation date: {whois_data['creation_date'].strftime('%Y-%m-%d')}")
            
            # Rate limiting - wait 15 seconds between requests (except for the last one)
            if i < len(domains) - 1:
                print(f"Waiting {self.rate_limit_delay} seconds before next query...")
                time.sleep(self.rate_limit_delay)
        
        return results
    
    def save_to_excel(self, results: List[Dict], output_file: str = "domain_review_results.xlsx"):
        """
        Save results to Excel file
        """
        if not results:
            print("No results to save")
            return
        
        df = pd.DataFrame(results)
        
        # Create Excel writer with formatting
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Domain_Review_Results', index=False)
            
            # Get the workbook and worksheet
            workbook = writer.book
            worksheet = writer.sheets['Domain_Review_Results']
            
            # Auto-adjust column widths
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)  # Cap at 50 characters
                worksheet.column_dimensions[column_letter].width = adjusted_width
        
        print(f"\nResults saved to {output_file}")
        print(f"Total domains reviewed: {len(results)}")


def load_domains_from_file(filename: str) -> List[str]:
    """
    Load domains from text file
    """
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            domains = [line.strip() for line in file if line.strip()]
        return domains
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return []
    except Exception as e:
        print(f"Error reading file '{filename}': {str(e)}")
        return []


def main():
    print("=== Domain Reviewer Tool ===")
    print("Reviews domains against VirusTotal OSINT database and WHOIS")
    print()
    
    # Check for API key
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        print("Error: VIRUSTOTAL_API_KEY environment variable not set")
        print("Please set your VirusTotal API key in a .env file or environment variable")
        print("You can get a free API key from: https://www.virustotal.com/gui/join-us")
        return
    
    # Check for input file
    input_file = "blocked_domains.txt"
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found")
        print("Please create a text file named 'blocked_domains.txt' with one domain per line")
        return
    
    # Load domains
    domains = load_domains_from_file(input_file)
    if not domains:
        print("No domains found in input file")
        return
    
    print(f"Loaded {len(domains)} domains from {input_file}")
    print()
    
    # Initialize reviewer
    reviewer = VirusTotalDomainReviewer(api_key)
    
    # Review domains
    results = reviewer.review_domains(domains)
    
    # Save results
    if results:
        output_file = f"domain_review_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        reviewer.save_to_excel(results, output_file)
        
        # Print summary
        successful_queries = sum(1 for r in results if r['Query_Status'] == 'Success')
        malicious_domains = sum(1 for r in results if r.get('Is_Malicious') == True)
        newly_registered = sum(1 for r in results if r.get('Is_Newly_Registered') == True)
        
        print(f"\n=== Summary ===")
        print(f"Total domains: {len(domains)}")
        print(f"Successfully queried: {successful_queries}")
        print(f"Malicious domains found: {malicious_domains}")
        print(f"Newly registered domains: {newly_registered}")
        print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()
