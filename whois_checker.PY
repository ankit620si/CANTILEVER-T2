import whois
import csv
import re
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def validate_domain(domain):
    # Basic regex for domain validation (e.g., example.com or example.co.uk)
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\." \
              r"[A-Za-z]{2,6}(\.[A-Za-z]{2,6})?$"
    return re.match(pattern, domain)

def fetch_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        # Check if domain_name field exists and is valid
        if domain_info.domain_name:
            return domain_info
        else:
            return None
    except Exception:
        return None

def format_date(date):
    if isinstance(date, list):
        return str(date[0])
    return str(date)

def display_results_table(results):
    headers = ["Domain", "Registrar", "Creation Date", "Expiration Date", "Name Servers"]
    table = []
    for res in results:
        table.append([
            res['domain'],
            res['registrar'] or "N/A",
            format_date(res['creation_date']),
            format_date(res['expiration_date']),
            ", ".join(res['name_servers']) if res['name_servers'] else "N/A"
        ])
    print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

def save_results(results, filename, filetype="csv"):
    try:
        if filetype == "csv":
            with open(filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file, quoting=csv.QUOTE_ALL)  # Quote all fields for CSV clarity
                # Write header
                writer.writerow(["Domain", "Registrar", "Creation Date", "Expiration Date", "Name Servers"])
                # Write rows
                for res in results:
                    writer.writerow([
                        res['domain'],
                        res['registrar'] or "N/A",
                        format_date(res['creation_date']),
                        format_date(res['expiration_date']),
                        ", ".join(res['name_servers']) if res['name_servers'] else "N/A"
                    ])
        elif filetype == "txt":
            with open(filename, mode='w', encoding='utf-8') as file:
                for res in results:
                    file.write(f"Domain: {res['domain']}\n")
                    file.write(f"Registrar: {res['registrar'] or 'N/A'}\n")
                    file.write(f"Creation Date: {format_date(res['creation_date'])}\n")
                    file.write(f"Expiration Date: {format_date(res['expiration_date'])}\n")
                    file.write(f"Name Servers: {', '.join(res['name_servers']) if res['name_servers'] else 'N/A'}\n")
                    file.write("-" * 40 + "\n")
        print(Fore.GREEN + f"\n✅ Results saved successfully to '{filename}'\n")
    except Exception as e:
        print(Fore.RED + f"\n❌ Failed to save results: {e}")

def main():
    print(Fore.CYAN + "🌐 WHOIS DOMAIN INFO CHECKER (Enhanced Interactive Edition)")
    print("Enter multiple domain names separated by commas (e.g., google.com, openai.com)")
    print("Type 'exit' to quit.\n")

    results = []

    while True:
        user_input = input(Fore.YELLOW + "Enter domain(s): ").strip()
        if user_input.lower() == 'exit':
            print(Fore.CYAN + "👋 Exiting. Thanks for using the WHOIS checker!")
            break
        
        domains = [d.strip().lower() for d in user_input.split(",") if d.strip()]
        if not domains:
            print(Fore.RED + "⚠️ No domains entered, try again.\n")
            continue
        
        for domain in domains:
            if not validate_domain(domain):
                print(Fore.RED + f"❌ Invalid domain format: {domain}")
                continue
            
            print(Fore.BLUE + f"\n🔎 Fetching WHOIS info for: {domain} ...")
            info = fetch_whois_info(domain)
            if info:
                domain_data = {
                    "domain": domain,
                    "registrar": info.registrar,
                    "creation_date": info.creation_date,
                    "expiration_date": info.expiration_date,
                    "name_servers": info.name_servers
                }
                results.append(domain_data)
                print(Fore.GREEN + f"✅ WHOIS info retrieved for {domain}")
            else:
                print(Fore.RED + f"⚠️ No WHOIS info found or domain protected: {domain}")

        if results:
            print("\n" + Fore.MAGENTA + "Summary of fetched domain info:")
            display_results_table(results)

            while True:
                save_choice = input(Fore.YELLOW + "Do you want to save results? (csv/txt/no): ").strip().lower()
                if save_choice == 'csv':
                    save_results(results, "domain_info.csv", "csv")
                    break
                elif save_choice == 'txt':
                    save_results(results, "domain_info.txt", "txt")
                    break
                elif save_choice == 'no':
                    print("Results not saved.")
                    break
                else:
                    print("Please type 'csv', 'txt', or 'no'.")

        results.clear()
        print("\n" + "-"*50 + "\n")

if __name__ == "__main__":
    main()
