import pyshark
import json
import csv
from datetime import datetime
from collections import Counter
import os

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class AdvancedPacketAnalyzer:
    def __init__(self):
        self.packets_data = []
        self.output_file = "captured_packets"
        self.interfaces = []
        self.selected_interface = None
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}
        /\\_/\\  
       ( o.o ) 
        > ^ <    {Colors.BOLD}{Colors.YELLOW}Advanced Network Packet Analyzer{Colors.ENDC}{Colors.CYAN}
       /|   |\\   {Colors.GREEN}Professional Network Analysis Tool{Colors.ENDC}{Colors.CYAN}
      (_|   |_)  
                 {Colors.BLUE}Topics in Cyber Security Programming{Colors.ENDC}{Colors.CYAN}
                 {Colors.MAGENTA}Version 2.0 - Cat Edition 🐱{Colors.ENDC}{Colors.CYAN}

{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}
        """
        print(banner)
    
    def get_available_interfaces(self):
        print(f"\n{Colors.YELLOW}[*] Detecting available network interfaces...{Colors.ENDC}")
        try:
            capture = pyshark.LiveCapture()
            self.interfaces = capture.interfaces
            
            if not self.interfaces:
                print(f"{Colors.RED}[!] No interfaces found. Using default interfaces.{Colors.ENDC}")
                self.interfaces = ['eth0', 'wlan0', 'lo']
            
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Error detecting interfaces: {e}{Colors.ENDC}")
            self.interfaces = ['eth0', 'wlan0', 'lo']
            return False
    
    def select_interface(self):
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}Available Network Interfaces:{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        
        for idx, iface in enumerate(self.interfaces, 1):
            print(f"{Colors.GREEN}{idx}.{Colors.ENDC} {iface}")
        
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        
        while True:
            try:
                choice = input(f"\n{Colors.YELLOW}Select interface number (1-{len(self.interfaces)}): {Colors.ENDC}")
                choice_num = int(choice)
                
                if 1 <= choice_num <= len(self.interfaces):
                    self.selected_interface = self.interfaces[choice_num - 1]
                    print(f"{Colors.GREEN}[✓] Selected interface: {self.selected_interface}{Colors.ENDC}")
                    return self.selected_interface
                else:
                    print(f"{Colors.RED}[!] Invalid choice. Please try again.{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.RED}[!] Please enter a valid number.{Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n{Colors.RED}[!] Operation cancelled.{Colors.ENDC}")
                return None
    
    def get_filter_choice(self):
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}Packet Filter Options:{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.GREEN}1.{Colors.ENDC} TCP     - Transmission Control Protocol")
        print(f"{Colors.GREEN}2.{Colors.ENDC} UDP     - User Datagram Protocol")
        print(f"{Colors.GREEN}3.{Colors.ENDC} ICMP    - Internet Control Message Protocol")
        print(f"{Colors.GREEN}4.{Colors.ENDC} HTTP    - Hypertext Transfer Protocol")
        print(f"{Colors.GREEN}5.{Colors.ENDC} HTTPS   - HTTP Secure (port 443)")
        print(f"{Colors.GREEN}6.{Colors.ENDC} DNS     - Domain Name System (port 53)")
        print(f"{Colors.GREEN}7.{Colors.ENDC} All     - Capture all packets (no filter)")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        
        filters = {
            '1': 'tcp',
            '2': 'udp',
            '3': 'icmp',
            '4': 'tcp port 80',
            '5': 'tcp port 443',
            '6': 'udp port 53',
            '7': None
        }
        
        choice = input(f"\n{Colors.YELLOW}Enter your choice (1-7): {Colors.ENDC}")
        selected_filter = filters.get(choice, None)
        
        if choice in filters:
            filter_name = {
                '1': 'TCP', '2': 'UDP', '3': 'ICMP', 
                '4': 'HTTP', '5': 'HTTPS', '6': 'DNS', '7': 'All packets'
            }[choice]
            print(f"{Colors.GREEN}[✓] Filter selected: {filter_name}{Colors.ENDC}")
        
        return selected_filter
    
    def get_packet_count(self):
        print(f"\n{Colors.CYAN}{'='*70}{Colors.ENDC}")
        default_count = 50
        
        try:
            count_input = input(f"{Colors.YELLOW}Enter number of packets to capture (default: {default_count}): {Colors.ENDC}")
            if count_input.strip() == "":
                return default_count
            
            count = int(count_input)
            if count <= 0:
                print(f"{Colors.RED}[!] Invalid count. Using default: {default_count}{Colors.ENDC}")
                return default_count
            
            print(f"{Colors.GREEN}[✓] Will capture {count} packets{Colors.ENDC}")
            return count
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input. Using default: {default_count}{Colors.ENDC}")
            return default_count
    
    def capture_packets(self, packet_filter=None, count=50):
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}Starting Packet Capture{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Interface: {self.selected_interface}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Filter: {packet_filter if packet_filter else 'None (All packets)'}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Target: {count} packets{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] Capturing... (Press Ctrl+C to stop early){Colors.ENDC}\n")
        
        try:
            if packet_filter:
                capture = pyshark.LiveCapture(interface=self.selected_interface, bpf_filter=packet_filter)
            else:
                capture = pyshark.LiveCapture(interface=self.selected_interface)
            
            packet_count = 0
            
            cat_frames = [
                "=^._.^= ∫",
                "=^._.^= ∫",
                "=^o.o^= ∫",
                "=^._.^= ∫"
            ]
            
            for packet in capture.sniff_continuously():
                if packet_count >= count:
                    break
                
                try:
                    packet_info = self.extract_packet_info(packet, packet_count + 1)
                    if packet_info:
                        self.packets_data.append(packet_info)
                        packet_count += 1
                        
                        percentage = (packet_count / count) * 100
                        filled = int(percentage / 5)
                        bar = '🐱' * filled + '·' * (20 - filled)
                        
                        cat_animation = cat_frames[packet_count % len(cat_frames)]
                        
                        print(f"\r{Colors.YELLOW}{cat_animation}{Colors.ENDC} [{bar}] {Colors.GREEN}{packet_count}/{count}{Colors.ENDC} ({percentage:.1f}%)", end='', flush=True)
                except Exception as e:
                    continue
            
            print()
            
            print(f"\n{Colors.GREEN}{'='*70}")
            print(f"[✓] Successfully captured {len(self.packets_data)} packets")
            print(f"{'='*70}{Colors.ENDC}")
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Capture stopped by user{Colors.ENDC}")
            print(f"{Colors.GREEN}[✓] Captured {len(self.packets_data)} packets before stopping{Colors.ENDC}")
            return len(self.packets_data) > 0
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error during capture: {e}{Colors.ENDC}")
            print(f"{Colors.YELLOW}[!] Tip: Make sure you're running with sudo/administrator privileges{Colors.ENDC}")
            return False
    
    def extract_packet_info(self, packet, seq_num):
        info = {
            'seq': seq_num,
            'timestamp': str(datetime.now()),
            'protocol': 'UNKNOWN',
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'src_mac': 'N/A',
            'dst_mac': 'N/A',
            'length': 'N/A',
            'info': 'N/A',
            'full_details': str(packet)
        }
        
        if hasattr(packet, 'eth'):
            info['src_mac'] = packet.eth.src if hasattr(packet.eth, 'src') else 'N/A'
            info['dst_mac'] = packet.eth.dst if hasattr(packet.eth, 'dst') else 'N/A'
        
        if hasattr(packet, 'ip'):
            info['src_ip'] = packet.ip.src if hasattr(packet.ip, 'src') else 'N/A'
            info['dst_ip'] = packet.ip.dst if hasattr(packet.ip, 'dst') else 'N/A'
            info['length'] = packet.ip.len if hasattr(packet.ip, 'len') else 'N/A'
        
        if hasattr(packet, 'tcp'):
            info['protocol'] = 'TCP'
            info['src_port'] = packet.tcp.srcport if hasattr(packet.tcp, 'srcport') else 'N/A'
            info['dst_port'] = packet.tcp.dstport if hasattr(packet.tcp, 'dstport') else 'N/A'
            if hasattr(packet.tcp, 'flags'):
                info['info'] = f"Flags: {packet.tcp.flags}"
        elif hasattr(packet, 'udp'):
            info['protocol'] = 'UDP'
            info['src_port'] = packet.udp.srcport if hasattr(packet.udp, 'srcport') else 'N/A'
            info['dst_port'] = packet.udp.dstport if hasattr(packet.udp, 'dstport') else 'N/A'
        elif hasattr(packet, 'icmp'):
            info['protocol'] = 'ICMP'
            if hasattr(packet.icmp, 'type'):
                info['info'] = f"Type: {packet.icmp.type}"
        
        return info
    
    def print_packets_table(self):
        print(f"\n{Colors.CYAN}{'='*150}")
        print(f"{Colors.BOLD}CAPTURED PACKETS TABLE{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*150}{Colors.ENDC}")
        
        header = f"{Colors.YELLOW}{'SEQ':<6} {'Source IP':<16} {'Port':<7} {'Source MAC':<18} {'Dest IP':<16} {'Port':<7} {'Dest MAC':<18} {'Proto':<8} {'Info':<20}{Colors.ENDC}"
        print(header)
        print(f"{Colors.CYAN}{'-'*150}{Colors.ENDC}")
        
        for packet in self.packets_data:
            proto_color = Colors.GREEN if packet['protocol'] == 'TCP' else Colors.BLUE if packet['protocol'] == 'UDP' else Colors.YELLOW
            row = f"{packet['seq']:<6} {packet['src_ip']:<16} {packet['src_port']:<7} {packet['src_mac']:<18} {packet['dst_ip']:<16} {packet['dst_port']:<7} {packet['dst_mac']:<18} {proto_color}{packet['protocol']:<8}{Colors.ENDC} {packet['info'][:20]:<20}"
            print(row)
        
        print(f"{Colors.CYAN}{'='*150}{Colors.ENDC}")
    
    def print_statistics(self):
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}CAPTURE STATISTICS{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        
        protocols = [p['protocol'] for p in self.packets_data]
        protocol_count = Counter(protocols)
        
        print(f"\n{Colors.YELLOW}Protocol Distribution:{Colors.ENDC}")
        for proto, count in protocol_count.most_common():
            percentage = (count / len(self.packets_data)) * 100
            print(f"  {Colors.GREEN}{proto:<10}{Colors.ENDC}: {count:>4} packets ({percentage:>5.1f}%)")
        
        src_ips = [p['src_ip'] for p in self.packets_data if p['src_ip'] != 'N/A']
        if src_ips:
            src_ip_count = Counter(src_ips)
            print(f"\n{Colors.YELLOW}Top 5 Source IPs:{Colors.ENDC}")
            for ip, count in src_ip_count.most_common(5):
                print(f"  {Colors.GREEN}{ip:<16}{Colors.ENDC}: {count:>4} packets")
        
        dst_ips = [p['dst_ip'] for p in self.packets_data if p['dst_ip'] != 'N/A']
        if dst_ips:
            dst_ip_count = Counter(dst_ips)
            print(f"\n{Colors.YELLOW}Top 5 Destination IPs:{Colors.ENDC}")
            for ip, count in dst_ip_count.most_common(5):
                print(f"  {Colors.GREEN}{ip:<16}{Colors.ENDC}: {count:>4} packets")
        
        print(f"\n{Colors.CYAN}Total Packets: {Colors.BOLD}{len(self.packets_data)}{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    
    def save_packets(self):
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}Save Captured Data{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.GREEN}1.{Colors.ENDC} JSON format (.json)")
        print(f"{Colors.GREEN}2.{Colors.ENDC} CSV format (.csv)")
        print(f"{Colors.GREEN}3.{Colors.ENDC} Text format (.txt)")
        print(f"{Colors.GREEN}4.{Colors.ENDC} All formats")
        print(f"{Colors.GREEN}5.{Colors.ENDC} Skip saving")
        
        choice = input(f"\n{Colors.YELLOW}Select format (1-5): {Colors.ENDC}")
        
        formats = {
            '1': ['json'],
            '2': ['csv'],
            '3': ['txt'],
            '4': ['json', 'csv', 'txt'],
            '5': []
        }
        
        selected_formats = formats.get(choice, ['json'])
        
        for fmt in selected_formats:
            if fmt == 'json':
                self._save_json()
            elif fmt == 'csv':
                self._save_csv()
            elif fmt == 'txt':
                self._save_txt()
    
    def _save_json(self):
        filename = f"{self.output_file}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.packets_data, f, indent=4, ensure_ascii=False)
        print(f"{Colors.GREEN}[✓] Saved to: {filename}{Colors.ENDC}")
    
    def _save_csv(self):
        filename = f"{self.output_file}.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            if self.packets_data:
                writer = csv.DictWriter(f, fieldnames=['seq', 'timestamp', 'protocol', 'src_ip', 'src_port', 'src_mac', 'dst_ip', 'dst_port', 'dst_mac', 'length', 'info'])
                writer.writeheader()
                for packet in self.packets_data:
                    row = {k: packet[k] for k in ['seq', 'timestamp', 'protocol', 'src_ip', 'src_port', 'src_mac', 'dst_ip', 'dst_port', 'dst_mac', 'length', 'info']}
                    writer.writerow(row)
        print(f"{Colors.GREEN}[✓] Saved to: {filename}{Colors.ENDC}")
    
    def _save_txt(self):
        filename = f"{self.output_file}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*150 + "\n")
            f.write("CAPTURED PACKETS REPORT\n")
            f.write("="*150 + "\n\n")
            
            for packet in self.packets_data:
                f.write(f"Packet #{packet['seq']}\n")
                f.write(f"  Timestamp: {packet['timestamp']}\n")
                f.write(f"  Protocol: {packet['protocol']}\n")
                f.write(f"  Source: {packet['src_ip']}:{packet['src_port']} ({packet['src_mac']})\n")
                f.write(f"  Destination: {packet['dst_ip']}:{packet['dst_port']} ({packet['dst_mac']})\n")
                f.write(f"  Info: {packet['info']}\n")
                f.write("-"*150 + "\n\n")
        print(f"{Colors.GREEN}[✓] Saved to: {filename}{Colors.ENDC}")
    
    def show_packet_details(self):
        while True:
            print(f"\n{Colors.CYAN}{'='*70}{Colors.ENDC}")
            user_input = input(f"{Colors.YELLOW}Enter packet number (1-{len(self.packets_data)}) or 'q' to quit: {Colors.ENDC}")
            
            if user_input.lower() == 'q':
                print(f"\n{Colors.GREEN}[*] Returning to main menu...{Colors.ENDC}")
                break
            
            try:
                seq_num = int(user_input)
                
                packet = None
                for p in self.packets_data:
                    if p['seq'] == seq_num:
                        packet = p
                        break
                
                if packet:
                    print(f"\n{Colors.CYAN}{'='*80}")
                    print(f"{Colors.BOLD}PACKET #{seq_num} DETAILED INFORMATION{Colors.ENDC}")
                    print(f"{Colors.CYAN}{'='*80}{Colors.ENDC}")
                    print(f"{Colors.YELLOW}Timestamp:{Colors.ENDC}        {packet['timestamp']}")
                    print(f"{Colors.YELLOW}Protocol:{Colors.ENDC}         {packet['protocol']}")
                    print(f"{Colors.YELLOW}Source IP:{Colors.ENDC}        {packet['src_ip']}")
                    print(f"{Colors.YELLOW}Source Port:{Colors.ENDC}      {packet['src_port']}")
                    print(f"{Colors.YELLOW}Source MAC:{Colors.ENDC}       {packet['src_mac']}")
                    print(f"{Colors.YELLOW}Destination IP:{Colors.ENDC}   {packet['dst_ip']}")
                    print(f"{Colors.YELLOW}Destination Port:{Colors.ENDC} {packet['dst_port']}")
                    print(f"{Colors.YELLOW}Destination MAC:{Colors.ENDC}  {packet['dst_mac']}")
                    print(f"{Colors.YELLOW}Packet Length:{Colors.ENDC}    {packet['length']}")
                    print(f"{Colors.YELLOW}Additional Info:{Colors.ENDC}  {packet['info']}")
                    print(f"\n{Colors.CYAN}--- Full Packet Details ---{Colors.ENDC}")
                    print(packet['full_details'][:1000])
                    if len(packet['full_details']) > 1000:
                        print(f"\n{Colors.YELLOW}[...output truncated...]{Colors.ENDC}")
                    print(f"{Colors.CYAN}{'='*80}{Colors.ENDC}")
                else:
                    print(f"\n{Colors.RED}[!] Packet #{seq_num} not found!{Colors.ENDC}")
                    print(f"{Colors.YELLOW}[!] Valid range: 1-{len(self.packets_data)}{Colors.ENDC}")
            
            except ValueError:
                print(f"\n{Colors.RED}[!] Please enter a valid number!{Colors.ENDC}")
            except Exception as e:
                print(f"\n{Colors.RED}[!] Error: {e}{Colors.ENDC}")
    
    def search_packets(self):
        print(f"\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}Search Packets{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.GREEN}1.{Colors.ENDC} Search by Source IP")
        print(f"{Colors.GREEN}2.{Colors.ENDC} Search by Destination IP")
        print(f"{Colors.GREEN}3.{Colors.ENDC} Search by Protocol")
        print(f"{Colors.GREEN}4.{Colors.ENDC} Search by Port")
        print(f"{Colors.GREEN}5.{Colors.ENDC} Back to menu")
        
        choice = input(f"\n{Colors.YELLOW}Enter choice (1-5): {Colors.ENDC}")
        
        if choice == '1':
            search_term = input(f"{Colors.YELLOW}Enter Source IP: {Colors.ENDC}")
            results = [p for p in self.packets_data if search_term in p['src_ip']]
        elif choice == '2':
            search_term = input(f"{Colors.YELLOW}Enter Destination IP: {Colors.ENDC}")
            results = [p for p in self.packets_data if search_term in p['dst_ip']]
        elif choice == '3':
            search_term = input(f"{Colors.YELLOW}Enter Protocol (TCP/UDP/ICMP): {Colors.ENDC}").upper()
            results = [p for p in self.packets_data if search_term in p['protocol']]
        elif choice == '4':
            search_term = input(f"{Colors.YELLOW}Enter Port number: {Colors.ENDC}")
            results = [p for p in self.packets_data if search_term in str(p['src_port']) or search_term in str(p['dst_port'])]
        else:
            return
        
        if results:
            print(f"\n{Colors.GREEN}[✓] Found {len(results)} matching packets:{Colors.ENDC}\n")
            for packet in results:
                print(f"{Colors.CYAN}#{packet['seq']}{Colors.ENDC} - {packet['protocol']} | {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}")
        else:
            print(f"\n{Colors.RED}[!] No packets found matching your search.{Colors.ENDC}")
    
    def main_menu(self):
        while True:
            print(f"\n{Colors.CYAN}{'='*70}")
            print(f"{Colors.BOLD}Main Menu{Colors.ENDC}")
            print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
            print(f"{Colors.GREEN}1.{Colors.ENDC} View packets table")
            print(f"{Colors.GREEN}2.{Colors.ENDC} View packet details")
            print(f"{Colors.GREEN}3.{Colors.ENDC} View statistics")
            print(f"{Colors.GREEN}4.{Colors.ENDC} Search packets")
            print(f"{Colors.GREEN}5.{Colors.ENDC} Save packets")
            print(f"{Colors.GREEN}6.{Colors.ENDC} Exit")
            
            choice = input(f"\n{Colors.YELLOW}Enter choice (1-6): {Colors.ENDC}")
            
            if choice == '1':
                self.print_packets_table()
            elif choice == '2':
                self.show_packet_details()
            elif choice == '3':
                self.print_statistics()
            elif choice == '4':
                self.search_packets()
            elif choice == '5':
                self.save_packets()
            elif choice == '6':
                print(f"\n{Colors.GREEN}[*] Thank you for using Advanced Packet Analyzer!{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Exiting...{Colors.ENDC}\n")
                break
            else:
                print(f"{Colors.RED}[!] Invalid choice. Please try again.{Colors.ENDC}")
    
    def run(self):
        self.print_banner()
        
        self.get_available_interfaces()
        
        if not self.select_interface():
            print(f"{Colors.RED}[!] No interface selected. Exiting.{Colors.ENDC}")
            return
        
        packet_filter = self.get_filter_choice()
        
        count = self.get_packet_count()
        
        if not self.capture_packets(packet_filter=packet_filter, count=count):
            print(f"{Colors.RED}[!] Capture failed or no packets captured.{Colors.ENDC}")
            return
        
        self._save_json()
        
        self.print_statistics()
        
        self.main_menu()

if __name__ == "__main__":
    try:
        analyzer = AdvancedPacketAnalyzer()
        analyzer.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Program interrupted by user{Colors.ENDC}")
        print(f"{Colors.GREEN}[*] Goodbye!{Colors.ENDC}\n")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal Error: {e}{Colors.ENDC}")
        print(f"{Colors.YELLOW}[!] Make sure:")
        print(f"  - pyshark is installed: pip install pyshark")
        print(f"  - Wireshark/tshark is installed")
        print(f"  - You're running as root/administrator{Colors.ENDC}\n")
