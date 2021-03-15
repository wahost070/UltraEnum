import sys
import argparse

"""
TODO:
    - Add method to load/buffer Ultra_ENUM.md in the program
    - Read specific section in md file
    - Return the data as a dictionary for each port
    - Parse dictionary and display nicely (e.g with more) 
    
"""


class UltraEnumTool:

    def load_ultra_enum(self, mode):
        # IF ONLINE:
        
        # IF OFFLINE:
        data = None
        with open('..\\NetworkEnum\\ULTRA_ENUM.md', 'r', encoding="utf8") as file:
            for line in file:
                print(line)
        file.close()
        
        return data

    def get_info_for_ports(self, ports_list):
        data = {}
        print(self.ultra_enum_doc)
        
        for i, v in enumerate(ports_list):
            # here we get the data for each port
            p = f"{i}"
            
            data[int(v)] = p
        
        return data
    
    def main(self):
        print(f"Mode: {self.args.mode}")
        print(f"Ports: {self.args.port}")
        
        data = self.get_info_for_ports(self.args.port.split(','))
        # here we need to prettify the dictionary
        print(data)

    def __init__(self, argv):
        parser = argparse.ArgumentParser(description='Get enumeration info for specified ports')
        parser.add_argument('mode', help='offline or online')
        parser.add_argument('-port', help='22,80,443 (comma seperated)')
                                                                                                
        self.args = parser.parse_args()
        self.ultra_enum_doc = self.load_ultra_enum(self.args.mode)
        

if __name__ == '__main__':

    if sys.version_info < (3, 0):
        print("Requires python 3.x")
        exit(0)
        
    tool = UltraEnumTool(sys.argv)
    tool.main()
    exit(1)
