import argparse

parser = argparse.ArgumentParser()
group1 = parser.add_mutually_exclusive_group()
group2 = parser.add_mutually_exclusive_group()
group1.add_argument("-n", "--use_nautobot", help="Use Nautobot for inventory", action="store_true")
group1.add_argument("-i", "--inventory_file", help="Inventory filename")
group2.add_argument("-s", "--site_list", help="Comma separated list of Nautobot Sites for selection of devices")
group2.add_argument("-r", "--region_list", help="Comma separated list of Nautobot Regions for selection of devices")
group2.add_argument("-d", "--device_list", help="Comma separated list of Nautobot Devices")

args = parser.parse_args()

device_list = [line.strip() for line in args.device_list.split(",")]

print(device_list)