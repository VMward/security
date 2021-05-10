from src.mitm import get_args, sniffer


interface = get_args()
sniffer(interface)