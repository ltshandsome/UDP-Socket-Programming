#!/usr/bin/env python3

# from asyncio import subprocess
import socket
import time
import threading
import os
import datetime as dt
import argparse
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", type=int,
                    help="port to bind", default=3437)
parser.add_argument("-l", "--length", type=int,
                    help="payload length", default=250)
parser.add_argument("-b", "--bandwidth", type=int,
                    help="data rate (bits per second)", default=200000)   
parser.add_argument("-t", "--time", type=int,
                    help="maximum experiment time", default=3600)                                   
                  
args = parser.parse_args()

HOST = '192.168.1.7'
PORT = args.port
length_packet = args.length
bandwidth = args.bandwidth
total_time = args.time

thread_stop = False

expected_packet_per_sec = bandwidth / (length_packet << 3)
sleeptime = 1.0 / expected_packet_per_sec

pcap_path = "pcapdir"

def connection_setup():
    print("Initial setting up...")
    
    s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_udp.bind((HOST, PORT))
    
    s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    s_tcp.bind((HOST, PORT))   

    print(str(PORT), "wait for tcp connection...")
    s_tcp.listen(1)
    conn, tcp_addr = s_tcp.accept()
    print(str(PORT), 'tcp Connected by', tcp_addr)

    conn.sendall(b"received TCP packet from server")
    
    indata = conn.recv(65535)
    if indata == b'received TCP packet from client':
        print("received TCP packet from client")
    else:
        print("Error: received TCP packet from client")
        

    return s_tcp, s_udp, tcp_addr

def transmision(s_udp, client_addr):
    global thread_stop
    print("start transmision to addr", s_udp)
    
    seq = 1
    prev_transmit = 0
    
    ok = (1).to_bytes(1, 'big')
    
    start_time = time.time()
    next_transmit_time = start_time + sleeptime
    
    time_slot = 1
    
    while time.time() - start_time < total_time and not thread_stop:
    
        t = time.time()
        while t < next_transmit_time:
            t = time.time()
        next_transmit_time = next_transmit_time + sleeptime
        
        datetimedec = int(t)
        microsec = int((t - int(t))*1000000)
        
        redundent = os.urandom(250-4*3-1)
        outdata = datetimedec.to_bytes(4, 'big') + microsec.to_bytes(4, 'big') + seq.to_bytes(4, 'big') + ok + redundent
        
        s_udp.sendto(outdata, client_addr)
        seq += 1
        
        if time.time()-start_time > time_slot:
            print("[%d-%d]"%(time_slot-1, time_slot), "transmit", seq-prev_transmit)
            time_slot += 1
            prev_transmit = seq
            
    
    print("---transmision timeout---")
    print("transmit", seq, "packets")


def receive(s_udp):
    s_udp.settimeout(3)
    print("wait for indata...")
    number_of_received_packets = 0
    
    seq = 1

    global thread_stop
    while not thread_stop:
        try:
            indata, addr = s_udp.recvfrom(1024)
            if len(indata) != 250:
                print("packet with strange length: ", len(indata))
                
            seq = int(indata.hex()[16:24], 16)
            ts = int(int(indata.hex()[0:8], 16)) + float("0." + str(int(indata.hex()[8:16], 16)))
            
            ok = int(indata.hex()[24:25], 16)
            
            number_of_received_packets += 1
            
        except Exception as inst:
            print("Error: ", inst)
            thread_stop = True
    thread_stop = True
    
    print("---Experiment Complete---")
    print("Total capture: ", number_of_received_packets, "Total lose: ", seq - number_of_received_packets)
    print("STOP bypass")


if not os.path.exists(pcap_path):
    os.system("mkdir %s"%(pcap_path))


now = dt.datetime.today()
n = '-'.join([str(x) for x in[ now.year, now.month, now.day, now.hour, now.minute, now.second]])

tcpproc =  subprocess.Popen(["tcpdump -i any port %s -w %s/%s_%s.pcap&"%(PORT, pcap_path,PORT, n)], shell=True)
time.sleep(1)

try:
    s_tcp, s_udp, client_addr = connection_setup()
except Exception as inst:
    print("Connection Error:", inst)
    exit()
thread_stop = False
t = threading.Thread(target = transmision, args = (s_udp, client_addr, ))
t1 = threading.Thread(target = receive, args = (s_udp,))


t.start()
t1.start()

try:
    while t.is_alive():
        control_message = input("Enter STOP to stop: ")
        if control_message == "STOP":
            thread_stop = True
            s_tcp.sendall("STOP".encode())
            break
    thread_stop = True
    t.join()
    t1.join()
    s_tcp.close()
    s_udp.close()
except Exception as e:
    print(e)
finally:
    tcpproc.terminate()
