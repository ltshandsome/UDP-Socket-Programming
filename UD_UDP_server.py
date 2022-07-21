#!/usr/bin/env python3

# from asyncio import subprocess
import socket
import time
import threading
import os
import datetime as dt
import argparse
import subprocess


#=================argument parsing======================
parser = argparse.ArgumentParser()
parser.add_argument("-ps", "--port_start", type=int,
                    help="port to bind, range: [start, end]", default=3280)
parser.add_argument("-pe", "--port_end", type=int,
                    help="port to bind, range: [start, end]", default=3287)
parser.add_argument("-n", "--number_client", type=int,
                    help="number of client", default=1)
parser.add_argument("-l", "--length", type=int,
                    help="payload length", default=250)
parser.add_argument("-b", "--bandwidth", type=int,
                    help="data rate (bits per second)", default=200000)   
parser.add_argument("-t", "--time", type=int,
                    help="maximum experiment time", default=3600)                                   
                  
args = parser.parse_args()

PORTS = [i for i in range(args.port_start, args.port_end+1)]
length_packet = args.length
bandwidth = args.bandwidth
total_time = args.time

expected_packet_per_sec = bandwidth / (length_packet << 3)
sleeptime = 1.0 / expected_packet_per_sec
#========================================================

#=================global variables=======================
thread_stop = True
exit_main_process = False
udp_addr = {}
#========================================================

#=================other variables========================
HOST = '192.168.1.181'
CONTROL_PORT = 3299
pcap_path = "pcapdir"
#========================================================

def connection_setup():
    print("Initial setting up...")
    
    s_udp_list = []
    conn_list = []
    
    #--------------establish sockets for UDP data traffic----- 
    for PORT in PORTS:
        s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_udp.bind((HOST, PORT))
        s_udp_list.append(s_udp)
    
    #--------------establish TCP control flows----------------
    s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    
    s_tcp.bind((HOST, CONTROL_PORT))   

    print(PORTS, "wait for tcp connection...")
    s_tcp.listen(len(PORTS))
    
    for i in range(len(PORTS)):
        conn, tcp_addr = s_tcp.accept()
        print('tcp Connected by', tcp_addr)
        conn_list.append(conn)

    return s_tcp, s_udp_list, conn_list

def transmission(s_udp_list):
    global thread_stop
    global udp_addr
    print("start transmission: ")
    
    seq = 1
    prev_transmit = 0
    
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
        
        redundant = os.urandom(length_packet-4*3)
        outdata = datetimedec.to_bytes(4, 'big') + microsec.to_bytes(4, 'big') + seq.to_bytes(4, 'big') + redundant
        
        for s_udp in s_udp_list:
            if s_udp in udp_addr.keys():
                s_udp.sendto(outdata, udp_addr[s_udp])
        seq += 1
        
        if time.time()-start_time > time_slot:
            print("[%d-%d]"%(time_slot-1, time_slot), "transmit", seq-prev_transmit)
            time_slot += 1
            prev_transmit = seq
            
    
    print("---transmission timeout---")
    print("transmit", seq, "packets")


def receive(s_udp):
    s_udp.settimeout(3)
    print("wait for indata...")
    number_of_received_packets = 0
    
    seq = 1
    max_seq = 1

    global thread_stop
    global udp_addr
    while not thread_stop:
        try:
            #receive data, update client's addresses (after receiving, server know where to transmit)
            indata, addr = s_udp.recvfrom(1024)
            udp_addr[s_udp] = addr                     
            
            if len(indata) != length_packet:
                print("packet with strange length: ", len(indata))
            seq = int(indata.hex()[16:24], 16)
            max_seq = max(max_seq, seq)
            
            ts = int(int(indata.hex()[0:8], 16)) + float("0." + str(int(indata.hex()[8:16], 16)))
            
            number_of_received_packets += 1
            
        except Exception as inst:
            print("Error: ", inst)
            thread_stop = True
    thread_stop = True
    
    print("---Experiment Complete---")
    print("Total capture: ", number_of_received_packets, "Total lose: ", max_seq - number_of_received_packets)
    print("STOP bypass")

while not exit_main_process:
    if not os.path.exists(pcap_path):
        os.system("mkdir %s"%(pcap_path))


    now = dt.datetime.today()
    n = '-'.join([str(x) for x in[ now.year, now.month, now.day, now.hour, now.minute, now.second]])
    
    #Create subprocesses to capture packets (TCPDUMP)
    tcpproc_list = []
    for PORT in PORTS:
        tcpproc =  subprocess.Popen(["sudo tcpdump -i any port %s -w %s/%s_%s.pcap"%(PORT, pcap_path,PORT, n)], shell=True, preexec_fn = os.setpgrp)
        tcpproc_list.append(tcpproc)
        
    time.sleep(1)
    
    receiving_threads = []
    udp_addr = {}

    try:
        s_tcp, s_udp_list, conn_list = connection_setup()
        
        while thread_stop == True:
            control_message = input("Enter START to start: ")
            if control_message == "START":
                thread_stop = False
                
                for conn in conn_list:
                    conn.sendall("START".encode())
                t = threading.Thread(target = transmission, args = (s_udp_list, ))
                t.start()
                for s_udp in s_udp_list:
                    t1 = threading.Thread(target = receive, args = (s_udp,))
                    t1.start()
                    receiving_threads.append(t1)
        
    except KeyboardInterrupt as inst:
        print("keyboard interrupt: ")
        #Kill TCPDUMP subprocesses
        for tcpproc in tcpproc_list:
            pgid = os.getpgid(tcpproc.pid)
    
            command = "sudo kill -9 -{}".format(pgid)
            subprocess.check_output(command.split(" "))
        exit()
    except Exception as e:
        print("Connection Error:", e)
        exit()
    

    try:
        while t.is_alive():
            control_message = input("Enter STOP to stop: ")
            if control_message == "STOP":
                thread_stop = True
                for conn in conn_list:
                    conn.sendall("STOP".encode())
                break
            elif control_message == "EXIT":
                thread_stop = True
                exit_main_process = True
                for conn in conn_list:
                    conn.sendall("EXIT".encode())
                break    
    except Exception as e:
        print(e)
        exit_main_progress = True
    finally:
        print("finally")
        
        thread_stop = True
        
        #end transmission and receive threads
        t.join()
        for t1 in receiving_threads:
            t1.join()
        
        #close sockets
        s_tcp.close()
        for s_udp in s_udp_list:
            s_udp.close()
            
        #Kill TCPDUMP subprocesses
        for tcpproc in tcpproc_list:
            pgid = os.getpgid(tcpproc.pid)
    
            command = "sudo kill -9 -{}".format(pgid)
            subprocess.check_output(command.split(" "))
