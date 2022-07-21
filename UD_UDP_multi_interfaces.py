#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import threading
import datetime as dt
import sys
import os
import argparse
import subprocess

#====================argument parsing==============================
parser = argparse.ArgumentParser()
parser.add_argument("-ps", "--port_start", type=int,
                    help="port to bind, range: [start, end]", default=3280)
parser.add_argument("-pe", "--port_end", type=int,
                    help="port to bind, range: [start, end]", default=3287)
parser.add_argument("-m", "--multiple_interfaces", type=int,
                    help="0: w/o multiple interfaces; 1: multiple interfaces", default=0)
parser.add_argument("-l", "--length", type=int,
                    help="payload length", default=250)
parser.add_argument("-b", "--bandwidth", type=int,
                    help="data rate (bits per second)", default=200000)   
parser.add_argument("-t", "--time", type=int,
                    help="maximum experiment time", default=3600)                                   
                         
args = parser.parse_args()

if args.multiple_interfaces == 0:
    try:
        f = open("port.txt", "r")
        l = f.readline()
        PORT = int(l)
    except:
        PORT = input("First time running... please input the port number: ")
        f = open("port.txt", "w")
        f.write(PORT)
    PORTS = [PORT]
else:
    PORTS = [i for i in range(args.port_start, args.port_end+1)]
print("PORTS = ", PORTS)

length_packet = args.length
bandwidth = args.bandwidth
total_time = args.time

expected_packet_per_sec = bandwidth / (length_packet << 3)
sleeptime = 1.0 / expected_packet_per_sec
#==================================================================

#===================global variables===============================
thread_stop = True
exit_main_process = False
#==================================================================

#===================other variables================================
HOST = '140.112.17.209'
CONTROL_PORT = 3299

pcap_path = "pcapdir"
if not os.path.exists(pcap_path):
    os.system("mkdir %s"%(pcap_path))
#==================================================================

def connection_setup():
    print("Initial setting up...")
    
    s_udp_list = []
    
    #--------------establish sockets for UDP data traffic----- 
    for PORT in PORTS:
        s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_udp.settimeout(1)
        
        #if m=1, bind to specific interface name
        if args.multiple_interfaces == 1:
            interface_name = 'ss0'+str(PORT%10) #'usb' + str(index)
            print(interface_name)
            s_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (interface_name+'\0').encode())
        
        s_udp_list.append(s_udp)
        
    #--------------establish TCP control flows----------------
    s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_tcp.connect((HOST, CONTROL_PORT))
    
    return s_tcp, s_udp_list

def transmission(s_udp_list):
    global thread_stop
    print("start transmission: ")
    
    seq = 1
    prev_transmit = 0
    
    start_time = time.time()
    next_transmit_time = start_time + sleeptime
    
    time_slot = 1
    
    while time.time() - start_time < total_time and not thread_stop:
        try:
            t = time.time()
            while t < next_transmit_time:
                t = time.time()
            next_transmit_time = next_transmit_time + sleeptime
        
            datetimedec = int(t)
            microsec = int((t - int(t))*1000000)
        
            redundant = os.urandom(length_packet-4*3)
            outdata = datetimedec.to_bytes(4, 'big') + microsec.to_bytes(4, 'big') + seq.to_bytes(4, 'big') + redundant
            
            for s_udp, PORT in zip(s_udp_list, PORTS):       
                s_udp.sendto(outdata, (HOST, PORT))
            seq += 1
        
            if time.time()-start_time > time_slot:
                print("[%d-%d]"%(time_slot-1, time_slot), "transmit", seq-prev_transmit)
                time_slot += 1
                prev_transmit = seq
        except Exception as e:
            print(e)
            thread_stop = True
    thread_stop = True
    print("---transmission timeout---")
    print("transmit", seq, "packets")

def receive(s_udp, s_udp_list):
    s_udp.settimeout(3)
    print("wait for indata...")
    number_of_received_packets = 0
    
    seq = 1
    max_seq = 1

    global thread_stop
    while not thread_stop:
        try:
            indata, addr = s_udp.recvfrom(1024)
            
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
    
    for s_udp_list_element, port in zip(s_udp_list, PORTS):
        if s_udp_list_element == s_udp:
            f = open(str(port)+".txt", "a")
            f.write("Total capture: " + str(number_of_received_packets) + "; Total lose: " + str(max_seq - number_of_received_packets) + "\n")
            f.close()
            
    print("STOP bypass")

def remote_control(s_tcp, t):
    global thread_stop
    global exit_main_process
    
    while t.is_alive() and not thread_stop:
        try:
            indata, addr = s_tcp.recvfrom(1024)    ###might need to check
            
            if indata.decode() == "STOP":    
                thread_stop = True
                break
            elif indata.decode() == "EXIT":
                thread_stop = True
                exit_main_process = True
                break
        except Exception as inst:
            print("Error: ", inst)
    thread_stop = True
    print("STOP remote control")

while not exit_main_process:
    tcpproc_list = []
    try:
        now = dt.datetime.today()
        n = '-'.join([str(x) for x in[ now.year, now.month, now.day, now.hour, now.minute, now.second]])
        print(len(PORTS))
        for PORT in PORTS:
            tcpproc = subprocess.Popen(["tcpdump -i any port %s -w %s/%s_%s.pcap"%(PORT,pcap_path,PORT,n)], shell=True, preexec_fn=os.setpgrp)
            tcpproc_list.append(tcpproc)
        print("ready to setup connection...")
        s_tcp, s_udp_list = connection_setup()
        
        #------------------wait for server ways "START"----------------
        while thread_stop == True:
            indata, addr = s_tcp.recvfrom(1024)    ###might need to check
            
            if indata.decode() == "START":    
                thread_stop = False
    except KeyboardInterrupt as inst:
        print("keyboard interrupt: ")
        for tcpproc in tcpproc_list:
            pgid = os.getpgid(tcpproc.pid)
    
            command = "kill -9 -{}".format(pgid)
            subprocess.check_output(command.split(" "))
        exit()
    except Exception as inst:
        print("Error: ", inst)
        pgid = os.getpgid(tcpproc.pid)
    
        command = "kill -9 -{}".format(pgid)
        subprocess.check_output(command.split(" "))
        exit()
    
    #--------------------start threads-------------------
    receiving_threads = []
    
    t = threading.Thread(target=transmission, args=(s_udp_list, ))
    t3 = threading.Thread(target=remote_control, args = (s_tcp, t))
    t.start()
    t3.start()
    
    for s_udp in s_udp_list:
        t2 = threading.Thread(target=receive, args=(s_udp, s_udp_list, ))
        t2.start()
        receiving_threads.append(t2)
    
    t.join()
    t3.join()

    #------------------wait for threads end-------------
    for t2 in receiving_threads:
        t2.join()

    s_tcp.close()
    for s_udp in s_udp_list:
        s_udp.close()

    print("finally: kill tcpdump")
    for tcpproc in tcpproc_list:
        pgid = os.getpgid(tcpproc.pid)
    
        command = "kill -9 -{}".format(pgid)
        subprocess.check_output(command.split(" "))
    
    time.sleep(5)
