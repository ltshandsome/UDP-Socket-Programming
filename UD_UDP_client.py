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

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--length", type=int,
                    help="payload length", default=250)
parser.add_argument("-b", "--bandwidth", type=int,
                    help="data rate (bits per second)", default=200000)   
parser.add_argument("-t", "--time", type=int,
                    help="maximum experiment time", default=3600)                                   
                         
args = parser.parse_args()
length_packet = args.length
bandwidth = args.bandwidth
total_time = args.time
expected_packet_per_sec = bandwidth / (length_packet << 3)
sleeptime = 1.0 / expected_packet_per_sec

HOST = '140.112.17.209'
try:
    f = open("port.txt", "r")
    l = f.readline()
    PORT = int(l)
except:
    PORT = input("First time running... please input the port number: ")
    f = open("port.txt", "w")
    f.write(PORT)
print("PORT = ", PORT)
server_addr = (HOST, PORT)

thread_stop = True
exit_main_process = False
pcap_path = "pcapdir"
if not os.path.exists(pcap_path):
    os.system("mkdir %s"%(pcap_path))

def connection_setup():
    print("Initial setting up...")
    
    s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_udp.settimeout(1)
    s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_tcp.connect((HOST, PORT))
    
    return s_tcp, s_udp

def transmision(s_udp):
    global thread_stop
    print("start transmision to addr", s_udp)
    
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
        
            redundent = os.urandom(250-4*3)
            outdata = datetimedec.to_bytes(4, 'big') + microsec.to_bytes(4, 'big') + seq.to_bytes(4, 'big') + redundent
        
            s_udp.sendto(outdata, server_addr)
            seq += 1
        
            if time.time()-start_time > time_slot:
                print("[%d-%d]"%(time_slot-1, time_slot), "transmit", seq-prev_transmit)
                time_slot += 1
                prev_transmit = seq
        except Exception as e:
            print(e)
            thread_stop = True
    thread_stop = True
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
            
            number_of_received_packets += 1
            
        except Exception as inst:
            print("Error: ", inst)
            thread_stop = True
    thread_stop = True
    
    print("---Experiment Complete---")
    print("Total capture: ", number_of_received_packets, "Total lose: ", seq - number_of_received_packets)
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
    try:
        now = dt.datetime.today()
        n = '-'.join([str(x) for x in[ now.year, now.month, now.day, now.hour, now.minute, now.second]])
        tcpproc = subprocess.Popen(["tcpdump -i any net 140.112.17.209 -w %s/%s.pcap"%(pcap_path,n)], shell=True, preexec_fn=os.setpgrp)
        s_tcp, s_udp = connection_setup()
        
        while thread_stop == True:
            indata, addr = s_tcp.recvfrom(1024)    ###might need to check
            
            if indata.decode() == "START":    
                thread_stop = False
    except KeyboardInterrupt as inst:
        print("keyboard interrupt: ")
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
    
    t = threading.Thread(target=transmision, args=(s_udp, ))
    t2 = threading.Thread(target=receive, args=(s_udp, ))
    t3 = threading.Thread(target=remote_control, args = (s_tcp, t))
    t.start()
    t2.start()
    t3.start()

    t.join()
    t2.join()
    t3.join()

    s_tcp.close()
    s_udp.close()

    print("finally: kill tcpdump")
    pgid = os.getpgid(tcpproc.pid)
    
    command = "kill -9 -{}".format(pgid)
    subprocess.check_output(command.split(" "))
    
    time.sleep(5)
