import random
from socket import *
import threading
import time
import json
import hashlib

import os
import urllib
import re

#first_join 141.222.126.136:12000


#first_join 141.222.30.177:12000
M = 32
MAX_IP = '141.222.115.202'
PETER_IP = '141.222.113.174'
WILL_IP = '141.222.123.162'
AJANI_IP = '141.222.126.136'
PHYSICS_IP = '141.222.30.177'
MY_IP = MAX_IP

INTERVAL = 10

class Message:
    def __init__(self=None, method=None, id=None, ip_port=None, 
        orig_requestor=None, mode=None, key=None, value=None):
        self.method = method
        self.id = id
        self.ip_port = ip_port
        self.orig_requestor = orig_requestor
        self.mode = mode
        self.key = key
        self.value = value
    

def serialize(msg):
    ser_msg = {}
    if (msg.method is not None):
        ser_msg['method'] = msg.method
    if(msg.id is not None):
        ser_msg['id'] = msg.id
    if (msg.ip_port is not None):
        ser_msg['ip_port'] = msg.ip_port
    if(msg.orig_requestor is not None):
        ser_msg['orig_requestor'] = msg.orig_requestor
    if (msg.mode is not None):
        ser_msg['mode'] = msg.mode
    if (msg.key is not None):
        ser_msg['key'] = msg.key
    if (msg.value is not None):
        ser_msg['value'] = msg.value
    return json.dumps(ser_msg)

def deserialize(ser_msg):
    json_msg = json.loads(ser_msg)
    des_msg = Message(None,None,None,None,None,None,None)
    if ('method' in json_msg):
        des_msg.method = json_msg['method']
    if('id' in json_msg):
        des_msg.id = json_msg['id']
    if ('ip_port' in json_msg):
        des_msg.ip_port = json_msg['ip_port']
    if('orig_requestor' in json_msg):
        des_msg.orig_requestor = json_msg['orig_requestor']
    if('mode' in json_msg):
        des_msg.mode = json_msg['mode']
    if('key' in json_msg):
        des_msg.key = json_msg['key']
    if('value' in json_msg):
        des_msg.value = json_msg['value']
    return des_msg

class DHTNode:


    # Hash some data using SHA1 and
    # return first 32 bits of result.
    def hash_and_chop(self, data):
        m = hashlib.sha1()
        m.update(str(data).encode('utf-8'))
        first_32_bits = m.hexdigest()[:8]
        return int(first_32_bits, 16)


    # both exclusive
    def mod_between(self, n, start, end):
        if(start < n and n < end):
            return True
        # Potential modulo case
        if(start > end and (n > start or n < end)):
            return True
        return False


    # Initially, all finger table entries point to self
    def setup_finger_table(self):
        for i in range(1,33):
            finger_table[i] = [self.id, self.ip_and_port]


    def __init__(self):
        self.predecessor = None
        self.ip_and_port = MY_IP + ':12000'
        self.id = self.hash_and_chop(self.ip_and_port)
        self.successor = [self.id, self.ip_and_port]
        self.finger_table = [[self.id, self.ip_and_port] for x in range(0,M)]
        self.hash_table = {} 
        self.next_finger = 0
        self.run()

    def run(self):
        client_thread = threading.Thread(target=self.client)
        server_thread = threading.Thread(target=self.server)
        client_thread.start()
        server_thread.start()
        client_thread.join()
        server_thread.join()


    def server(self):
        serverSocket = socket(AF_INET, SOCK_DGRAM)
        serverSocket.bind(('',12000))
        while True:
            message, address = serverSocket.recvfrom(1024)
            print(message)
            self.handle_msg(message)


    def client(self):
        while True:
            command = input("Type a command to interact with the DHT: ")
            print(command)
            params = command.split(' ')
            if(params[0] == 'join'): #join ip:port
                ip_port = params[1]
                msg = Message(method='FIND_SUCC', mode='JOIN', id=self.id, orig_requestor=self.ip_and_port)
                self.send_msg(msg, ip_port)
            elif(params[0] == 'first_join'):
                ip_port = params[1]
                msg = Message(method='FIND_SUCC', mode='FIRST_JOIN', id=self.id, orig_requestor=self.ip_and_port)
                self.send_msg(msg, ip_port)
            elif(command == 'get'):
                print()
            elif(command == 'put'):
                print()
            elif(command == 'print'):
                for item in self.finger_table:
                    print(item)
                


    def closest_preceding_node(self, id):
        for i in range(M-1,-1,-1):
            curr_id_and_ip = self.finger_table[i]
            curr_id = curr_id_and_ip[0]
            if(self.mod_between(curr_id, self.id, id)):
                return curr_id_and_ip
        return [self.id, self.ip_and_port]

    def find_succ(self, msg):
        # First join is a special case
        if(msg.mode == 'FIRST_JOIN'):
            print('if case first_join')
            for item in self.finger_table:
                print(item)
            msg.method = 'FIND_SUCC_RES' # now we are sending a result, so change type
            msg.id = self.successor[0] # id is id of successor node
            msg.ip_port = self.successor[1]# ip_port is ip and port of successor node
            self.send_msg(msg, msg.orig_requestor)

        elif(self.mod_between(msg.id, self.id, self.successor[0] + 1)):
            msg.method = 'FIND_SUCC_RES' # now we are sending a result, so change type
            msg.id = self.successor[0] # id is id of successor node
            msg.ip_port = self.successor[1]# ip_port is ip and port of successor node
            self.send_msg(msg, msg.orig_requestor)
        # If cannot resolve locally, then make an RPC
        else:
            node_to_rpc = self.closest_preceding_node(msg.id)[1] # store actual IP/port in index 1
            self.send_msg(msg, node_to_rpc)

    def handle_msg(self, ser_msg):
        print("RECEVIED: " + str(ser_msg))
        print()
        msg = deserialize(ser_msg)
        if(msg.method == 'FIND_SUCC'):
            if msg.mode == 'FIRST_JOIN':
                self.predecessor = [msg.id,msg.orig_requestor]
                self.successor = [msg.id,msg.orig_requestor]
                self.finger_table = [[msg.id, msg.orig_requestor] for x in range(0,len(self.finger_table))]
                self.time_interval(INTERVAL)
            self.find_succ(msg)

        elif(msg.method == 'FIND_SUCC_RES'):
            if(msg.mode == 'JOIN' or msg.mode == 'FIRST_JOIN'):
                self.successor = [msg.id, msg.ip_port]
                if msg.mode == 'FIRST_JOIN':
                    self.predecessor = [msg.id,msg.ip_port]
                self.finger_table = [[msg.id, msg.ip_port] for x in range(0,len(self.finger_table))]
                self.time_interval(INTERVAL)

        elif(msg.method == 'CHECK_PRED' and self.predecessor is not None):
            msg.method = 'CHECK_PRED_RES'
            msg.id = self.predecessor[0]
            msg.ip_port = self.predecessor[1]
            msg.orig_requestor = self.ip_and_port
            self.send_msg(msg, msg.orig_requestor)
            

        elif(msg.method == 'CHECK_PRED_RES'):
            if self.mod_between(msg.id,self.id,self.successor[0]):
                self.successor = [msg.id, msg.ip_port]
                msg.method = 'NOTIFY'
                msg.id = self.id
                msg.ip_port = self.ip_and_port
                self.send_msg(msg, msg.orig_requestor)
            

        elif(msg.method == 'NOTIFY'):
            if self.predecessor is None or self.mod_between(msg.id, self.predecessor[0], self.id):
                self.predecessor = [msg.id, msg.ip_port]
                for item in self.finger_table:
                    print(item)
            


    def send_msg(self, des_msg, ip_port):
        msg = serialize(des_msg)
        print("SENT: " + msg)
        print()
        client_socket = socket(AF_INET, SOCK_DGRAM)
        dest = ip_port.split(':')
        dest_tuple = (dest[0], int(dest[1]))
        print(dest_tuple)
        client_socket.sendto(msg.encode(), dest_tuple)

    def action_in_interval(self):
        self.fix_fingers()
        self.stabilize()
        self.time_interval(INTERVAL)

    def time_interval(self, seconds):
        print(time.ctime())
        threading.Timer(seconds, self.action_in_interval).start()
        

    def stabilize(self):
        msg = Message(method='CHECK_PRED',orig_requestor=self.ip_and_port)
        self.send_msg(msg,self.successor[1])
         
        
    def fix_fingers(self):
        self.next_finger = self.next_finger + 1
        if self.next_finger > M:
            self.next_finger = 0

        msg = Message(id=self.id + 2**self.next_finger, ip_port='', orig_requestor=self.ip_and_port)
        #self.finger_table[self.next_finger] = self.find_succ(msg)
        self.find_succ(msg)

        


def main():
    node = DHTNode()

main()





