#!/usr/bin/env python

from __future__ import print_function
from __future__ import division
from datetime import datetime, timedelta
from builtins import str
from builtins import range
from past.utils import old_div

import time
import json
import random
import threading
from queue import Queue, Empty

from .interface import Listener, Talker
from .protocol import MessageType, MessageDirection, RequestVotesResults, \
    AppendEntriesResults, RequestVotesMessage, AppendEntriesMessage, \
    parse_json_message
from .secure_transport import SecureKeystore, ReplayCache, encode_secure_message, decode_secure_message

# Adjust these to test
address_book_fname = 'address_book.json'
total_nodes = 1

class RaftNode(threading.Thread):
    def __init__(self, config, name, role='follower', verbose=True):
        threading.Thread.__init__(self) 
        
        self._terminate = False
        self.daemon = True

        self.verbose = verbose

        # Where incoming client requests go
        self.client_queue = Queue()
        self.client_lock = threading.Lock()

        # List of known nodes and their communication information
        if (isinstance(config, dict)):
            address_book = config
        else:
            address_book = self._load_config(config, name)
        # Filter only node entries with ip/port
        node_entries = {k: v for k, v in address_book.items() if isinstance(v, dict) and ('ip' in v) and ('port' in v)}
        self.all_ids = [node_entries[a]['ip'] + ':' + node_entries[a]['port'] for a in node_entries if a != 'leader']
        self.my_id = node_entries[name]['ip'] + ':' + node_entries[name]['port']
        # Pretty names for addresses (e.g., 192.46.237.85:2380 -> node1)
        self.addr_to_name = {}
        self.name_to_addr = {}
        try:
            for node_name, meta in node_entries.items():
                addr = meta['ip'] + ':' + meta['port']
                self.addr_to_name[addr] = node_name
                self.name_to_addr[node_name] = addr
        except Exception:
            pass

        # Timestamp validation removed - using secure transport for replay protection

        # Demo logs (human-readable event logs for presentations)
        self.demo_logs = bool(address_book.get('demo_logs', True))
        self.demo_stdout_simple = bool(address_book.get('demo_stdout_simple', True))
        self._printed_following_leader = False
        # Stdout throttling for noisy events
        self._stdout_throttle_secs = 2.0
        self._last_stdout_sent_hb = 0.0
        self._last_stdout_sent_ae = 0.0
        self._last_stdout_recv_hb = 0.0
        self._last_stdout_recv_ae = 0.0

        # On startup, all nodes begin as followers. Emit a clear stdout + file log.
        if self.demo_logs:
            try:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                line = current_time+" : "+ f"event=role_init role=follower term={getattr(self, 'current_term', 0)}"
                if self.demo_stdout_simple:
                    print(f"{self.name}: Starting as follower (term {getattr(self, 'current_term', 0)})")
                else:
                    print(line)
                log_file_path = str(self.name)+"_logs.txt"
                with open(log_file_path, "a") as file:
                    file.write(line + "\n")
            except Exception:
                pass

        # Transport security (optional, backward-compatible)
        self.secure_enabled = bool(address_book.get('secure_transport', False))
        if self.secure_enabled:
            key_id = str(address_book.get('secure_key_id', 'default'))
            # Use pro vided PSK (hex/base64) or fallback dev key
            psk_text = address_book.get('secure_psk', 'dev-psk-not-for-production')
            try:
                # Try hex first
                psk_bytes = bytes.fromhex(psk_text)
            except ValueError:
                try:
                    # Then base64
                    import base64 as _b64
                    psk_bytes = _b64.b64decode(psk_text)
                except Exception:
                    # Fallback to utf-8
                    psk_bytes = psk_text.encode('utf-8')
            self._keystore = SecureKeystore({key_id: psk_bytes})
            self._active_key_id = key_id
            self._replay_cache = ReplayCache()

        # Timing variables
        # self.election_timeout = random.uniform(0.1, 0.1+0.05*len(self.all_ids)) # Failed vote backoff, used for pretty much all timing related things.
        # self.heartbeat_frequency = 0.01                                     # How often to send heartbeat (should be less than the election timeout).
        # self.resend_time = 2.0                                              # How often to resend an append entries if you havent heard from a node in a while. 

        # changes by hamza to make it a little slower for testing
        # To (much slower):
        self.election_timeout = random.uniform(5.0, 8.0)  # 5-8 seconds
        self.heartbeat_frequency = 5.0  # 2 seconds between heartbeats
        self.resend_time = 10.0  # 10 seconds


        # State variables that I've added
        self._name = name                                                   # Your name. Used mostly for debugging.
        self.current_num_nodes = len(self.all_ids)                          # Number of nodes in the system.
        self.current_role = role                                            # Your role in the system (follower, candidate, leader, pending).
        self.leader_id = None                                               # Who you think the current leader is.
        
        # Persistent state variables
        self.current_term = 1                                               # Your current election term.
        self.voted_for = None                                               # Who have you voted in this term. None means you haven't voted for anyone. 
        self.log = [{'term': 1, 'entry': 'Init Entry', 'id': -1}]           # Your log. Log entries are a dict with the following fields: term, entry, id.
        self.log_hash = {}
    
        # Volatile state variables
        self.commit_index = 0                                               # Index of the highest known committed entry in the system.
        self.last_applied_index = 0                                         # Index of the highest entry you have committed. Note that functionally this is the same as commit_index.
        self.last_applied_term = 1                                          # Term of the highest entry you have committed.

        # Volotile state leader variables 
        self.next_index = [None for _ in range(self.current_num_nodes)]     # Index to send to each node next. None means up to date
        self.match_index = [0 for _ in range(self.current_num_nodes)]       # Index of highest committed entry on each node
        self.heard_from = [0 for _ in range(self.current_num_nodes)]        # Time last heard from each node. 

        # Start both ends of your interface
        identity = {'my_id': self.my_id, 'my_name': name}
        self.listener = Listener(port_list=self.all_ids, identity=identity)
        self.listener.start()
        self.talker = Talker(identity=identity)
        self.talker.start()

        # Store last sent secure envelope per receiver for replay testing
        self._last_envelope_per_receiver = {}

    def stop(self):
        self.talker.stop()
        self.listener.stop()
        self._terminate = True

    @property
    def name(self):
        ''' Return the name of the node. '''
        return self._name
        
    def client_request(self, value, id_num=-1):
        '''
            client_request: Public function to enqueue a value. If the node
                is not the leader, this request will be forewarded to the 
                leader before being appended. If the system is in a transition
                state, the request may not be appended at all, so this should 
                be retried. If no id_num is specified, the id is set to -1.
            Inputs:
                value: any singleton data type.
                id_num: any immutable object.
        '''

        entry = {
            'term': self.current_term,
            'entry': value,
            'id': id_num
        }
        self.client_queue.put(entry)

    def check_committed_entry(self, id_num=None):
        ''' 
            check_committed_entry: Public function to check the last entry 
                committed. Optionally specify an id_num to search for. If 
                specified, will return the most recent entry with this id_num. 
            Inputs:
                id_num: returns the most recent entry with this id_num. 
        '''
        if (id_num is None):
            with self.client_lock:
                return self.log[self.commit_index]['entry']
        with self.client_lock:
            return self.log_hash.get(id_num, None)

    def check_role(self):
        ''' 
            check_role: Public function to check the role of a given node.
        '''
        with self.client_lock:
            return self.current_role

    def pause(self):
        '''
            pause: Allows the user to pause a node. In this state nodes are 
                "removed" from the system until un_pause is called. 
        '''
        self._set_current_role('none')
        if (self.verbose):
            print(self._name + ': pausing...')
        
    def un_pause(self):
        '''
            un_pause: Allows the user to unpause a node. If the node was not 
                already paused, does nothing.
        '''
        if (self.check_role() == 'none'):
            self._set_current_role('follower')
            if (self.verbose):
                print(self._name + ': unpausing...')
        else:
            if (self.verbose):
                print(self._name + ': node was not paused, doing nothing')

    def run(self):
        '''
            run: Called when the node starts. Facilitates state transitions. 
        '''
        # Wait for the interface to be ready
        time.sleep(self.listener.initial_backoff)

        # Your role determines your action. Every time a state chance occurs, this loop will facilitate a transition to the next state. 
        try:
            while not self._terminate:
                if self.check_role() == 'leader':
                    self._leader()
                elif self.check_role() == 'follower':
                    self._follower()
                elif self.check_role() == 'candidate':
                    self._candidate()
                else:
                    time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def _follower(self):
        ''' 
            _follower: Nodes will start here if they have been newly added to 
                the network. The responsibilities of the follower nodes are:
                    - Respond to election requests with a vote if the candidate 
                        is more up-to-date than they are. 
                    - Replicate entries sent by the leader. 
                    - Commit entries committed by the leader. 
                    - Promote self to candidate if the leader has crashed. 
        ''' 

        # This will be when you've seen the most recent heartbeat
        most_recent_heartbeat = time.time()

        while ((not self._terminate) and (self.check_role() == 'follower')):
            incoming_message = self._get_message()
            if (incoming_message is not None):

                # Followers only handle requests
                if (incoming_message.direction == MessageDirection.Request):

                    # Incoming message is a new election candidate
                    if (incoming_message.type == MessageType.RequestVotes):

                        # Timestamp validation removed - using secure transport for replay protection

                        # If this election is for a new term, update your term
                        if (incoming_message.term > self.current_term):
                            self._increment_term(incoming_message.term)
                            
                        # If you haven't already voted and you're less up to date than the candidate, send your vote
                        if ((self.voted_for is None) and (incoming_message.last_log_index >= self.last_applied_index) and (incoming_message.last_log_term >= self.last_applied_term)):
                            self._send_vote(incoming_message.sender)
                        else: 
                            self._send_vote(incoming_message.sender, False)

                        # If there's currently a candidate running, then you shouldn't promote yourself
                        most_recent_heartbeat = time.time()

                    # Incoming message is a heartbeat, make sure you're up to date, restart the timer
                    elif (incoming_message.type == MessageType.Heartbeat):
                        if (incoming_message.term > self.current_term):
                            self._increment_term(incoming_message.term)
                        self.leader_id = incoming_message.leader_id
                        most_recent_heartbeat = time.time()

                        # If leader has been resolved, check for any client requests
                        if (self.leader_id):
                            client_request = self._get_client_request()
                            if (client_request is not None):
                                self._send_client_request(incoming_message.leader_id, client_request)
                        
                    # Incoming message is some data to append
                    elif (incoming_message.type == MessageType.AppendEntries):

                        # Added: display append entry received
                        print(str(self.name)+": log received ["+str(incoming_message.entries['entry'])+"]")

                        # add the log to the file log (received logs only)
                        log_file_path = str(self.name)+"_logs.txt"
                        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with open(log_file_path, "a") as file:
                            file.write("Append entry received : "+current_time+" : ["+str(incoming_message.entries['entry'])+"]" "\n") 
                        
                        # Reply false if message term is less than current_term, this is an invalid entry
                        if (incoming_message.term < self.current_term):
                            self._send_acknowledge(incoming_message.leader_id, False)

                        # Reply false if log doesnt contain an entry at prev_log_index whose term matches prev_log_term
                        elif (not self._verify_entry(incoming_message.prev_log_index, incoming_message.prev_log_term)):
                            self._send_acknowledge(incoming_message.leader_id, False)

                        # Else if the previous index and term match, append the entry and reply true
                        else:
                            if (incoming_message.leader_commit > self.commit_index):
                                self._append_entry(incoming_message.entries, commit=True, prev_index=incoming_message.prev_log_index)
                            else:
                                self._append_entry(incoming_message.entries, commit=False, prev_index=incoming_message.prev_log_index)
                            self._send_acknowledge(incoming_message.leader_id, True)
                    
                    # Incoming message is a commit message
                    elif (incoming_message.type == MessageType.Committal):
                        self._commit_entry(incoming_message.prev_log_index, incoming_message.prev_log_term)

            # If you haven't heard a heartbeat in a while, promote yourself to a candidate
            if ((time.time() - most_recent_heartbeat) > (self.election_timeout)):
                self._set_current_role('candidate')
                return

        return

    # method to send malicious entry
    def send_entry_attack(self,message):
        if self.check_role != 'leader':
            entry = {'term': self.current_term, 'entry': message, 'id': -1}
            self._broadcast_append_entries(entry)


    # method to send candidate votes by attacker (with or without term increment)
    def replay_attack(self,bypass_timestamp=False):
        
        i = self.current_term + 1

        # read vote_request and send same vote
        json_file = "vote_request.json"
        vote_data = ""
        try:
            with open(json_file, "r") as f:
                vote_data = json.load(f)[0] 
        except (FileNotFoundError, IndexError) as e:
            print(e)
            return

        message = RequestVotesMessage(
            type_=vote_data["type"],
            term=vote_data["term"]+i,
            sender=self.my_id,
            direction=vote_data["direction"],
            candidate_id=self.my_id,
            last_log_index=self.last_applied_index,
            last_log_term=self.last_applied_term
        )
        
        # send the message to followers
        self._send_message(message)

        # vote for yourself
        self._send_vote(self.my_id, True)


    def _candidate(self):
        ''' 
            _candidate: Nodes will start here if they have not heard the leader 
                for a period of time. The responsibilities of the candidate 
                nodes are:
                    - Call for a new election and await the results: 
                    - If you recieve more than half of the votes in the system, 
                        promote yourself. 
                    - If you see someone else starting an election for a term 
                        higher than your own, vote for them, update yourself, 
                        and then demote yourself. 
                    - If you see a heartbeat for a term higher than or equal to 
                        your own, update yourself, and then demote yourself. 
                    - If you have not won after the election timeout, restart 
                        the election. 
        ''' 

        if(self.verbose):
            print(self._name + ': became candidate')
            # add the log to the file log (received logs only)
            log_file_path = str(self.name)+"_logs.txt"
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(log_file_path, "a") as file:
                file.write(current_time+" : "+ str(self._name) + ': became candidate' + "\n") 
                file.write(current_time+" : "+ str(self._name) + ': sent votes requests' + "\n") 

        # If you're a candidate, then this is a new term
        self._increment_term()

        # Request for nodes to vote for you
        self._send_request_vote()

        # Vote for yourself
        self._send_vote(self.my_id, True)
        
        # Keep track of votes for and against you
        votes_for_me = 0
        total_votes = 0

        # Keep track of how long the election has been going
        time_election_going = time.time()

        while ((not self._terminate) and (self.check_role() == 'candidate')):
            incoming_message = self._get_message()
            if (incoming_message is not None):

                # Handle responses to your election
                if (incoming_message.direction == MessageDirection.Response):
                
                    # If it is a vote, then tally for or against you
                    if (incoming_message.type == MessageType.RequestVotes):
                        if (incoming_message.results.vote_granted):
                            votes_for_me += 1
                        total_votes += 1

                        #print(self._name + ": votes for me " + str(votes_for_me))
                        #print(self._name + ": total votes " + str(total_votes))

                        print(f"{self.name}: got accepted votes [{votes_for_me}]")
                        # add the log to the file log (received logs only)
                        log_file_path = str(self.name)+"_logs.txt"
                        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with open(log_file_path, "a") as file:
                            file.write(current_time+" : "+ f"{self.name}: received vote requests acceptance [{votes_for_me}]" + "\n") 
                            
                        # If you have a majority, promote yourself
                        # Timestamp validation removed - using secure transport for replay protection
                        if ((votes_for_me > int(old_div(self.current_num_nodes, 2))) or (self.current_num_nodes == 1)):
                            self._set_current_role('leader')
                            return

                # Handle outside requests
                elif (incoming_message.direction == MessageDirection.Request):

                    # If there's an election for someone else on a higher term, update your term, vote for them, and demote yourself
                    if (incoming_message.type == MessageType.RequestVotes):
                        if (incoming_message.term > self.current_term):
                            self._increment_term(incoming_message.term)
                            self._send_vote(incoming_message.sender)
                            self._set_current_role('follower')
                            return

                    # If you see a heartbeat on the current term then someone else has been elected, update your term and demote yourself
                    elif (incoming_message.type == MessageType.Heartbeat):
                        if (incoming_message.term >= self.current_term):
                            self._increment_term(incoming_message.term)
                            self.leader_id = incoming_message.leader_id
                            self._set_current_role('follower')
                            return
            
            # If this election has been going for a while we're probably deadlocked, restart the election
            if ((time.time() - time_election_going) > self.election_timeout):
                if(self.verbose):
                    print(self._name + ': election timed out')
                    # add the log to the file log (received logs only)
                    log_file_path = str(self.name)+"_logs.txt"
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    with open(log_file_path, "a") as file:
                        file.write(current_time+" : "+ str(self._name) + ': election timed out' + "\n") 
                    
                self._set_current_role('candidate')
                return
        
        return

    def _leader(self):
        ''' 
            _leader: Nodes will start here if they have won an election and 
                promoted themselves. The responsibilities of the leader nodes 
                are:
                    - Send a periodic heartbeat. 
                    - Keep track of who is active in the system and their 
                        status. This is done using self.next_index and 
                        self.match_index.
                    - Accept client requests and replicate them on the system. 
                        When a new request is made, send an append entries to 
                        all up-to-date nodes and away a response. When  more 
                        than half of the nodes respond, commit that entry. 
                    - Catch up nodes that are behind by resending append 
                        entries after a short amount of time. 
                    - If there's a vote going on with a term term higher than 
                        your own, vote for them, update yourself, and then 
                        demote yourself. 
        ''' 
        
        if(self.verbose):
            print(self._name + ': became leader')
            # add the log to the file log (received logs only)
            log_file_path = str(self.name)+"_logs.txt"
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(log_file_path, "a") as file:
                file.write(current_time+" : "+ str(self._name) + ': became leader' + "\n") 

        # First things first, send a heartbeat
        self._send_heartbeat()

        # Keep track of when you've sent the last heartbeat
        most_recent_heartbeat = time.time()

        # You're the current leader
        self.leader_id = self.my_id

        # Assume all other nodes are up to date with your log
        self.match_index = [self.commit_index for _ in range(self.current_num_nodes)]
        self.next_index = [None for _ in range(self.current_num_nodes)]

        # Reset heard from
        self.heard_from = [time.time() for _ in range(self.current_num_nodes)]

        # Broadcast an entry to get everyone on the same page
        entry = {'term': self.current_term, 'entry': 'Leader Entry', 'id': -1}
        self._broadcast_append_entries(entry)

        while ((not self._terminate) and (self.check_role() == 'leader')):

            # First, send a heartbeat
            if ((time.time() - most_recent_heartbeat) > self.heartbeat_frequency):
                self._send_heartbeat()
                most_recent_heartbeat = time.time()
                if (self.verbose):
                    pass
                    #print(self._name + ': sent heartbeat')
                    #print(self._name + ': max committed index: ' + str(self.commit_index))

            # If you haven't heard from a node in a while and it's not up to date, resend the most recent append entries
            for node, index in enumerate(self.next_index):
                if ((index is not None) and ((time.time() - self.heard_from[node]) > self.resend_time)):
                    self._send_append_entries(index - 1, self.log[index - 1]['term'], self.log[index], self.all_ids[node])
                    self.heard_from[node] = time.time()

            # Watch for messages
            incoming_message = self._get_message()
            if (incoming_message is not None):

                # Handle incoming responses 
                if (incoming_message.direction == MessageDirection.Response):

                    # Incoming message is an ack, update next_index and see if there's more log to send
                    if (incoming_message.type == MessageType.Acknowledge):
                        sender_index = self._get_node_index(incoming_message.sender)
                        self.heard_from[sender_index] = time.time()

                        # If you haven't already gotten a positive ack for this operation 
                        if (self.next_index[sender_index] is not None):

                            # If the append entries was successful, then increment next index to send, otherwise decrement
                            if (incoming_message.results.success):
                                self.match_index[sender_index] = self.next_index[sender_index]
                                self.next_index[sender_index] += 1
                            else:
                                if (self.next_index[sender_index] != 1):
                                    self.next_index[sender_index] -= 1

                            # Are there more entries to send to bring this node up to date?
                            if self.next_index[sender_index] > self._log_max_index():
                                self.next_index[sender_index] = None
                            else:
                                next_index = self.next_index[sender_index]
                                self._send_append_entries(next_index - 1, self.log[next_index - 1]['term'], self.log[next_index], incoming_message.sender)
                            
                            if (self.verbose):
                                print(self._name + ": updated standing is " + str(self.match_index) + " current index: " + str(self._log_max_index()) + " current term: "+ str(self.current_term))
                                # add the log to the file log (received logs only)
                                log_file_path = str(self.name)+"_logs.txt"
                                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                with open(log_file_path, "a") as file:
                                    file.write(current_time+" : "+ self._name + ": updated standing is " + str(self.match_index) + " current index: " + str(self._log_max_index()) + " current term: "+ str(self.current_term) + "\n") 

                            # Determine the 'committable' indices
                            log_lengths = [int(i) for i in self.match_index if (i is not None)]
                            log_lengths.sort(reverse=True)
                            max_committable_index = 0
                            for index in log_lengths:
                                # Count how many other nodes this index is replicated on
                                replicated_on = sum([1 if index <= i else 0 for i in log_lengths])
                                if (replicated_on >= (int(old_div(self.current_num_nodes, 2)) + 1)):
                                    max_committable_index = index

                            # If there's a new committable index, then send the commit
                            if (max_committable_index > self.commit_index):
                                    self._broadcast_commmit_entries(max_committable_index)

                    # If its a client then it's a new request
                    elif (incoming_message.type == MessageType.ClientRequest):
                        client_request = incoming_message.entries
                        self._broadcast_append_entries(client_request)

                # Handle incoming requests
                elif (incoming_message.direction == MessageDirection.Request):

                    # Incoming message is a request votes, if there's a vote going on with a term above yours, update your term, vote for them, and demote yourself
                    if (incoming_message.type == MessageType.RequestVotes):

                        # Timestamp validation removed - using secure transport for replay protection
                        if (incoming_message.term > self.current_term):
                            self._increment_term(incoming_message.term)
                            self._send_vote(incoming_message.sender)
                            self._set_current_role('follower')

                            if(self.verbose):
                                print(self._name + ': saw higher term, demoting')
                                # add the log to the file log (received logs only)
                                log_file_path = str(self.name)+"_logs.txt"
                                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                with open(log_file_path, "a") as file:
                                    file.write(current_time+" : "+ self._name + ': saw higher term, demoting' + "\n") 
                                
                            return
            
            # Get any pending client requests
            client_request = self._get_client_request()
            if (client_request is not None):
                self._broadcast_append_entries(client_request)

        return

    def _send_message(self, message):
        '''
            _send_message: A wrapper to send a message.
            Inputs:
                message: (RequestVotesMessage or AppendEntriesMessage)
        '''
        msg_dict = message.jsonify()
        # Demo log: outbound message summaries
        if getattr(self, 'demo_logs', False):
            try:
                log_file_path = str(self.name)+"_logs.txt"
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                def _nm(addr):
                    try:
                        return self.addr_to_name.get(addr, str(addr))
                    except Exception:
                        return str(addr)
                if msg_dict.get('type') == MessageType.RequestVotes and msg_dict.get('direction') == MessageDirection.Request:
                    line = current_time+" : "+ f"event=sent_vote_request term={msg_dict.get('term')} from={_nm(msg_dict.get('sender'))} to={_nm(msg_dict.get('receiver'))} last_log_index={msg_dict.get('last_log_index', '')} last_log_term={msg_dict.get('last_log_term', '')}"
                    if self.demo_stdout_simple:
                        print(f"{self.name}: Asked for votes (term {msg_dict.get('term')})")
                    else:
                        print(line)
                    with open(log_file_path, "a") as file:
                        file.write(line + "\n")
                elif msg_dict.get('type') == MessageType.RequestVotes and msg_dict.get('direction') == MessageDirection.Response:
                    granted = None
                    try:
                        granted = msg_dict.get('results', {}).get('vote_granted')
                    except Exception:
                        granted = None
                    line = current_time+" : "+ f"event=sent_vote_response term={msg_dict.get('term')} to={_nm(msg_dict.get('receiver'))} granted={granted}"
                    if self.demo_stdout_simple:
                        print(f"{self.name}: Voted {'YES' if granted else 'NO'} (term {msg_dict.get('term')})")
                    else:
                        print(line)
                    with open(log_file_path, "a") as file:
                        file.write(line + "\n")
                elif msg_dict.get('type') == MessageType.Heartbeat:
                    leader_addr = msg_dict.get('leader_id', msg_dict.get('sender'))
                    line = current_time+" : "+ f"event=sent_heartbeat term={msg_dict.get('term')} leader={_nm(leader_addr)}"
                    if self.demo_stdout_simple:
                        now_ts = time.time()
                        if (now_ts - self._last_stdout_sent_hb) >= self._stdout_throttle_secs:
                            print(f"{self.name}: Heartbeat sent (term {msg_dict.get('term')})")
                            self._last_stdout_sent_hb = now_ts
                    else:
                        print(line)
                    with open(log_file_path, "a") as file:
                        file.write(line + "\n")
                elif msg_dict.get('type') == MessageType.AppendEntries and msg_dict.get('direction') == MessageDirection.Request:
                    entries = msg_dict.get('entries')
                    count = 0 if entries is None else len(entries)
                    line = current_time+" : "+ f"event=sent_append_entries term={msg_dict.get('term')} count={count} prev_index={msg_dict.get('prev_log_index')} prev_term={msg_dict.get('prev_log_term')}"
                    if self.demo_stdout_simple:
                        now_ts = time.time()
                        if (now_ts - self._last_stdout_sent_ae) >= self._stdout_throttle_secs:
                            print(f"{self.name}: Replicating {count} entries (term {msg_dict.get('term')})")
                            self._last_stdout_sent_ae = now_ts
                    else:
                        print(line)
                    with open(log_file_path, "a") as file:
                        file.write(line + "\n")
            except Exception:
                pass
        if getattr(self, 'secure_enabled', False):
            receiver = msg_dict.get('receiver')
            # For broadcast (receiver None), derive context with a shared label
            peer_context_id = '' if receiver is None else receiver
            envelope = encode_secure_message(
                message_dict=msg_dict,
                peer_id=peer_context_id,
                key_id=self._active_key_id,
                keystore=self._keystore,
                confidential=True
            )
            send_obj = {
                'receiver': receiver,
                'secure': True,
                'broadcast': (receiver is None),
                'envelope': envelope
            }
            # Remember the exact envelope to allow tx_id replay
            key = receiver if receiver is not None else '__broadcast__'
            self._last_envelope_per_receiver[key] = send_obj
            self.talker.send_message(send_obj)
        else:
            self.talker.send_message(msg_dict)

    def _get_message(self):
        '''
            _get_message: A wrapper to get a message. If there are no pending 
                messages returns None. 
        '''
        raw = self.listener.get_message()
        if raw is None:
            return None
        if raw.get('secure') and getattr(self, 'secure_enabled', False):
            # Determine context id used during encode
            peer_context_id = '' if raw.get('broadcast') else self.my_id
            # Remember last received secure envelope for replay testing
            try:
                self._last_received_envelope = raw
            except Exception:
                pass
            try:
                decoded = decode_secure_message(
                    envelope=raw['envelope'],
                    peer_id=peer_context_id,
                    keystore=self._keystore,
                    replay_cache=self._replay_cache,
                    confidential=True
                )
                # Demo log: received summaries (pretty names + stdout)
                if getattr(self, 'demo_logs', False):
                    try:
                        def _nm(addr):
                            try:
                                return self.addr_to_name.get(addr, str(addr))
                            except Exception:
                                return str(addr)
                        msg_type = decoded.get('type')
                        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        log_file_path = str(self.name)+"_logs.txt"
                        sender_addr = decoded.get('sender')
                        # Skip logging received events originating from this node (self)
                        if sender_addr == self.my_id:
                            pass
                        elif msg_type == MessageType.RequestVotes and decoded.get('direction') == MessageDirection.Request:
                            line = current_time+" : "+ f"event=received_vote_request term={decoded.get('term')} from={_nm(decoded.get('sender'))} last_log_index={decoded.get('last_log_index', '')} last_log_term={decoded.get('last_log_term', '')}"
                            if self.demo_stdout_simple:
                                print(f"{self.name}: Vote request from {_nm(decoded.get('sender'))} (term {decoded.get('term')})")
                            else:
                                print(line)
                            with open(log_file_path, "a") as file:
                                file.write(line + "\n")
                        elif msg_type == MessageType.RequestVotes and decoded.get('direction') == MessageDirection.Response:
                            granted = None
                            try:
                                granted = decoded.get('results', {}).get('vote_granted')
                            except Exception:
                                granted = None
                            line = current_time+" : "+ f"event=received_vote_response term={decoded.get('term')} from={_nm(decoded.get('sender'))} granted={granted}"
                            if self.demo_stdout_simple:
                                print(f"{self.name}: Vote {'YES' if granted else 'NO'} from {_nm(decoded.get('sender'))} (term {decoded.get('term')})")
                            else:
                                print(line)
                            with open(log_file_path, "a") as file:
                                file.write(line + "\n")
                        elif msg_type == MessageType.Heartbeat:
                            leader_addr = decoded.get('leader_id', decoded.get('sender'))
                            line = current_time+" : "+ f"event=received_heartbeat term={decoded.get('term')} leader={_nm(leader_addr)}"
                            if self.demo_stdout_simple:
                                now_ts = time.time()
                                if (now_ts - self._last_stdout_recv_hb) >= self._stdout_throttle_secs:
                                    print(f"{self.name}: Heartbeat from {_nm(leader_addr)} (term {decoded.get('term')})")
                                    self._last_stdout_recv_hb = now_ts
                            else:
                                print(line)
                            with open(log_file_path, "a") as file:
                                file.write(line + "\n")
                        elif msg_type == MessageType.AppendEntries and decoded.get('direction') == MessageDirection.Request:
                            entries = decoded.get('entries')
                            count = 0 if entries is None else len(entries)
                            line = current_time+" : "+ f"event=received_append_entries term={decoded.get('term')} count={count} prev_index={decoded.get('prev_log_index')} prev_term={decoded.get('prev_log_term')}"
                            if self.demo_stdout_simple:
                                now_ts = time.time()
                                if (now_ts - self._last_stdout_recv_ae) >= self._stdout_throttle_secs:
                                    print(f"{self.name}: AppendEntries {count} entries (term {decoded.get('term')})")
                                    self._last_stdout_recv_ae = now_ts
                            else:
                                print(line)
                            with open(log_file_path, "a") as file:
                                file.write(line + "\n")
                    except Exception:
                        pass
                # Log acceptance with tx_id for observability
                try:
                    log_file_path = str(self.name)+"_logs.txt"
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    with open(log_file_path, "a") as file:
                        file.write(current_time+" : "+ f"secure accepted tx_id [{raw['envelope'].get('tx_id','')}]" + "\n")
                except Exception:
                    pass
            except Exception as _:
                # Log authentication/replay failures to node logs
                try:
                    log_file_path = str(self.name)+"_logs.txt"
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    txid = ''
                    try:
                        txid = raw.get('envelope', {}).get('tx_id', '')
                    except Exception:
                        txid = ''
                    with open(log_file_path, "a") as file:
                        file.write(current_time+" : "+ f"secure drop tx_id [{txid}] (auth/replay)" + "\n")
                except Exception:
                    pass
                return None
            return parse_json_message(decoded)
        else:
            # If secure is enabled, drop any non-secure incoming message
            if getattr(self, 'secure_enabled', False) and (not raw.get('secure')):
                try:
                    log_file_path = str(self.name)+"_logs.txt"
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    with open(log_file_path, "a") as file:
                        file.write(current_time+" : "+ "non-secure message received while secure enabled (dropped)" + "\n")
                except Exception:
                    pass
                return None
            # If we receive a secure envelope while secure is disabled, drop it safely
            if raw.get('secure') and not getattr(self, 'secure_enabled', False):
                try:
                    log_file_path = str(self.name)+"_logs.txt"
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    with open(log_file_path, "a") as file:
                        file.write(current_time+" : "+ "secure message received while secure disabled (dropped)" + "\n")
                except Exception:
                    pass
                return None
            return parse_json_message(raw)

    # Testing utility: resend the last exact secure envelope to trigger replay protection
    def replay_last_envelope(self, target_receiver=None):
        '''
            Resend the last secure envelope for the given receiver (or broadcast) verbatim.
            This will reuse the same tx_id and should trigger the replay cache on peers.
        '''
        if not getattr(self, 'secure_enabled', False):
            return False
        key = target_receiver if target_receiver is not None else '__broadcast__'
        send_obj = self._last_envelope_per_receiver.get(key)
        if not send_obj:
            return False
        # Re-send verbatim
        self.talker.send_message(send_obj)
        return True

    # Testing utility: resend the last received secure envelope as-is
    def replay_last_received_envelope(self):
        if not getattr(self, 'secure_enabled', False):
            return False
        raw = getattr(self, '_last_received_envelope', None)
        if not raw:
            return False
        # Re-send the exact raw envelope
        self.talker.send_message(raw)
        return True

    # Attack/demonstration utilities
    def _resolve_target_addr(self, target: str):
        # Accept node name (node1) or address (192.46.237.85:2380)
        if not target:
            return None
        if ':' in target:
            return target
        return self.name_to_addr.get(target, target)

    def send_vote_attack(self, target: str, delta_term: int = 1, raw: bool = False, old_term: bool = False):
        try:
            target_addr = self._resolve_target_addr(target)
            if target_addr is None:
                return False
            # Determine attack term
            if old_term:
                attack_term = max(0, self.current_term - abs(delta_term))
            else:
                attack_term = self.current_term + abs(delta_term)

            vote = RequestVotesMessage(
                type_ = MessageType.RequestVotes,
                term = attack_term,
                sender = self.my_id,
                receiver = target_addr,
                direction = MessageDirection.Request,
                candidate_id = self.my_id,
                last_log_index = self.last_applied_index,
                last_log_term = self.last_applied_term
            )
            msg_dict = vote.jsonify()

            if raw or not getattr(self, 'secure_enabled', False):
                # Send as raw JSON (simulates outsider or secure off)
                self.talker.send_message(msg_dict)
                if self.demo_stdout_simple:
                    print(f"{self.name}: Attack sent (RAW vote term {attack_term}) to {target}")
            else:
                # Insider (with PSK): wrap securely
                envelope = encode_secure_message(
                    message_dict=msg_dict,
                    peer_id=target_addr,
                    key_id=self._active_key_id,
                    keystore=self._keystore,
                    confidential=True
                )
                send_obj = {
                    'receiver': target_addr,
                    'secure': True,
                    'broadcast': False,
                    'envelope': envelope
                }
                self.talker.send_message(send_obj)
                if self.demo_stdout_simple:
                    print(f"{self.name}: Attack sent (secure vote term {attack_term}) to {target}")
            return True
        except Exception as e:
            try:
                print(f"{self.name}: Attack send failed: {e}")
            except Exception:
                pass
            return False

    # Toggle secure transport on this node (demo convenience)
    def set_secure(self, enabled: bool):
        try:
            self.secure_enabled = bool(enabled)
            # Reset replay cache when toggling to avoid stale tx_ids surprises
            if self.secure_enabled:
                self._replay_cache = ReplayCache()
            if self.demo_stdout_simple:
                print(f"{self.name}: Secure transport {'ENABLED' if self.secure_enabled else 'DISABLED'}")
            # File log for visibility
            try:
                log_file_path = str(self.name)+"_logs.txt"
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(log_file_path, "a") as file:
                    file.write(current_time+" : "+ f"event=secure_toggle enabled={self.secure_enabled}" + "\n")
            except Exception:
                pass
            return True
        except Exception as e:
            try:
                print(f"{self.name}: Secure toggle failed: {e}")
            except Exception:
                pass
            return False

    def _load_config(self, config, name):
        with open(config, 'r') as infile:
            data = json.load(infile)
        return data

    def _get_client_request(self):
        '''
            _get_node_index: Pops the most recent client request. 
        '''
        try:
            return self.client_queue.get(block=False)
        except Empty:
            return None
    
    def _set_current_role(self, role):
        '''
            _set_current_role: Set the node role. Options are ['follower', 
            'leader', 'candidate']
            Inputs: 
                role: (str)
                    Node's new role
        '''
        with self.client_lock:
            prev = getattr(self, 'current_role', None)
            self.current_role = role
            # Reset helper flag used to print a single "following leader" line
            self._printed_following_leader = False
        # Demo log role changes
        if getattr(self, 'demo_logs', False):
            try:
                log_file_path = str(self.name)+"_logs.txt"
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                line = current_time+" : "+ f"event=role_change old={prev} new={role} term={self.current_term}"
                if prev != role:
                    print(line)
                    with open(log_file_path, "a") as file:
                        file.write(line + "\n")
            except Exception:
                pass

    def _get_node_index(self, node_address):
        '''
            _get_node_index: Retuns the index of a specific node address,
                e.g. for
                    self.all_ids = ['192.46.237.85:2380', '172.105.85.119:2380']
                    _get_node_index('192.46.237.85:2380') <- returns 0
            Inputs: 
                node_address: (str)
                    The query address
        '''
        return self.all_ids.index(node_address)

    def _log_max_index(self):
        '''
            _log_max_index: Returns the max index of the log. Used for 
                convenience. 
        '''
        return len(self.log) - 1

    def _increment_term(self, term=None):
        '''
            _increment_term: Should be called whenever changing terms. 
                Does the following: clears the voted for status, increments
                the term. Useful for ensuring that both of these are done
                whenever the term is changed
            Input: 
                term: (int or None)
                    If term is none, will increment by one. Else will change
                    the term to whatever was input.
        '''
        self.voted_for = None
        if (term is None):
            self.current_term = self.current_term + 1
        else:
            self.current_term = term

    def _verify_entry(self, prev_index, prev_term):
        '''
            _verify_entry: Should be called whenever checking if an entry can 
                be appended to the log. Checks that the log has enough entries
                that the target index will not cause an error. Then checks if
                the target index has the same term as the target term. If it 
                does then this is a valid entry. 
            Input: 
                prev_index: (int)
                    Index to check.
                prev_term: (int)
                    Term to check.
        '''
        
        if (len(self.log) <= prev_index):
            return False
        if (self.log[prev_index]['term'] == prev_term):
            return True
        return False

    def _append_entry(self, entry, commit=False, prev_index=None):
        '''
            _append_entry: Appends entries to the log and optionally commits. 
                Assumes that the entry has already been verified (see 
                _verify_entry).
            Inputs:
                entry: (dict with the attributes 'term' and 'entry') 
                    Stores  whatever information to append to the log. 
                commit: (bool) 
                    If True, will update the last applied index and term after
                    writing to the log. If false will do nothing. 
                prev_index: (int) 
                    If None, will append the entry to the end of the log. Else 
                    will append the entry to the index specified.
        '''

    
        # If prev_term was specified, might have to cut the log short
        if (prev_index is None):
            prev_index = len(self.log) - 1
        else:
            self.log = self.log[:prev_index+1]
        
        # Add this to the log
        prev_term = self.log[-1]['term']
        with self.client_lock:
            self.log.append(entry)
            self.log_hash[entry['id']] = entry

        # Maybe commit
        if (commit):
            self._commit_entry(prev_index, entry['term'])

        return prev_index, prev_term

    def _commit_entry(self, index, term):
        '''
            _commit_entry: Update internal varables to reflect a commit at the 
                given index and term. Specifically the below variables should 
                be updated whenever a commmit is made. 
            Inputs:
                index: (int) 
                    Index to commit.
                term: (int) 
                    Term corresponding to this commit.
        '''
        self.last_applied_index = index
        self.last_applied_term = term

        # Commit index can be used in parallel by the client to query a log index
        with self.client_lock:
            self.commit_index = index

    def _broadcast_append_entries(self, entry):
        '''
            _broadcast_append_entries: Should be called only by the leader. 
                Sends an append entries message to all nodes for the given 
                entry.
            Inputs:
                entry: (dict with the attributes 'term' and 'entry') 
                    Entry to append to all nodes.    
        '''
        # Append the new entry 
        prev_index, prev_term = self._append_entry(entry, commit=False)

        # Send out other append entries
        for node, index in enumerate(self.next_index):
            # Only send out append entries to nodes that are up-to-date. Also they will now be out of date so update next. 
            if (index is None):
                self._send_append_entries(prev_index, prev_term, entry, self.all_ids[node])
                self.next_index[node] = self._log_max_index()

        # Update your own information
        self.next_index[self._get_node_index(self.my_id)] =  None
        self.match_index[self._get_node_index(self.my_id)] = self._log_max_index()

    def _broadcast_commmit_entries(self, index):
        '''
            _broadcast_commmit_entries: Should be called only by the leader. 
                Sends a commit message to all nodes for the given index.
            Inputs:
                index: (int) 
                    Index to commit.          
        '''
        # Commit yourself
        self._commit_entry(index, self.log[index]['term'])

        # Commit everybody else
        for node, index in enumerate(self.match_index):
            if (index >= index):
                self._send_committal(index, self.all_ids[node])

    def _send_request_vote(self, receiver=None):
        message = RequestVotesMessage(
            type_ =   MessageType.RequestVotes, 
            term =   self.current_term, 
            sender = self.my_id,
            receiver = receiver, 
            direction = MessageDirection.Request, 
            candidate_id = self.my_id, 
            last_log_index = self.last_applied_index,
            last_log_term = self.last_applied_term,
        )
        self._send_message(message)

        # capture the message vote
        #self.capture_message_vote(message)

    # message capturing
    def capture_message_vote(self, message):

        # only capture send votes from current node
        if message.sender == self.my_id:

            vote_data = message.to_dict()
            json_file = "vote_request.json"

            # Overwrite the JSON file with the latest vote request
            with open(json_file, "w") as f:
                json.dump([vote_data], f, indent=4)

    def _send_vote(self, candidate, vote_granted=True):
        message = RequestVotesMessage(
            type_ =   MessageType.RequestVotes, 
            term =   self.current_term,
            sender = self.my_id,
            receiver = candidate, 
            direction = MessageDirection.Response, 
            candidate_id = candidate, 
            last_log_index = self.last_applied_index,
            last_log_term = self.last_applied_term,
            results = RequestVotesResults(
                term = self.current_term,
                vote_granted = vote_granted
            )
        )
        self._send_message(message)
        self.voted_for = candidate

    def _send_heartbeat(self):
        message = AppendEntriesMessage(
            type_ = MessageType.Heartbeat,
            term = self.current_term,
            sender = self.my_id,
            receiver = None,
            direction = MessageDirection.Request,
            leader_id = self.my_id,
            prev_log_index = None,
            prev_log_term = None,
            entries = None,
            leader_commit = self.commit_index
        )
        self._send_message(message)

    def _send_append_entries(self, index, term, entries, receiver=None):
        message = AppendEntriesMessage(
            type_ = MessageType.AppendEntries,
            term = self.current_term,
            sender = self.my_id,
            receiver = receiver,
            direction = MessageDirection.Request,
            leader_id = self.my_id,
            prev_log_index = index,
            prev_log_term = term,
            entries = entries,
            leader_commit = self.commit_index
        )
        self._send_message(message)
    
    def _send_committal(self, index, receiver=None):
        message = AppendEntriesMessage(
            type_ = MessageType.Committal,
            term = self.current_term,
            sender = self.my_id,
            receiver = receiver,
            direction = MessageDirection.Request,
            leader_id = self.my_id,
            prev_log_index = self.last_applied_index,
            prev_log_term = self.last_applied_term,
            entries = None,
            leader_commit = self.commit_index
        )
        self._send_message(message)

    def _send_acknowledge(self, receiver, success, entry=None):
        message = AppendEntriesMessage(
            type_ = MessageType.Acknowledge,
            term = self.current_term,
            sender = self.my_id,
            receiver = receiver,
            direction = MessageDirection.Response,
            leader_id =self.leader_id ,
            prev_log_index = self.last_applied_index,
            prev_log_term = self.last_applied_term,
            entries = entry,
            leader_commit = self.commit_index, 
            results = AppendEntriesResults(
                term = self.current_term,
                success = success
            ) 
        )
        self._send_message(message)

    def _send_client_request(self, receiver, entry):
        message = AppendEntriesMessage(
            type_ = MessageType.ClientRequest,
            term = self.current_term,
            sender = self.my_id,
            receiver = receiver,
            direction = MessageDirection.Response,
            leader_id =self.leader_id ,
            prev_log_index = self.last_applied_index,
            prev_log_term = self.last_applied_term,
            entries = entry,
            leader_commit = self.commit_index
        )
        self._send_message(message)

def test_failures():
    '''
        test_failures: Creates a bunch of nodes and then crashes half of them. 
            A leader should emerge after the crash. 
    '''
    # Create the address book with x number of nodes
    d = {'leader':{'ip': local_ip,
            'port': '5553'}}

    node_num = 1
    for p in range(start_port, start_port+total_nodes):
        name = 'node' + str(node_num)
        d[str(name)] = { 
            'ip': local_ip,
            'port': str(p)
        }
        node_num = node_num + 1
        
    with open(address_book_fname, 'w') as outfile:
        json.dump(d, outfile)

    # Create and start the sentinals
    s = []
    node_num = 1
    for p in range(start_port, start_port+total_nodes):
        name = 'node' + str(node_num)
        s.append(RaftNode(address_book_fname, name, 'follower'))
        node_num = node_num + 1
    for n in s:
        n.start()
    time.sleep(2)

    # Make some requests
    for i in range(10):
        s[0].client_request(i)
    time.sleep(3)

    # Pause about half of them, including the leader
    l = [n for n in s if (n.check_role() == 'leader')][0]
    l.pause()
    num_to_kill = int(old_div(total_nodes, 2)) - 1
    for n in s:
        num_to_kill = num_to_kill - 1
        if num_to_kill == 0:
            break
        else:
            n.pause()
    time.sleep(5)

    # Unpause them
    for n in s:
        n.un_pause()
    time.sleep(5)

    # Need to do this before closing
    for n in s:
        n.stop() 

if __name__ == '__main__':
    test_failures()