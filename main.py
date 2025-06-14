import os
import json
import hashlib
import time
import threading
import sys
import lmdb
import base64
import socks
import socket
import stem
import requests
import quantcrypt.kem
from stem.control import Controller
from cryptography.fernet import Fernet
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QFormLayout, QHBoxLayout, QComboBox, QStackedWidget
)

# File paths for individual credential storage
USER_FILE = "username.json"  # ✅ Converts to JSON for structured storage
PUBLIC_KEY_FILE = "public_key.bin"
PRIVATE_KEY_FILE = "private_key.bin"

encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# ✅ Initialize encryption
cipher_key = Fernet.generate_key()  # Replace with a stored key in production
cipher = Fernet(cipher_key)

kem1024 = quantcrypt.kem.MLKEM_1024()

def save_user_data(username, public_key, private_key):
    """Ensures username.json stores valid JSON and prevents corruption."""
    try:
        if not username or not isinstance(username, str):
            print("⚠ WARNING: Attempted to save empty or invalid username! Preventing overwrite.")
            return  

        user_data = {"username": username}  

        # ✅ Validate JSON before saving
        with open(USER_FILE, "w") as file:
            json.dump(user_data, file, indent=4)  
        print(f"✅ DEBUG: Saved Username -> {username}")

        # ✅ Verify the keys before saving
        if not isinstance(public_key, bytes):
            print(f"❌ ERROR: Public Key is not in bytes format. Current format: {type(public_key)}")
        if not isinstance(private_key, bytes):
            print(f"❌ ERROR: Private Key is not in bytes format. Current format: {type(private_key)}")

        # ✅ Write binary keys separately with logging
        if isinstance(public_key, bytes):
            with open(PUBLIC_KEY_FILE, "wb") as file:
                file.write(public_key)
            print(f"✅ DEBUG: Successfully wrote Public Key ({len(public_key)} bytes)")

        if isinstance(private_key, bytes):
            with open(PRIVATE_KEY_FILE, "wb") as file:
                file.write(private_key)
            print(f"✅ DEBUG: Successfully wrote Private Key ({len(private_key)} bytes)")

    except Exception as e:
        print(f"❌ ERROR: Failed to save user data: {e}")

def load_user_data():
    """Loads stored credentials securely from JSON and binary files without modifying them."""
    
    # ✅ Debugging file existence
    if not os.path.exists(USER_FILE):
        print(f"❌ ERROR: {USER_FILE} not found.")
    if not os.path.exists(PUBLIC_KEY_FILE):
        print(f"❌ ERROR: {PUBLIC_KEY_FILE} not found.")
    if not os.path.exists(PRIVATE_KEY_FILE):
        print(f"❌ ERROR: {PRIVATE_KEY_FILE} not found.")

    try:
        # ✅ Ensure username.json exists before reading
        if not os.path.exists(USER_FILE) or os.path.getsize(USER_FILE) == 0:
            print("⚠ DEBUG: username.json is missing or empty. Returning default empty values.")
            return {"username": "", "public_key": b"", "private_key": b""}

        # ✅ Read username.json safely
        with open(USER_FILE, "r") as file:
            content = file.read().strip()
            print(f"DEBUG: username.json Raw Content: {repr(content)}")

            # ✅ If content is raw text instead of valid JSON, return empty username
            if content and not content.startswith("{"):
                print("❌ ERROR: username.json is incorrectly formatted. Returning default empty values.")
                return {"username": "", "public_key": b"", "private_key": b""}

            user_data = json.loads(content)

        username = user_data.get("username", "")
        print(f"✅ DEBUG: Loaded Username: {repr(username)}")

        # ✅ Ensure public and private key files exist before reading
        if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
            print("❌ ERROR: One or both key files are missing! Returning default empty keys.")
            return {"username": username, "public_key": b"", "private_key": b""}

        with open(PUBLIC_KEY_FILE, "rb") as file:
            public_key = file.read()

        with open(PRIVATE_KEY_FILE, "rb") as file:
            private_key = file.read()

        print(f"✅ DEBUG: Loaded Public Key Length: {len(public_key)} bytes")
        print(f"✅ DEBUG: Loaded Private Key Length: {len(private_key)} bytes")

        return {"username": username, "public_key": public_key, "private_key": private_key}

    except json.JSONDecodeError:
        print("❌ ERROR: Invalid JSON format in username.json! Returning default empty values.")
        return {"username": "", "public_key": b"", "private_key": b""}
    except Exception as e:
        print(f"❌ ERROR: Failed to load user data: {e}")
        return {"username": "", "public_key": b"", "private_key": b""}

def generate_keypair():
    """Generate quantum-safe public and private keys using QuantCrypt."""
    kem_instance = quantcrypt.kem.MLKEM_1024()
    public_key, private_key = kem_instance.keygen()

    return public_key, private_key  # ✅ Return raw binary keys for direct storage

def initialize_blockchain(username, public_key):
    """Creates a blockchain instance and stores the Genesis Block, ensuring raw data storage."""
    blockchain = Blockchain(username, public_key)

    if not blockchain.chain:
        genesis_block = Block(
            block_id="Genesis",
            username=username,
            public_key=public_key,
            previous_hash="0"
        )

        blockchain.store_block(genesis_block)
        print("DEBUG: Genesis Block created and stored successfully.")

    blockchain.load_chain()
    if not blockchain.chain:
        print("ERROR: Blockchain storage failed—no blocks found!")
        return None  

    print(f"DEBUG: Blockchain now contains {len(blockchain.chain)} blocks.")
    return blockchain

def get_torrc_path():
    """Find the correct Tor config path for Windows/Linux/macOS."""
    user_home = os.path.expanduser("~")

    if os.name == "nt":
        torrc_path = os.path.join(user_home, "AppData", "Roaming", "tor", "torrc")
    else:
        torrc_path = "/etc/tor/torrc"

    return torrc_path

def ensure_torrc_exists():
    """Creates torrc file and ensures the hidden service directory exists."""
    torrc_path = get_torrc_path()

    # Determine HiddenServiceDir based on OS
    if os.name == "nt":
        hidden_service_dir = os.path.join(os.environ["APPDATA"], "tor", "my_hidden_service")
    else:
        hidden_service_dir = "/var/lib/tor/my_hidden_service"

    # Make sure the directory exists before writing to torrc
    if not os.path.exists(hidden_service_dir):
        print(f"Creating hidden service directory: {hidden_service_dir}...")
        os.makedirs(hidden_service_dir)

    # Write the configuration file if missing
    if not os.path.exists(torrc_path):
        print(f"Creating missing torrc file at {torrc_path}...")
        with open(torrc_path, "w") as f:
            f.write(f"""SOCKSPort 9050
ControlPort 9051
HTTPTunnelPort 9080
HiddenServiceDir {hidden_service_dir}
HiddenServicePort 80 127.0.0.1:5000
""")
        print("Tor configuration initialized with a valid hidden service.")

    return torrc_path

class BaseBlock:
    """Base class for all blockchain blocks."""
    def __init__(self, previous_hash="0"):
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Computes block hash based on standard attributes."""
        data = f"{self.timestamp}{self.previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

class Block:
    """Represents a basic blockchain block."""
    def __init__(self, block_id, username, public_key, previous_hash="0", timestamp=None):
        self.block_id = block_id
        self.username = username
        self.public_key = public_key
        self.previous_hash = previous_hash
        self.timestamp = timestamp if timestamp else str(int(time.time()))
        self.hash = self.calculate_hash()  # ✅ Make sure this method exists

    def calculate_hash(self):
        """Computes a secure hash for the block using SHA-256."""
        data = f"{self.block_id}{self.username}{self.public_key}{self.timestamp}{self.previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

class PostBlock(BaseBlock):
    """Defines a block where 'posts' are stored securely."""
    def __init__(self, block_id, sender, title, body, tags, link, previous_hash=""):
        print("Initializing PostBlock...")
        self.block_id = block_id  # ✅ Properly set block_id to "Post"
        self.sender = sender
        self.title = title
        self.body = body
        self.tags = tags
        self.link = link
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.nonce = self.generate_nonce()  # Prevents replay attacks
        self.hash = self.calculate_hash()
        self.signature = self.sign_block()  # MLKEM_1024 Digital Signature
        print(f"✅ DEBUG: PostBlock '{self.block_id}' successfully created.")

    def generate_nonce(self):
        """Generates a random nonce to prevent duplicate block attacks."""
        nonce = hashlib.sha256(str(time.time()).encode()).hexdigest()
        print(f"Generated nonce: {nonce}")
        return nonce

    def calculate_hash(self):
        """Computes hash for the block, including timestamp and nonce."""
        data = f"{self.sender}{self.title}{self.body}{self.tags}{self.link}{self.timestamp}{self.nonce}{self.previous_hash}"
        hash_value = hashlib.sha256(data.encode()).hexdigest()
        print(f"Computed hash: {hash_value}")
        return hash_value

    def sign_block(self):
        """Generates a quantum-safe digital signature using MLKEM_1024."""
        print("Signing block with MLKEM_1024...")
        try:
            kem_instance = quantcrypt.kem.MLKEM_1024()  # Instantiate encryption module
            public_key, private_key = kem_instance.keygen()
            signature = kem_instance.encaps(public_key)  # Encrypt data for verification
            print("Block signed successfully.")
            return signature
        except Exception as e:
            print(f"Error signing block: {e}")
            return None
        
class Blockchain:
    def __init__(self, username, public_key, db_path="blockchain_db"):
        self.env = lmdb.open(db_path, max_dbs=1, sync=True, map_size=10485760)
        self.username = username
        self.public_key = public_key
        self.post_balance = 0
        self.countdown = 60  # Reward countdown in seconds
        self.node_active = False
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.lock = threading.Lock()
        self.chain = []

        #self.start_rewarding()

        # ✅ Validate blockchain existence before loading
        if not self.has_genesis_block():
            print("ERROR: Blockchain missing or uninitialized!")
        else:
            print("DEBUG: Blockchain found—loading existing chain...")
            self.load_chain()

    def has_genesis_block(self):
        """Checks if the blockchain has a Genesis Block stored by verifying any block presence."""
        try:
            with self.env.begin() as txn:
                cursor = txn.cursor()
                return cursor.first()
        except Exception as e:
            print(f"ERROR: Failed to check Genesis Block: {e}")
            return False

    def add_block(self, block):
        """Stores a block in the blockchain with proper validation before appending."""
        with self.lock:
            previous_hash = self.chain[-1].hash if self.chain else "0"
            block.previous_hash = previous_hash
            block.hash = block.calculate_hash()

            # ✅ Ensure `block_id` is correctly formatted before storage
            if not isinstance(block.block_id, str):
                print(f"❌ ERROR: Block ID is not a string! Type: {type(block.block_id)}")
                return False

            # ✅ Ensure successful storage before modifying chain
            if self.store_block(block):
                self.chain.append(block)
                print(f"✅ DEBUG: Block '{block.block_id}' successfully added to blockchain.")
            else:
                print("❌ ERROR: Block storage failed. Not appending to blockchain.")

    def store_block(self, block):
        """Stores blockchain data in LMDB while ensuring bytes fields are properly converted for JSON compatibility."""
        safe_block = block.__dict__.copy()

        for key, value in safe_block.items():
            if isinstance(value, bytes):
                print(f"DEBUG: Converting bytes field '{key}' to Base64.")
                safe_block[key] = base64.b64encode(value).decode("utf-8")  # ✅ Convert bytes to Base64

            elif isinstance(value, tuple):
                print(f"DEBUG: Converting tuple field '{key}' to a list of Base64 strings.")
                safe_block[key] = [base64.b64encode(item).decode("utf-8") if isinstance(item, bytes) else str(item) for item in value]  # ✅ Convert tuple to a list of Base64 strings
        
        try:
            print(f"DEBUG: Preparing to store Block {safe_block['block_id']}...")

            with self.env.begin(write=True) as txn:
                block_key = safe_block["hash"].encode("utf-8")
                block_value = json.dumps(safe_block).encode("utf-8")  # ✅ No raw bytes present now

                txn.put(block_key, block_value)  # ✅ Store JSON block in LMDB
                txn.commit()  # ✅ Ensure persistence

            print(f"✅ DEBUG: Block {safe_block['block_id']} stored successfully.")
            return True  # ✅ Return success status

        except lmdb.Error as e:
            print(f"❌ ERROR: Failed to store block in LMDB: {e}")
            return False  # ✅ Return failure status

    def store_reward_transaction(self, amount):
        """Stores reward transaction in LMDB to ensure fairness."""
        reward_entry = {
            "id": "Reward",
            "username": self.username,
            "amount": amount,
            "timestamp": time.time(),
            "nonce": hashlib.sha256(str(time.time()).encode()).hexdigest()  # Prevents replay attacks
        }
        with self.env.begin(write=True) as txn:
            txn.put(f"reward_{self.username}_{reward_entry['timestamp']}".encode(), json.dumps(reward_entry).encode())
        
    def load_chain(self):
        """Loads blockchain from LMDB storage, ensuring valid initialization."""
        self.chain = []
        blockchain_users = {}

        try:
            with self.env.begin() as txn:
                cursor = txn.cursor()
                if not cursor.first():
                    print("⚠ DEBUG: No blockchain data found. Checking existing records...")
                    return {}

                for key, raw_value in cursor:
                    try:
                        block_data = json.loads(raw_value.decode())

                        for field, val in block_data.items():
                            if isinstance(val, str) and all(c in "0123456789abcdefABCDEF" for c in val):
                                try:
                                    block_data[field] = bytes.fromhex(val)
                                except ValueError:
                                    pass  # Keep as string if conversion fails

                        if block_data.get("block_id") == "Genesis" or block_data.get("block_id") == "Account":
                            username = block_data.get("username", "")
                            public_key = block_data.get("public_key", b"")

                            if username and public_key:
                                blockchain_users[username] = public_key
                            else:
                                print(f"⚠ WARNING: Found Genesis Block but no stored user credentials!")

                    except Exception as e:
                        print(f"ERROR: Failed to parse blockchain entry {key.decode()}: {e}")

            if not blockchain_users:
                print("⚠ DEBUG: Blockchain exists but contains no user records!")

            print(f"✅ DEBUG: Blockchain loaded with {len(self.chain)} blocks.")
            return blockchain_users

        except Exception as e:
            print(f"❌ ERROR: Failed to load blockchain: {e}")
            return {}

    def start_rewarding(self):
        """Starts the reward thread if not already running."""
        def reward_cycle():
            while not self.reward_stop_event.is_set():
                if self.node_active:
                    for _ in range(self.countdown):
                        if self.reward_stop_event.is_set():
                            return
                        time.sleep(1)
                        with self.lock:
                            self.countdown -= 1

                    with self.lock:
                        self.post_balance += 10
                        self.countdown = 60
                        self.store_reward_transaction(10)
                        print(f"Node [{self.username}] rewarded: +10 posts (Total: {self.post_balance})")
                else:
                    time.sleep(1)  # Avoid tight loop if node is off

        # Start a new thread only if not already running
        if not hasattr(self, "reward_thread") or not self.reward_thread.is_alive():
            self.reward_stop_event = threading.Event()
            self.reward_thread = threading.Thread(target=reward_cycle)
            self.reward_thread.start()

    def toggle_node(self, status):
        """Starts or stops the node and reward mechanism."""
        with self.lock:
            self.node_active = status

            if status:
                self.start_rewarding()
            else:
                self.countdown = 60
                if hasattr(self, "reward_stop_event"):
                    self.reward_stop_event.set()

    def display_chain(self):
        """Displays all stored blockchain transactions securely."""
        try:
            with self.env.begin() as txn:
                cursor = txn.cursor()
                for key, value in cursor:
                    raw_data = value.decode()
                    print(f"Raw Data from DB: {raw_data}")  # Debugging output
                    block_data = json.loads(raw_data)

                    # Identify whether this is a post or a reward/account entry
                    if "sender" in block_data and "title" in block_data:  # PostBlock format
                        print(f"[Post] Sender: {block_data['sender']}, Title: {block_data['title']}, Tags: {block_data.get('tags', [])}")
                    elif "username" in block_data and "amount" in block_data:  # Reward/Account format
                        print(f"[Reward] User: {block_data['username']}, Amount: {block_data['amount']}, Timestamp: {block_data['timestamp']}")
                    else:
                        print(f"Unknown entry format: {block_data}")  # Handle unexpected data
        except json.JSONDecodeError:
            print("Error: Unable to decode JSON. Check data format in storage.")
        except Exception as e:
            print(f"Unexpected error displaying chain: {e}")

class BlockchainNode:
    """Manages secure peer networking using Tor Hidden Services."""

    def __init__(self, username, peers=None):
        self.username = username
        self.peers = peers if peers else []
        self.hidden_service = None
        self.running = True  # ✅ Initialize the running flag in constructor

        # Ensure torrc exists before connecting to Tor
        torrc_path = ensure_torrc_exists()
        print(f"Using Tor configuration at: {torrc_path}")

        # Connect to Tor and create hidden service
        try:
            self.tor_controller = Controller.from_port(port=9050)
            self.tor_controller.authenticate()
        except Exception as e:
            print(f"ERROR: Tor connection failed on port 9050. Trying 9051...")
            try:
                self.tor_controller = Controller.from_port(port=9051)
                self.tor_controller.authenticate()
            except Exception as e:
                print(f"ERROR: Tor connection completely failed: {e}")
                return

        self.hidden_service = self.create_tor_hidden_service()

        # Start peer discovery process (only if no peers provided)
        if not self.peers:
            print("Starting peer discovery...")
            self.discover_peers()
        else:
            print(f"Using provided peer list: {self.peers}")

        # Start post synchronization
        self.sync_thread = threading.Thread(target=self.sync_posts)
        self.sync_thread.start()

    def create_tor_hidden_service(self):
        """Registers a new Tor Hidden Service with a correct directory."""
        print(f"Initializing Tor hidden service for {self.username}...")

        try:
            hidden_service_dir = f"/var/lib/tor/{self.username}_hidden_service"
            if os.name == "nt":
                hidden_service_dir = os.path.join(os.environ["APPDATA"], "tor", f"{self.username}_hidden_service")

            with self.tor_controller:
                self.tor_controller.set_options({
                    "HiddenServiceDir": hidden_service_dir,
                    "HiddenServicePort": "80 127.0.0.1:5000"
                })
                onion_address = self.tor_controller.get_info("HiddenServiceDir")
                print(f"Hidden Service created: {onion_address}.onion")
                return onion_address + ".onion"
        except Exception as e:
            print(f"Error creating hidden service: {e}")
            return None

    def encrypt_peer_list(self):
        """Encrypts and securely stores peer list without Base64 encoding."""
        encrypted_peers = cipher.encrypt(json.dumps(self.peers).encode())  # ✅ Encrypt peer list directly
        print(f"Encrypted peer list stored successfully.")
        return encrypted_peers

    def discover_peers(self):
        """Find active blockchain nodes using Tor. Defaults to genesis if none found."""
        print("Discovering peer nodes...")

        if not self.peers:
            print("No peer nodes found. Using genesis block as bootstrap point.")
            self.peers = ["genesis.onion"]
        else:
            self.peers = self.query_tor_network()
            print(f"Active peers found: {self.peers}")

    def query_tor_network(self):
        """Queries the Tor network for active blockchain nodes."""
        try:
            response = requests.get("http://hidden_service.onion/api/peers", timeout=10)
            peer_list = response.json()
            
            if not peer_list:
                print("No active peers found. Falling back to genesis node...")
                return ["genesis.onion"]
            
            print(f"Retrieved peer list: {peer_list}")
            return peer_list
        except requests.exceptions.RequestException as e:
            print(f"Error querying Tor network: {e}")
            return ["genesis.onion"]

    def sync_posts(self):
        """Periodically sync blockchain posts across peer nodes, but stops when requested."""
        while self.running:
            time.sleep(10)  # Sync every 10 seconds
            print("Syncing posts from peers...")

            if not self.running:
                print("DEBUG: BlockchainNode sync process stopped.")
                return  # ✅ Exits function instead of looping further

            for peer in self.peers:
                try:
                    response = requests.get(f"http://{peer}/api/latest_posts")
                    posts = response.json()
                    print(f"Synced {len(posts)} posts from {peer}")
                except Exception as e:
                    print(f"Failed to sync posts from {peer}: {e}")

    def wait_for_sync(self):
        """Ensures blockchain sync runs only when needed."""
        print("DEBUG: Waiting for blockchain sync to complete...")
        time.sleep(5)  # Simulate short sync delay before launching
        print("DEBUG: Blockchain sync completed.")

    def stop(self):
        """Stops blockchain syncing immediately and terminates sync thread."""
        print("DEBUG: Stopping blockchain node...")
        self.running = False  # ✅ Properly stops sync loop

        if self.sync_thread and self.sync_thread.is_alive():
            print("DEBUG: Terminating sync thread...")
            self.sync_thread.join(timeout=1)  # ✅ Wait for thread to exit
            self.sync_thread = None  # ✅ Remove thread reference for cleanup

class BlockchainApp(QMainWindow):
    def __init__(self, username, public_key, private_key, post_balance):
        super().__init__()

        print("DEBUG: Inside BlockchainApp constructor...")

        # ✅ Ensure username remains a string
        self.username = username.decode() if isinstance(username, bytes) else str(username)

        # ✅ Debug: Print raw public and private keys before processing
        print(f"DEBUG: Raw Public Key (Before Processing): {public_key}")
        print(f"DEBUG: Raw Private Key (Before Processing): {private_key}")

        # ✅ Ensure public and private keys remain raw binary (no hex or encoding conversion)
        if not isinstance(public_key, bytes):
            print(f"ERROR: Public key should be raw binary, but received incorrect format: {type(public_key)}")
            raise ValueError("Invalid public key format: Must be bytes")

        if not isinstance(private_key, bytes):
            print(f"ERROR: Private key should be raw binary, but received incorrect format: {type(private_key)}")
            raise ValueError("Invalid private key format: Must be bytes")

        self.public_key = public_key
        self.private_key = private_key

        self.post_balance = post_balance
        print(f"DEBUG: Final Processed Public Key (Hex for Debugging): {self.public_key.hex()}")

        print("DEBUG: Initializing blockchain...")
        self.blockchain = Blockchain(self.username, self.public_key.hex())  # ✅ Store public key in hex for blockchain
        print("DEBUG: Blockchain initialized successfully.")

        print("DEBUG: Setting up main window...")
        self.setWindowTitle("Lampchain Application")
        self.setGeometry(100, 100, 1200, 675)
        print("DEBUG: Main window setup completed.")

        print("DEBUG: Creating UI Tabs...")
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        print("DEBUG: Adding tabs to UI...")
        self.tabs.addTab(self.create_account_tab(), "Account")
        self.tabs.addTab(self.create_post_tab(), "Post")
        self.tabs.addTab(QWidget(), "Posts")  # Placeholder
        self.tabs.addTab(self.create_blockchain_tab(), "Blockchain")
        self.tabs.addTab(QWidget(), "Tagged")  # Placeholder
        self.tabs.addTab(self.create_send_tab(), "Send")  # Placeholder
        self.tabs.addTab(self.create_search_tab(), "Search")
        self.tabs.addTab(QWidget(), "Stats")  # Placeholder
        self.tabs.addTab(QWidget(), "Help")  # Placeholder

        print("DEBUG: Assigning layout to tabs...")
        self.tabs.setLayout(QVBoxLayout())  # ✅ Explicitly set layout
        print("DEBUG: Tabs layout assigned.")

        print("DEBUG: BlockchainApp UI setup completed.")
        global start_time
        # Stop stopwatch
        end_time = time.time()

        # Calculate elapsed time
        elapsed_time = end_time - start_time
        print(f"Execution time: {elapsed_time:.4f} seconds")

    def closeEvent(self, event):
        """Stops blockchain node when user closes the app."""
        print("DEBUG: Closing BlockchainApp... shutting down blockchain node.")

        if hasattr(self.blockchain, "node") and self.blockchain.node:
            print("DEBUG: Stopping blockchain process...")
            self.blockchain.node.stop()

        event.accept()
        print("DEBUG: BlockchainApp closed successfully.")

    def create_account_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        print("DEBUG: Creating Account Tab...")

        layout.addWidget(QLabel("Username:"))
        username_field = QLineEdit(self.username)
        username_field.setReadOnly(True)
        layout.addWidget(username_field)

        layout.addWidget(QLabel("Public Key:"))
        public_key_field = QLineEdit(self.public_key.hex())  # ✅ Convert binary key to hex for display
        public_key_field.setReadOnly(True)
        layout.addWidget(public_key_field)

        layout.addWidget(QLabel("Private Key:"))
        private_key_field = QLineEdit(self.private_key.hex())  # ✅ Convert binary key to hex for display
        private_key_field.setReadOnly(True)
        layout.addWidget(private_key_field)

        tab.setLayout(layout)
        print("DEBUG: Account Tab successfully created!")
        return tab

    def create_post_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Title:"))
        self.title_input = QLineEdit()
        layout.addWidget(self.title_input)

        layout.addWidget(QLabel("Body:"))
        self.body_input = QTextEdit()
        layout.addWidget(self.body_input)

        layout.addWidget(QLabel("Tags (Optional):"))
        self.tag_inputs = []
        form_layout = QFormLayout()
        for i in range(10):
            tag_input = QLineEdit()
            self.tag_inputs.append(tag_input)
            form_layout.addRow(f"Tag {i+1}:", tag_input)
        layout.addLayout(form_layout)

        layout.addWidget(QLabel("Link (Optional):"))
        self.link_input = QLineEdit()
        layout.addWidget(self.link_input)

        self.submit_button = QPushButton("Submit Post")
        self.submit_button.clicked.connect(self.submit_post)
        layout.addWidget(self.submit_button)

        tab.setLayout(layout)
        return tab

    def create_blockchain_tab(self):
        print("DEBUG: Creating Blockchain Tab...")
        tab = QWidget()
        layout = QVBoxLayout()

        self.node_button = QPushButton("Start Node")
        self.node_button.clicked.connect(self.toggle_node)
        layout.addWidget(self.node_button)

        tab.setLayout(layout)
        print("DEBUG: Blockchain Tab successfully created!")
        return tab

    def create_send_tab(self):
        print("DEBUG: Creating Send Tab...")
        tab = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Send to Username or Public Key:"))
        self.recipient_input = QLineEdit()
        layout.addWidget(self.recipient_input)

        layout.addWidget(QLabel("Amount of posts to send:"))
        self.amount_input = QLineEdit()
        layout.addWidget(self.amount_input)

        self.send_button = QPushButton("Send Posts")
        self.send_button.clicked.connect(self.send_posts)
        layout.addWidget(self.send_button)

        tab.setLayout(layout)
        print("DEBUG: Send Tab successfully created!")
        return tab

    def send_posts(self):
        print("DEBUG: Starting post send process...")
        recipient = self.recipient_input.text().strip()
        amount = self.amount_input.text().strip()

        if not amount.isdigit():
            print("ERROR: Amount must be an integer.")
            return

        amount = int(amount)

        if amount > self.post_balance:
            print("ERROR: Insufficient post balance.")
            return

        print(f"DEBUG: Sending {amount} posts to {recipient}...")
        transaction_block = PostBlock(
            id_type="Post Send",
            sender=self.username,
            body=f"Sending {amount} posts to {recipient}",
            tags=[],
            link="",
            previous_hash=self.blockchain.get_latest_block().hash if self.blockchain.chain else "0",
        )

        self.blockchain.add_block(transaction_block)
        print("DEBUG: Posts sent successfully.")

    def create_search_tab(self):
        print("DEBUG: Creating Search Tab...")
        tab = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Search for posts:"))
        self.search_input = QLineEdit()
        layout.addWidget(self.search_input)

        self.search_button = QPushButton("Search")
        layout.addWidget(self.search_button)

        tab.setLayout(layout)
        print("DEBUG: Search Tab successfully created!")
        return tab

    def submit_post(self):
        """Submits a post, ensuring 'Post' is assigned as the block_id."""
        try:
            block_id = "Post"  # ✅ Assigning block_id

            sender = self.blockchain.username
            title = self.title_input.text().strip()
            body = self.body_input.toPlainText().strip()
            tags = [tag.text().strip() for tag in self.tag_inputs if tag.text()]
            link = self.link_input.text().strip()

            # ✅ Debugging User Input
            print(f"DEBUG: block_id -> {block_id}")
            print(f"DEBUG: Sender -> {sender}")
            print(f"DEBUG: Title -> {title}")
            print(f"DEBUG: Body -> {body}")
            print(f"DEBUG: Tags -> {tags}")
            print(f"DEBUG: Link -> {link}")

            # ✅ Validate Post Balance
            if self.blockchain.post_balance <= 0:
                print("❌ ERROR: Insufficient post balance to submit.")
                return

            # ✅ Create a new post block with block_id = "Post"
            block = PostBlock(block_id, sender, title, body, tags, link)
            print(f"✅ DEBUG: PostBlock instance created successfully with block_id '{block.block_id}'.")

            # ✅ Add the block to the blockchain
            self.blockchain.add_block(block)
            print(f"✅ DEBUG: Block '{block.block_id}' added to blockchain.")

            # ✅ Deduct post balance after submission
            self.blockchain.post_balance -= 1
            print(f"✅ DEBUG: Updated posts balance -> {self.blockchain.post_balance}")

            # ✅ Display current chain for verification
            self.blockchain.display_chain()
            print("✅ DEBUG: Blockchain displayed successfully.")

        except AttributeError as e:
            print(f"❌ ERROR: Attribute missing or incorrectly referenced: {e}")
        except TypeError as e:
            print(f"❌ ERROR: Type mismatch encountered: {e}")
        except Exception as e:
            print(f"❌ ERROR: Unexpected exception occurred: {e}")

    def toggle_node(self):
        """Toggles blockchain node state, ensuring error handling and debugging are included."""
        try:
            print("DEBUG: Attempting to toggle blockchain node state...")

            # ✅ Verify that blockchain instance is available
            if not hasattr(self, "blockchain") or self.blockchain is None:
                print("❌ ERROR: Blockchain instance not found. Cannot toggle node.")
                return

            # ✅ Debug current state before toggling
            print(f"DEBUG: Current Node Active Status -> {self.blockchain.node_active}")

            if self.blockchain.node_active:
                self.blockchain.toggle_node(False)
                self.node_button.setText("Start Node")
                print("✅ DEBUG: Blockchain node stopped successfully.")
            else:
                self.blockchain.toggle_node(True)
                self.node_button.setText("Stop Node")
                print("✅ DEBUG: Blockchain node started successfully.")

        except AttributeError as e:
            print(f"❌ ERROR: Attribute missing or incorrectly referenced: {e}")
        except TypeError as e:
            print(f"❌ ERROR: Type mismatch encountered: {e}")
        except Exception as e:
            print(f"❌ ERROR: Unexpected exception occurred: {e}")

class SignUpSignIn(QWidget):
    """Sign-Up and Sign-In UI handling user authentication."""
    def __init__(self, app_callback):
        super().__init__()
        self.app_callback = app_callback  # Callback to launch BlockchainApp
        self.setWindowTitle("Lampchain Authentication")
        self.setGeometry(100, 100, 800, 450)

        layout = QVBoxLayout()

        # Sign-up Section (Left Side)
        layout.addWidget(QLabel("Sign-Up (New Users)"))
        self.signup_username = QLineEdit()
        self.signup_button = QPushButton("Sign Up")
        self.signup_button.clicked.connect(self.handle_signup)

        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.signup_username)
        layout.addWidget(self.signup_button)

        # Sign-in Section (Right Side)
        layout.addWidget(QLabel("Sign-In (Existing Users)"))
        self.signin_username = QLineEdit()
        self.signin_private_key = QLineEdit()
        self.signin_private_key.setEchoMode(QLineEdit.Password)
        self.signin_button = QPushButton("Sign In")
        self.signin_button.clicked.connect(self.handle_signin)

        layout.addWidget(QLabel("Username or Public Key:"))
        layout.addWidget(self.signin_username)
        layout.addWidget(QLabel("Private Key:"))
        layout.addWidget(self.signin_private_key)
        layout.addWidget(self.signin_button)

        self.setLayout(layout)

    def handle_signup(self):
        print("DEBUG: Starting signup process...")

        username = self.signup_username.text().strip()
        print(f"DEBUG: User entered username: {username}")

        user_data = load_user_data()
        print(f"DEBUG: Loaded user data: {user_data}")

        # ✅ Check username BOTH in local database and blockchain
        if username in user_data and user_data["username"]:
            print("ERROR: Username already exists.")
            return

        print("DEBUG: Generating public/private key pair...")
        public_key, private_key = generate_keypair()  # ✅ Generate keys FIRST

        print(f"DEBUG: Generated keys:\nPublic Key: {public_key}\nPrivate Key: {private_key}")

        # ✅ First, check if the blockchain folder exists
        blockchain_exists = os.path.exists("blockchain_db")
        print(f"DEBUG: Checking blockchain folder existence: {blockchain_exists}")

        # ✅ Then, check if blockchain has stored data
        has_data = False  # Assume no data initially
        if blockchain_exists:
            print("DEBUG: Blockchain folder found. Checking for stored blockchain records...")

            try:
                blockchain = Blockchain()  # ✅ Initialize blockchain without username to load all data
                blockchain_users = blockchain.load_chain()  # ✅ Retrieve stored blockchain usernames

                if blockchain_users:
                    has_data = True  # ✅ If user records exist, set flag to True
                    print(f"✅ DEBUG: Blockchain contains {len(blockchain_users)} stored user records.")
                else:
                    print("⚠ WARNING: Blockchain folder exists, but no valid user records found!")

            except Exception as e:
                print(f"❌ ERROR: Failed to check blockchain contents: {e}")
                has_data = False  # ✅ Prevent crash due to blockchain failure

        # ✅ Condition now checks BOTH folder existence and stored blockchain data
        if blockchain_exists and has_data:
            print("✅ DEBUG: Blockchain exists and contains valid user data. Proceeding normally.")
        else:
            print("⚠ DEBUG: Blockchain is missing or empty. Running initialization...")
            try:
                blockchain = initialize_blockchain(username, public_key.hex())
                print("✅ DEBUG: Blockchain initialized successfully.")
            except Exception as e:
                print(f"❌ ERROR: Blockchain initialization failed: {e}")
                return
            
        print("DEBUG: Saving user data securely...")

        try:
            # ✅ Use save_user_data instead of manually writing files
            save_user_data(username, public_key, private_key)

            print("✅ DEBUG: User data successfully stored.")

        except Exception as e:
            print(f"ERROR: Failed to save user data: {e}")
            return

        print(f"SUCCESS: Account created!\nUsername: {username}")

        print("DEBUG: Launching blockchain app callback...")
        self.app_callback(username, public_key, private_key)

        # ✅ Ensure the application does not exit prematurely
        print("DEBUG: Keeping application active...")
        app.exec_()  # ✅ Prevents app from closing after signup
        print("DEBUG: Callback execution completed.")

    def handle_signin(self):
        """Handles user sign-in authentication using blockchain records, ensuring keys are formatted correctly and user data is stored properly."""
        print("\n===== DEBUG: Starting sign-in process =====")

        # ✅ Retrieve input values
        user_input = self.signin_username.text().strip()
        private_key_input = self.signin_private_key.text().strip()
        print(f"DEBUG: Received User Input -> Username/Public Key: {user_input}, Private Key: (hidden)")

        # ✅ Validate input presence
        if not user_input or not private_key_input:
            print("❌ ERROR: Username/Public Key and Private Key are required.")
            return

        # ✅ Load blockchain records
        print("DEBUG: Fetching blockchain records...")
        blockchain_users = self.blockchain.load_chain()
        print(f"DEBUG: Loaded {len(blockchain_users)} users from the blockchain.")

        # ✅ Convert stored public keys to hex for accurate matching
        blockchain_users_hex = {user: (key.hex() if isinstance(key, bytes) else key) for user, key in blockchain_users.items()}
        print(f"DEBUG: Converted Blockchain Public Keys to Hex: {blockchain_users_hex}")

        # ✅ Determine whether to search by username or public key
        username = None
        public_key = None
        if len(user_input) <= 100:
            # 🔹 Input is a username → Search for Genesis or Account block to find the public key
            print(f"DEBUG: Searching blockchain for Genesis/Account record matching username '{user_input}'...")
            if user_input in blockchain_users_hex:
                public_key = blockchain_users_hex[user_input]
                username = user_input
            else:
                print(f"❌ ERROR: Username '{user_input}' not found in blockchain records.")
                return
        else:
            # 🔹 Input is a public key → Verify it exists in blockchain database and retrieve associated username
            print(f"DEBUG: Checking blockchain for direct public key match...")
            matched_user = next((user for user, key in blockchain_users_hex.items() if key == user_input), None)

            if matched_user:
                username = matched_user
                public_key = user_input
            else:
                print(f"❌ ERROR: Public key '{user_input}' not found in blockchain records.")
                return

        print(f"✅ DEBUG: Found Username -> {username}, Public Key -> {public_key}")

        # ✅ Ensure public key is in bytes format before verification
        if isinstance(public_key, str):
            print(f"DEBUG: Converting Public Key '{public_key}' to bytes format...")
            try:
                public_key = bytes.fromhex(public_key)  # Convert hex string to bytes
            except ValueError:
                print(f"❌ ERROR: Failed to convert Public Key '{public_key}' to bytes. Invalid hex format.")
                return
        print(f"DEBUG: Final Public Key Format -> {public_key}")

        # ✅ Ensure private key is in bytes format before verification
        if isinstance(private_key_input, str):
            print(f"DEBUG: Converting Private Key to bytes format...")
            try:
                private_key_input = bytes.fromhex(private_key_input)  # Convert hex string to bytes
            except ValueError:
                print(f"❌ ERROR: Failed to convert Private Key '{private_key_input}' to bytes. Invalid hex format.")
                return
        print(f"DEBUG: Final Private Key Format -> {private_key_input}")

        # ✅ Compare user's input private key with found public key for authentication
        print(f"DEBUG: Comparing Private Key Input with Public Key '{public_key}'...")

        if not verify_keys(public_key, private_key_input):
            print("❌ ERROR: Key verification failed. Sign-in rejected.")
            return

        print(f"🎉 SUCCESS: Signed in as '{username}' with Public Key -> {public_key}")

        # ✅ Convert public key to bytes for storage
        public_key_bin = public_key if isinstance(public_key, bytes) else bytes.fromhex(public_key)

        # ✅ Convert private key to bytes for storage
        private_key_bin = private_key_input if isinstance(private_key_input, bytes) else bytes.fromhex(private_key_input)

        # ✅ Save user credentials using `save_user_data()`
        try:
            save_user_data(username, public_key_bin, private_key_bin)
            print(f"✅ DEBUG: User credentials saved successfully using save_user_data() (Public Key & Private Key stored in binary format)")
        except Exception as e:
            print(f"❌ ERROR: Failed to save user credentials using save_user_data(): {e}")

        # ✅ Launch blockchain app after successful sign-in
        print("DEBUG: Launching BlockchainApp...")
        self.app_callback(username, public_key, private_key_input)  # ✅ Ensure username is passed correctly
        print("DEBUG: Callback execution completed.")

        print("\n===== DEBUG: Sign-in process completed successfully =====")

# ✅ Function to verify keys using encapsulation & decapsulation
def verify_keys(public_key, secret_key):
    """Verifies if the provided key pair is valid using encapsulation and decapsulation."""
    try:
        # Encapsulate a shared secret with the public key
        cipher_text, shared_secret = kem1024.encaps(public_key)

        # Decapsulate the shared secret with the private key
        shared_secret_copy = kem1024.decaps(secret_key, cipher_text)

        # ✅ Check if decapsulated secret matches original shared secret
        if shared_secret_copy == shared_secret:
            print("✅ DEBUG: Public and Private key pair is valid!")
            return True
        else:
            print("❌ ERROR: Key verification failed! Shared secrets do not match.")
            return False

    except Exception as e:
        print(f"❌ ERROR: Key verification process failed: {e}")
        return False

def authenticate_user(blockchain_instance):
    """Checks LMDB blockchain database and auto-authenticates if credentials match."""
    user_data = load_user_data()  # ✅ Load locally stored user credentials
    blockchain_users = blockchain_instance.load_chain()  # ✅ Load blockchain database for user records

    username = user_data["username"]
    public_key = user_data["public_key"]
    private_key = user_data["private_key"]

    print("===== DEBUG: Authentication Process =====")
    print(f"DEBUG: Loaded Local Username: {repr(username)}")
    print(f"DEBUG: Loaded Local Public Key: {public_key.hex() if isinstance(public_key, bytes) else public_key}")
    print(f"DEBUG: Loaded Local Private Key (First 64 hex chars): {private_key.hex()[:64]}...")

    # ✅ If no blockchain records exist, fallback to manual authentication
    if not blockchain_users:
        print("⚠ DEBUG: No blockchain user records found. Proceeding with manual sign-in.")
        return None, None, None

    # ✅ Check if username exists in blockchain database
    print(f"DEBUG: Checking Blockchain Database for Username: {username}")
    if username not in blockchain_users:
        print(f"❌ DEBUG: Username '{username}' not found in blockchain database. Sign-in required.")
        return None, None, None

    # ✅ Retrieve stored public key from blockchain
    blockchain_public_key = blockchain_users[username]

    print(f"DEBUG: Blockchain Stored Public Key: {blockchain_public_key.hex() if isinstance(blockchain_public_key, bytes) else blockchain_public_key}")

    # ✅ Compare local public key to blockchain public key
    if blockchain_public_key != public_key:
        print(f"❌ DEBUG: Public key mismatch for username '{username}'. Manual authentication required.")
        return None, None, None

    print("✅ DEBUG: Public key matches blockchain record. Verifying private key...")

    # ✅ Verify private key cryptographically
    if verify_keys(public_key, private_key):
        print(f"✅ DEBUG: Private key successfully verified for {username}. Auto-loading BlockchainApp...")
        return username, public_key, private_key
    else:
        print(f"❌ DEBUG: Private key verification failed for {username}. Manual authentication required.")

    return None, None, None

if __name__ == "__main__":
    global start_time
    start_time = time.time()
    
    app = QApplication([])

    # ✅ Load user credentials before initializing blockchain instance
    user_data = load_user_data()
    username = user_data.get("username")
    public_key = user_data.get("public_key")

    # ✅ Initialize Blockchain instance for authentication
    blockchain_instance = Blockchain(username if username else None, public_key if public_key else None)

    def launch_app(username, public_key, private_key):
        """Launch blockchain app after successful authentication."""
        global blockchain_window
        print(f"DEBUG: Launching blockchain app for {username}...")

        try:
            # ✅ Ensure username is correctly formatted
            username = username.decode("utf-8") if isinstance(username, bytes) else str(username)

            # ✅ Ensure public/private keys are in raw binary format
            if not isinstance(public_key, bytes):
                public_key = bytes.fromhex(public_key) if isinstance(public_key, str) else public_key
            if not isinstance(private_key, bytes):
                private_key = bytes.fromhex(private_key) if isinstance(private_key, str) else private_key

            print("DEBUG: Stopping blockchain in SignUpSignIn window...")
            if hasattr(auth_window, "blockchain") and hasattr(auth_window.blockchain, "node"):
                print("DEBUG: Found active blockchain node in SignUpSignIn. Shutting it down.")
                auth_window.blockchain.node.stop()
            else:
                print("DEBUG: No active blockchain node found in SignUpSignIn.")

            print("DEBUG: Creating BlockchainApp instance now...")
            blockchain_window = BlockchainApp(username, public_key, private_key, 0)
            blockchain_window.show()
            print("DEBUG: BlockchainApp UI should be visible now.")

            print("DEBUG: Hiding SignUpSignIn window...")
            auth_window.hide()  # ✅ Hide authentication UI on success
        except Exception as e:
            print(f"ERROR: BlockchainApp failed to launch: {e}")

    # ✅ Attempt Auto-Authentication via Blockchain First
    username, public_key, private_key = authenticate_user(blockchain_instance)

    if username and public_key and private_key:
        # ✅ Auto-launch BlockchainApp if authentication succeeds
        blockchain_window = BlockchainApp(username, public_key, private_key, 0)
        blockchain_window.show()
    else:
        # ✅ Fallback to Manual Authentication via Sign-Up/Sign-In Window
        auth_window = SignUpSignIn(launch_app)
        auth_window.blockchain = blockchain_instance  # ✅ Pass blockchain instance for database queries
        auth_window.show()

    print("DEBUG: Starting main event loop with BlockchainApp...")
    app.exec_()  # ✅ Keeps the app running
    print("DEBUG: Main event loop exited.")


