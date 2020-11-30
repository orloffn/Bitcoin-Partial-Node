import argparse
import socket
import time
import struct
import select
import random
import hashlib
from pprint import PrettyPrinter


_CHOSEN_PEER = ('111.42.74.65', 8333)
_MAGIC = 'f9beb4d9'
_MAX_BLOCK_ID = 650000
_MAX_INV_MESSAGES = 2
_MAX_TXN_COUNT = 5
_MAX_INV_COUNT = 500
HDR_SZ = 24


def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    return int.from_bytes(b, byteorder='little', signed=False)

def get_command(x):
    return str(bytearray([b for b in x[4:16] if b != 0]), encoding='utf-8')


def tx_in_t(b):
    """
    marshal a tx_in datatype from a python dict
    :param b: dict representing tx_in
    :return: bytes
    """
    payload = b''
    payload += b['hash']
    payload += uint32_t(b['index'])
    payload += compactsize_t(b['script_bytes'])
    payload += b['signature_script']
    payload += uint32_t(b['sequence'])
    return payload


def tx_out_t(b):
    """
    marshal a tx_out datatype from a python dict
    :param b: dict representing tx_in
    :return: bytes
    """
    payload = b''
    payload += int64_t(b['value'])
    payload += compactsize_t(b['pub_key_script_bytes'])
    payload += b['pk_script']
    return payload


def tx_message_t(txn):
    """
    marshal a tex message from python dict
    :param txn: dict representing tx message
    :return: txn message bytes
    """
    payload = b''
    payload += uint32_t(txn['version'])
    payload += compactsize_t(txn['tx_in_count'])
    for i in txn['tx_in']:
        payload += tx_in_t(i)
    payload += compactsize_t(txn['tx_out_count'])
    for i in txn['tx_out']:
        payload += tx_out_t(i)
    payload += uint32_t(txn['lock_time'])
    return payload


def get_txIn(b, tx_in_count):
    """
    unmarshal a tx_in datatype to a python dict
    :param b: tx_in bytes
    :param tx_in_count: the number of transactions in the tx_in
    :return: tuple of (<length>, dict)
             length is the number of bytes read
    """
    tx_in = []
    i = 0
    for _ in range(tx_in_count):
        h = b[i:i+32]
        i += 32
        index = unmarshal_uint(b[i:i+4])
        i += 4
        script_bytes_b, script_bytes = unmarshal_compactsize(b[i:])
        i += len(script_bytes_b)
        signature_script = b[i:i+script_bytes]
        i += script_bytes
        sequence = unmarshal_uint(b[i:i+4])
        i += 4

        tx_in.append({
            "hash":h,
            "index":index,
            "script_bytes": script_bytes,
            "signature_script": signature_script,
            "sequence": sequence,
        })

    return i, tx_in


def get_txOut(b, tx_out_count):
    """
    unmarshal a tx_out datatype to a python dict
    :param b: tx_out bytes
    :param tx_out_count: the number of transactions in the tx_out
    :return: tuple of (<length>, dict)
             length is the number of bytes read
    """
    tx_out = []
    i = 0
    for _ in range(tx_out_count):
        value = unmarshal_uint(b[i:i+8])
        i += 8
        pub_key_script_bytes_b, pub_key_script_bytes = unmarshal_compactsize(b[i:])
        i += len(pub_key_script_bytes_b)
        pk_script = b[i:i+pub_key_script_bytes]
        i += pub_key_script_bytes
        tx_out.append({
            "value": value,
            "pub_key_script_bytes": pub_key_script_bytes,
            "pk_script": pk_script,
        })

    return i, tx_out

def read_txns(b, txn_count):
    """
    unmarshal a tx message to a python dict
    :param b: tx message bytes
    :param txn_count: number of transactions in the message
    :return: list of transaction dicts
    """
    transactions = []
    for _ in range(txn_count):
        version = unmarshal_uint(b[:4])
        b = b[4:]
        tx_in_count_b, tx_in_count = unmarshal_compactsize(b)
        b = b[len(tx_in_count_b):]
        tx_in_len, tx_in = get_txIn(b,tx_in_count)
        b = b[tx_in_len:]
        tx_out_count_b, tx_out_count = unmarshal_compactsize(b)
        b = b[len(tx_out_count_b):] 
        tx_out_len, tx_out = get_txOut(b,tx_out_count)
        b = b[tx_out_len:]
        lock_time = unmarshal_uint(b[:4])
        b = b[4:]
        tx = {
            "version": version,
            "tx_in_count": tx_in_count,
            "tx_in": tx_in,
            "tx_out_count": tx_out_count,
            "tx_out": tx_out,
            "lock_time": lock_time,
        }

        transactions.append(tx)
    return transactions


def txns_to_hex(b):
    """
    convert hashes in transaction to hex
    :param b: transactions returned from read_txns
    :return: copy of b with hashes converted to hex
    """
    txns = b
    for tx in range(len(txns)):
        for i in range(len(txns[tx]['tx_in'])):
            txns[tx]['tx_in'][i]['hash'] = txns[tx]['tx_in'][i]['hash'].hex()
            txns[tx]['tx_in'][i]['signature_script'] = \
                txns[tx]['tx_in'][i]['signature_script'].hex()
        for i in range(len(txns[tx]['tx_out'])):
            txns[tx]['tx_out'][i]['pk_script'] = \
                txns[tx]['tx_out'][i]['pk_script'].hex()
    return txns


def read_block(b):
    """
    unmarshal a block message
    :param b: block in bytes
    :return: tuple representation of bluck
    """
    version = b[:4]
    prev_block = bytearray(b[4:36])
    prev_block.reverse()
    root_hash = bytearray(b[36:68])
    root_hash.reverse()
    time = b[68:72]
    nbits = b[72:76]
    nonce = b[76:80]
    b = b[80:]
    txn_b, txn_count = unmarshal_compactsize(b)
    b = b[len(txn_b):]
    txns = read_txns(b, txn_count)
    return version, prev_block, root_hash, time, \
           nbits, nonce, txn_count, txns


def read_inv(b):
    """
    unmarshal an inv message
    :param b: inv message as bytes
    :return: tuple of (<inventory count>, <inventory entries>)
             inventory entries is a list of dicts
    """
    count_b, count_n = unmarshal_compactsize(b)
    payload = b[len(count_b):]
    inventories = []
    for i in range(0, len(payload), 36):
        t = unmarshal_uint(payload[i:i+4])
        h = bytearray(payload[i+4:i+36])
        h.reverse()
        inv = {
            "type": t,
            "hash": h
        }
        inventories.append(inv)
    return count_n, inventories


def print_sending_message(msg):
    """
    print a message before it is sent
    :param msg: the message in bytes
    """
    print('SENDING:')
    print_message(msg)


def print_message(msg, text=None):
    """
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + \
                                     ('' if len(msg) < 60 else '...')))
    payload = msg[HDR_SZ:]
    command = print_header(msg[:HDR_SZ], checksum(payload)[:4])
    if command == 'version':
        print_version_msg(payload)
    elif command == 'inv':
        print_inv(payload)
    elif command == 'getblocks':
        print_getblocks(payload)
    elif command == 'block':
        print_block(read_block(payload))
    elif command == 'merkleblock':
        print_merkleblock(read_merkleblock(payload))
    elif command == 'tx':
        print_transaction(read_txns(payload, 1))
    return command


def print_transaction(txns):
    """
    print the contents of a tx message
    :param txns: the unmarshalled tx message
    """
    print('  TX')
    print('  --------------------------------------------------------')
    if len(txns) > _MAX_TXN_COUNT:
        txns_hex = txns_to_hex(txns[:_MAX_TXN_COUNT])
    else: txns_hex = txns_hex(txns)
    pp = PrettyPrinter()
    for i in pp.pformat(txns_hex).splitlines():
        print('    ' + i[:100] + ('' if len(i) < 100 else '...'))
    if len(txns) > _MAX_TXN_COUNT:
        print('\n    Hiding {} of {} transactions'.format(len(txns)-_MAX_TXN_COUNT, \
                                                    len(txns)))


def print_block(b):
    """
    print the contents of a block message
    :param b: the unmarshalled block message
    """
    ver, prev_block, root_hash, time, bits, nonce, txn_count, txns = b
    prefix = '    '
    print('  BLOCK')
    print('  --------------------------------------------------------')
    print('{}{:32} version {}'.format(prefix, ver.hex(), unmarshal_int(ver)))
    print('{}{:32} prev_block'.format(prefix, prev_block.hex()))
    print('{}{:32} root_hash'.format(prefix, root_hash.hex()))
    print('{}{:32} time {}'.format(prefix, time.hex(), unmarshal_uint(time)))
    print('{}{:32} nBits {}'.format(prefix, bits.hex(), unmarshal_uint(bits)))
    print('{}{:32} nonce {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))
    print('{}txn_count {}'.format(prefix, txn_count))
    print_transaction(txns)


def print_inv(b):
    """
    print the contents of an inv message
    :param b: the unmarshalled inv message
    """
    count_n, inv = read_inv(b)
    print('  VERSION')
    print('  --------------------------------------------------------')
    print('    COUNT: {0}'.format(count_n))
    print('    NUM\tTYPE\tTXID')
    for i in range(len(inv)):
        print('    {0}\t{1}\t{2}'.format(i + 1, str(inv[i]['type']), \
                                                inv[i]['hash'].hex()))


def print_getblocks(b):
    """
    print the contents of a getblocks message
    :param txns: the unmarshalled getblocks message
    """
    ver = b[:4]
    hash_count_b, hash_count = unmarshal_compactsize(b[4:])
    b = b[len(hash_count_b) + 4:]
    block_header_hashs = b[:-32]
    stop_hash = b[-32:]
    prefix = '    '
    print('  GETBLOCKS')
    print('  --------------------------------------------------------')
    print('{}{:32} version {}'.format(prefix, ver.hex(), unmarshal_int(ver)))
    print('{}{:32} hash count {}'.format(prefix, hash_count_b.hex(), hash_count))
    for i in range(0, len(block_header_hashs), 32):
        h = bytearray(block_header_hashs[i:i+32])
        h.reverse()
        print('{}block header {}\t{:32}'.format(prefix, i + 1, h.hex()))
    print('{}stop hash\t\t{:32}'.format(prefix, stop_hash.hex()))


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = \
        b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = \
        header[:4], header[4:16], header[16:20], header[20:]
    try:
        command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    except UnicodeDecodeError:
        print('  Could not read header...')
        return 'unknown'
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command


def command_name_to_bytes(n):
    return bytes(n, 'utf-8') + bytearray(12-len(n))


def checksum(n):
    return hashlib.sha256(hashlib.sha256(n).digest()).digest()


class BitcoinNode():
    """
    A partial bitcoin node
    """
    def __init__(self, suid):
        """
        Instantiate an object of the class
        :param suid: the id number to use when getting the block
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.block_id = suid % _MAX_BLOCK_ID

    @staticmethod
    def make_message(data):
        """
        Add header bytes to a message
        :param data: message bytes
        :return: header + message bytes
        """
        cmd, payload = data
        magic = bytes.fromhex(_MAGIC)
        command = bytes(cmd, 'utf-8') + bytearray(12-len(cmd))
        length = uint32_t(len(payload))
        check = checksum(payload)[:4]
        return magic + command + length + check + payload

    @staticmethod
    def version_message(peer):
        """
        Marshal a version message
        :param peer: tuple of (<ip>, <port>) of recieving node
        :return: tuple of ("version", message bytes)
        """
        version = int32_t(70015)
        services = uint64_t(0)
        timestamp = int64_t(time.time())
        addr_recv = uint64_t(1)
        addr_recv += ipv6_from_ipv4(peer[0])
        addr_recv += uint16_t(peer[1])
        addr_from = uint64_t(0)
        addr_from += ipv6_from_ipv4('127.0.0.1')
        addr_from += uint16_t(8333)
        nonce = uint64_t(0)
        user_agent_bytes = compactsize_t(0)
        height = int32_t(0)
        payload = version + \
                  services + \
                  timestamp + \
                  addr_recv + \
                  addr_from + \
                  nonce + \
                  user_agent_bytes + \
                  height
        return ("version", payload)

    @staticmethod
    def getblocks_message(header_hash):
        """
        Marshal a getblocks message
        :param header_hash: most recently seen inv entry
        :return: tuple of ("getblocks", message_bytes)
        """
        v = int32_t(70015)
        if header_hash is not None:
            header_hash.reverse()
            h_c = compactsize_t(1)
            h_h = header_hash
            s = b'0' * 32
        else:
            h_c = compactsize_t(0)
            h_h = b''
            s = b'0' * 32
        payload = v + h_c + h_h + s
        return ('getblocks', payload)

    @staticmethod
    def getdata_message(block):
        """
        Marshal a getdata message
        :param block: dict of {<type>, <hash>} for desired block
        :return: tuple of ("getdata", message_bytes)
        """
        c = compactsize_t(1)
        t = uint32_t(block['type'])
        b = block['hash']
        b.reverse()
        payload = c + t + b
        return ('getdata', payload)

    @staticmethod
    def make_balanced(txns):
        n = 1
        while 2 ** n < len(txns):
            n += 1
        for i in range((2**n) - len(txns)):
            txns.append(txns[-1])
        return txns

    @staticmethod
    def print_message_wrapper(msg):
        """
        Print a message that has been recieved from the peer
        :param msg: message bytes recieved
        """
        print('RECIEVED:')
        print_message(msg)

    def send_message(self, msg, p=True):
        """
        Send a message and optionally print it
        :param msg: the bytes to send
        :p: print flag
        """
        if p: print_sending_message(msg)
        self.sock.send(msg)

    def receive_message(self):
        """
        Recieve a variable length message
        :return: message bytes
        """
        response = self.sock.recv(HDR_SZ)
        payload = unmarshal_uint(response[16:20])
        while len(response) - HDR_SZ < payload:
            data = self.sock.recv(payload - len(response)+HDR_SZ)
            response += data
        return response

    def wait_for_message(self, expected_cmd):
        """
        wait for a specific message from the peer
        :param expected_cmd: the command to wait for
        :return: response bytes
        """
        cmd = ''
        while cmd != expected_cmd:
            ready, *_ = select.select([self.sock], [], [])
            response = self.receive_message()
            cmd = get_command(response)
        self.print_message_wrapper(response)
        return response


    def connect_to_peer(self, peer=_CHOSEN_PEER):
        """
        Connect to a peer in the P2P BitCoin network.
        chosen peer is hardcoded
        :param peer: the peer to connect to
        """
        self.sock.connect(peer)
        self.ip, self.port = self.sock.getsockname()
        self.send_message(self.make_message(self.version_message(peer)))
        self.print_message_wrapper(self.receive_message())
        self.send_message(self.make_message(('verack', b'')))
        self.print_message_wrapper(self.receive_message())

    def get_inv_at_height(self, height, p=True, last=None):
        """
        Get an inventory item at a specific height in the blockchain
        :param height: the height of the item to return
        :param p: print flag
        :param last: the last seen inv message
                     None to start from genesis block
        :return: inventory dict {<type>, <hash>}
        """
        count_total = 0
        last_hash = last
        send_new = True
        while count_total < height:
            if send_new:
                msg = self.getblocks_message(last_hash)
                self.send_message(self.make_message(msg), p) 
            ready, *_ = select.select([self.sock], [], [])
            response = self.receive_message()
            cmd = get_command(response)
            size = unmarshal_uint(response[16:20])
            if cmd == 'inv' and size >= 18003:
                if p: self.print_message_wrapper(response)
                count, inv = read_inv(response[HDR_SZ:])
                count_total += count
                last_hash = inv[499]['hash']
                send_new = True
            else: send_new = False
        return inv[height % count]

    def get_my_block(self):
        """
        Get block with height corrosponding to the provided suid
        :return: inventory entry dict
        """
        inv = self.get_inv_at_height(_MAX_INV_COUNT * _MAX_INV_MESSAGES - 1)
        print()
        print('Getting remaining invs without printing...')
        inv = self.get_inv_at_height(self.block_id, False, inv['hash'])
        print('Found block {}'.format(inv['hash'].hex()))
        print()
        return inv

    def get_block_info(self, block):
        """
        Get block given its hash
        :param block: inventory entry dict
        :return: tuple containing block contents
        """
        msg = self.getdata_message(block)
        self.send_message(self.make_message(msg))
        response = self.wait_for_message('block')
        return read_block(response[HDR_SZ:])

    def print_transactions(self, hashes):
        """
        Print transactions in a block
        :param hashes: list of txids
        """
        for i in hashes:
            b = bytearray(i)
            b.reverse()
            msg_body = {'type': 1, 'hash': b}
            msg = self.getdata_message(msg_body)
            self.send_message(self.make_message(msg))
            self.wait_for_message('tx')

    def modify_transactions(self, txns):
        """
        Shuffle the bytes in a transaction outpoint hash
        :param txns: transactions in a block
        :return: new list of transactions
        """
        b = bytearray(txns[1]['tx_in'][0]['hash'])
        random.shuffle(b)
        txns[1]['tx_in'][0]['hash'] = bytes(b)
        return txns

    def build_merkle(self, txns):
        """
        Build a merkle root given a list of transaction bytes
        :param txns: list of transaction bytes
        :return: hash of merkle root
        """
        def recur(txns):
            if len(txns) == 1:
                return txns[0]
            out = []
            for i in range(0, len(txns), 2):
                out.append(checksum(txns[i] + txns[i+1]))
            return recur(out)

        txns = self.make_balanced([tx_message_t(i) for i in txns])
        txns = [checksum(i) for i in txns]
        return recur(txns)

    def build_block_header(self, block_data, new_txns = None):
        """
        Build a block header from its python data type representation
        :param block_data: the python representation of the block header
        :param new_txns: new transaction list to use instead
        :return: block header bytes
        """
        payload = b''
        prev = bytearray(block_data[1])
        prev.reverse()
        payload += block_data[0]
        payload += prev
        if new_txns is not None:
            root = self.build_merkle(new_txns)
        else:
            root = block_data[2]
        root = bytearray(root)
        root.reverse()
        payload += root
        for i in block_data[3:6]:
            payload += i
        return payload

    def close(self):
        """
        Close the connection with the peer
        """
        self.sock.close()


def check_proof_of_work(b):
    """
    Verify that the nonce used in a block satisfies the proof-of-work system
    :param b: the bytes of the hash to check
    """
    b = bytearray(b)
    b.reverse()
    b = b.hex()
    print()
    if b[:10] != '0'*10:
        print('INCORRECT NONCE FOR HASH STARTING WITH {}...'.format(b[:32]))
        print('FAILED PROOF OF WORK CHECK')
    else:
        print('CORRECT NONCE FOR HASH STARTING WITH {}...'.format(b[:32]))
        print('PASSED PROOF OF WORK CHECK')


def show_hashes(old, new):
    """
    Show two block hashes
    :param old: hash of unmodified block
    :param new: hash of block with modified transactions
    """
    old, new = bytearray(old), bytearray(new)
    old.reverse()
    new.reverse()
    old, new = old.hex(), new.hex()
    print('Hash of original block header:\t\t', old)
    print('Hash of block header after manipulation:', new)


def check(h, txns):
    """
    Check if a block will be accepted or rejected by peers
    :param h: the hash of the block header
    :param txns: transactions in the block
    """
    check_proof_of_work(h)
    check_sum_of_transactions(txns)


def main(args):
    """
    the main execution run
    :param args: command line args 
    """
    node = BitcoinNode(args.id)
    node.connect_to_peer()
    block = node.get_my_block()
    block_data = node.get_block_info(block)
    txns = block_data[-1]
    txns = node.modify_transactions(txns)
    old_hash = checksum(node.build_block_header(block_data))
    new_hash = checksum(node.build_block_header(block_data, txns))
    print()
    show_hashes(old_hash, new_hash)
    check_proof_of_work(old_hash)
    check_proof_of_work(new_hash)
    node.close()


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('id', type=int, help='SUID to use when getting block')
    main(ap.parse_args())
