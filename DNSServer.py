import socket
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import threading
import signal
import os
import sys

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,  # refresh
            1800,  # retry
            604800,  # expire
            86400,  # minimum
        ),
    },
    'nyu.edu.': {
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.NS: 'ns1.nyu.edu.',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: ('aa11583@nyu.edu',),
    },
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'google.com.': {
    dns.rdatatype.A: '8.8.4.4',
    }
}

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('localhost', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            threading.Thread(target=handle_dns_query, args=(server_socket, data, addr)).start()
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)


def handle_dns_query(server_socket, data, addr):
    try:
        request = dns.message.from_wire(data)
        print("Received query:", request)
        
        response = dns.message.make_response(request)

        question = request.question[0]
        qname = question.name.to_text()
        qtype = question.rdtype

        if qname in dns_records and qtype in dns_records[qname]:
            answer_data = dns_records[qname][qtype]

            if qtype == dns.rdatatype.MX:
                for pref, server in answer_data:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.MX))
                    response.answer[-1].add(dns.rdtypes.ANY.MX.MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
            elif qtype == dns.rdatatype.SOA:
                mname, rname, serial, refresh, retry, expire, minimum = answer_data
                response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.SOA))
                response.answer[-1].add(dns.rdtypes.ANY.SOA.SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum))
            else:
                response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                response.answer[-1].add(dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data))
        else:
            # If the record is not found, set an empty answer to indicate an error
            response.answer = []

        response.flags |= 1 << 10

        server_socket.sendto(response.to_wire(), addr)
        print("Sent response:", response)
    except Exception as e:
        print("Error handling DNS query:", e)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()
