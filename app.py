import dash
from dash import dcc, html
import plotly.graph_objs as go
from dash.dependencies import Input, Output
import socket
import threading
import queue
import pandas as pd
from scapy.all import sniff, IP, traceroute, ARP
import time
from collections import defaultdict
import geoip2



# Queue to store packet data
packet_queue = queue.Queue()

#A table containing IP address to MAC address. This will be used to see if  
arp_table = defaultdict(set)

packet_times = defaultdict(list)
ip_traceroutes = {}
route_data = {}

# Function to capture network packets
def capture_packets():
    def handle_packet(packet):
        if IP in packet:
            
            #collecting IP information and time 
            current_time = packet.time
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_times[dst_ip].append(current_time) 

            packet_details = {            
            "src": packet.sprintf("%IP.src%"),
            "dst": packet.sprintf("%IP.dst%"),
            "protocol": packet.sprintf("%IP.proto%")
        }
            ip_src = packet_details['src']
            ip_dst = packet_details['dst']
            proto = packet_details['protocol']
            packet_queue.put({'Source': ip_src, 'Destination': ip_dst, 'Protocol': packet.sprintf("%IP.proto%")})
            #print(f"src: {ip_src} dst: {ip_dst} proto: {proto}")

        
        #ARP Management:
        if ARP in packet and packet[ARP].op == 2: #Not all packets have this information
            source_packet_ip = packet[ARP].psrc  # Source protocol address
            source_mac_address = packet[ARP].hwsrc  # Source hardware address
            arp_table[source_packet_ip].add(source_mac_address)


    sniff(prn=handle_packet, store=False)

#Runs a traceroute on the destination sent, can read more about this online on exactly what it does but it like sends a packet through the network
def trace_route(destination):
    result, _ = traceroute([destination], maxttl=20, verbose=False)
    ip_traceroutes[destination] = result

#we probably want this to see if a packet is taking a long time to arrive at the final destination, but I didn't exactly know how to do that
def analyze_timing():
    df = pd.DataFrame([(dst, times[-1] - times[0]) for dst, times in packet_times.items() if len(times) > 1], columns=['Destination', 'Total Time']) #finding the difference in time between the first packet and the last packet
    print(df)

# Function to initiate traceroute to suspicious destinations
def check_routes():
    suspicious_destinations = [dst for dst, times in packet_times.items() if len(times) > 1]
    counter = 0 #currently used for testing but this should be removed and should be ran on all suspicious destinations
    for dst in suspicious_destinations:
        trace_route(dst) #a slow running method. 
        if counter > 0:
            break
        counter += 1

#check if since the last time, new hops have been added, which could mean that there is someone intercepting the data
def analyze_route(target, result):
    current_route = [res[1].src for res in result.res if res[1].src != '<no reply>']
    historical_route = route_data.get(target, [])

    # Check for new hops not in historical data
    new_hops = [hop for hop in current_route if hop not in historical_route]
    if new_hops:
        print(f"New hops detected for {target}: {new_hops}")

    # Update historical data
    route_data[target] = current_route

#runs on a 10 second basis
def analyze_traceroutes():
    for ip in ip_traceroutes:
        #route_details[ip].world_trace()
        result = ip_traceroutes[ip]
        #print(result.summary())
        analyze_route(ip, result)
        #print snd.ttl, rcv.src, isinstance(rcv.payload, TCP)

def analyze_arp_spoofing():
    for ip in arp_table:
        if len(arp_table[ip]) > 1:
            print("Two MAC addresses detected for IP, MiTM May be happening!")

# Start the packet capture in a background thread
threading.Thread(target=capture_packets, daemon=True).start()

# Initialize Dash app
app = dash.Dash(__name__)
app.layout = html.Div([
    html.H1("Real-Time Network Packet Data"),
    
    html.Div(id='live-table', style={'height': '300px', 'overflowY': 'auto'}),
    dcc.Interval(
        id='table-update',
        interval=100,  # Update every second
        n_intervals=0
    ),
    dcc.Graph(id='live-graph', animate=False),
    dcc.Interval(
        id='graph-update',
        interval=100,  # Update every second
        n_intervals=0
    )

])
def generate_table(dataframe, max_rows=1000):
    return html.Table( children =[
        html.Thead([
            html.Tr([html.Th('Source'), html.Th('Destination'), html.Th('Protocol'), html.Th('HostName')])
        ]),
        html.Tbody([
            html.Tr([
                html.Td(dataframe.iloc[i][col]) for col in dataframe.columns
            ]) for i in range(min(len(dataframe), max_rows))
        ]),
        
    ])


data = {'Source': [], 'Destination': [], 'Protocol': [], 'HostName': []}
graphData = {}
# Callback to update the graph
@app.callback(Output('live-table', 'children'),
              [Input('table-update', 'n_intervals')])
def update_table(n):

    # Get up to 10 packets from the queue
    for _ in range(1):
        if not packet_queue.empty():
            packet = packet_queue.get()
            data['Source'].append(packet['Source'])
            data['Destination'].append(packet['Destination'])
            data['Protocol'].append(packet['Protocol'])
            try:
                # Perform a reverse DNS lookup to get the hostname
                destination_hostname = socket.gethostbyaddr(packet['Destination'])[0]
            except (socket.herror, socket.gaierror):
                # If the reverse lookup fails, use the IP address
                destination_hostname = "Hostname not found"
            data['HostName'].append(destination_hostname)

    df = pd.DataFrame(data)
    
    return generate_table(df)

@app.callback(Output('live-graph', 'figure'),
              [Input('graph-update', 'n_intervals')])
def update_graph(n):
    
    # Get up to 10 packets from the queue
    for _ in range(1):
        if not packet_queue.empty():
            addr = packet_queue.get()['Destination']
            graphData[addr] = graphData.get(addr, 0) + 1
            

    # Create the Plotly figure
    fig = go.Figure(data=[go.Bar(x=list(graphData.keys()), y=list(graphData.values()))])
    fig.update_layout(title='Real-Time Network Packet Data',
                      xaxis=dict(title='IP Address'),
                      yaxis=dict(title='Number of Visits'),
                      autosize=True,
                      height=500,
                      width=800)
    return fig


if __name__ == '__main__':
    #app.run_server(debug=True)
    while True:
        time.sleep(10) 
        print("Hello")
        analyze_timing()
        check_routes()
        analyze_traceroutes()
        analyze_arp_spoofing()
        print(arp_table)

