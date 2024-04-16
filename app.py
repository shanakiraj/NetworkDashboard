import collections
import datetime
import dash
from dash import dcc, html
import plotly.graph_objs as go
from dash.dependencies import Input, Output
import socket
import threading
import queue
import pandas as pd
from scapy.all import sniff, IP, traceroute
import time
from collections import Counter, defaultdict
from geoip2.database import Reader
# call the ability to add external scripts
external_scripts = [

# add the tailwind cdn url hosting the files with the utility classes
    {'src': 'https://cdn.tailwindcss.com'}

]


# Queue to store packet data
packet_queue = queue.Queue()

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

    sniff(prn=handle_packet, store=False)

#Runs a traceroute on the destination sent, can read more about this online on exactly what it does but it like sends a packet through the network
def trace_route(destination):
    result, _ = traceroute([destination], maxttl=20, verbose=False)
    ip_traceroutes[destination] = result

#we probably want this to see if a packet is taking a long time to arrive at the final destination, but I didn't exactly know how to do that
def analyze_timing():
    df = pd.DataFrame([(dst, times[-1] - times[0]) for dst, times in packet_times.items() if len(times) > 1], columns=['Destination', 'Total Time']) #finding the difference in time between the first packet and the last packet
    # print(df)

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
        alert_message = f"New hops detected for {target}: {new_hops}"
        print(alert_message)
        handle_alert(alert_message)  # Handle the alert

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

def analyze_traffic():
    # Example threshold values
    traffic_threshold = 2  # Adjust based on baseline measurements
    ip_threshold = 2  # Adjust based on baseline measurements

    current_time = time.time() // 1
    current_traffic = traffic_volume.get(current_time, 0)

    suspicious_ips = [ip for ip, count in ip_counter.items() if count > ip_threshold]

    if current_traffic > traffic_threshold:
        alert = f"High traffic volume detected: {current_traffic} bytes/s"
        handle_alert(alert, risk_level="High")
    
    if suspicious_ips:
        alert  = f"Suspicious IPs with high request rates: {suspicious_ips}"
        handle_alert(alert, risk_level="Medium")

# Start the packet capture in a background thread
threading.Thread(target=capture_packets, daemon=True).start()

# Initialize Dash app
app = dash.Dash(__name__,external_scripts=external_scripts)
app.layout = html.Div([
    html.Div(id='header'),

    html.Div(children = [html.Div(id='live-table', className='h-72 overflow-y-auto w-screen/2'), html.Div(id='alerts-area', className='max-h-72 px-2')], className='w-full grid grid-cols-2 '),
    dcc.Interval(
        id='table-update',
        interval=100,  # Update every second
        n_intervals=0
    ),
    html.Div(className="flex", children=[
        dcc.Graph(id='live-graph', animate=False, className='w-1/2', config={
            'staticPlot': True  # This will make the plot completely static
        }),
        dcc.Graph(id='globe-3d', className='w-1/2', config={
            'staticPlot': True  # This will make the plot completely static
        }),
    ]),
    dcc.Interval(
        id='graph-update',
        interval=100,  # Update every second
        n_intervals=0
    ),
    dcc.Interval(
        id='alert-update',
        interval=1000*5,  # Update every second
        n_intervals=0
    )

])
def generate_table(dataframe, max_rows=1000):
    return html.Table(className = "w-full text-lg text-left rtl:text-right text-gray-500 mx-10 ", children =[
        html.Thead(className = "text-xs text-gray-700 uppercase bg-gray-50 sticky top-0", children =[
            html.Tr([html.Th('Source'), html.Th('Destination'), html.Th('Protocol'), html.Th('HostName')])
        ]),
        html.Tbody([
            html.Tr(className = "odd:bg-white even:bg-gray-50 border-b", children = [
                html.Td(dataframe.iloc[i][col]) for col in dataframe.columns
            ]) for i in range(min(len(dataframe), max_rows)-1,-1,-1)
        ]),
        
    ])

@app.callback(Output('header', 'children'),
              [Input('graph-update', 'n_intervals')])
def update_header(n):
    return html.Div(className='bg-blue-800 text-white py-2 px-4 flex justify-between items-center', children=[
    html.Img(src='https://upload.wikimedia.org/wikipedia/en/thumb/d/d1/Virginia_Cavaliers_sabre.svg/2560px-Virginia_Cavaliers_sabre.svg.png', className='h-8'),  # Tailwind class for height
    html.H1('Network Dashboard', className='text-2xl font-bold'),  # Tailwind classes for text sizing and font weight
    
    # Operational status with rounded corners and padding
    html.Div(f"{'' if not alerts else '⚠️'}", className='text-3xl text-yellow-500 animate-pulse pr-4')
    ]),


data = {'Source': [], 'Destination': [], 'Protocol': [], 'HostName': []}
graphData = {}
ip_counter = Counter()
traffic_volume = Counter()
# Callback to update the graph
@app.callback(Output('live-table', 'children'),
              [Input('table-update', 'n_intervals')])
def update_table(n):

    
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
    
    if not packet_queue.empty():
        packet = packet_queue.get()
        addr = packet['Destination']

        try:
            # Perform a DNS lookup to get the hostname
            hostname = socket.gethostbyaddr(addr)[0]
        except (socket.herror, socket.gaierror):
            # If the reverse lookup fails, use the IP address
            hostname = addr
        
        graphData[hostname] = graphData.get(hostname, 0) + 1

       
        src_ip = packet['Source']
        
        # Update counters
        ip_counter[src_ip] += 1
        traffic_volume[time.time() // 1] += len(packet)  # Traffic volume per second

        update_location_data(src_ip)
            

    # Create the Plotly figure
    fig = go.Figure(data=[go.Bar(x=list(graphData.keys()), y=list(graphData.values()))])
    fig.update_layout(title='Real-Time Network Packet Data',
                      xaxis=dict(title='Host'),
                      yaxis=dict(title='Number of Visits'),
                      autosize=True,
                      height=500,
                      width=800)
    return fig

alerts = []  # This will store all alerts

def handle_alert(message, risk_level="Low"):
    alert_time = datetime.datetime.now().strftime("%H:%M:%S")
    alerts.append({"time": alert_time, "message": message, "risk": risk_level})

@app.callback(Output('alerts-area', 'children'),
              [Input('alert-update', 'n_intervals')])
def update_alerts(n):
    
    analyze_timing()
    check_routes()
    analyze_traceroutes()
    # ddos
    analyze_traffic()
    ip_counter.clear()
    traffic_volume.clear()

    

    # Creating a table with an additional Alert Time column
    return html.Div([
        html.Table([
            html.Thead(
                html.Tr([
                    html.Th("Alert Time", className="bg-blue-100 px-4 py-2"),
                    html.Th("Alert Message", className="bg-blue-100 px-4 py-2"),
                    html.Th("Risk", className="bg-blue-100 px-4 py-2"),
                ], className="bg-gray-200 text-gray-800 top-0 sticky")
            ),
            html.Tbody([
                html.Tr([
                    html.Td(alert['time'], className="border px-4 py-2"),
                    html.Td(alert['message'], className="border px-4 py-2"),
                    html.Td([
                        html.Span(f"{alert['risk']}", className=f"flex items-center gap-2 {'text-green-500 font-bold' if alert['risk'] == 'Low' else 'text-yellow-500 font-semibold' if alert['risk'] == 'Medium' else 'text-red-500 font-bold'}")
                    ], className="border px-4 py-2"),
                ]) for alert in reversed(alerts)
            ])
        ], className="min-w-full table-fixed")
    ], className="overflow-x-auto overflow-y-auto shadow rounded-lg max-h-96")


# Load the GeoIP2 database
reader = Reader('GeoLite2-City.mmdb')

def get_location(ip_address):
    location_data = reader.city(ip_address)
    return {
        'latitude': location_data.location.latitude,
        'longitude': location_data.location.longitude,
        'country': location_data.country.name
    }

location_counts = defaultdict(int)

def update_location_data(src_ip):
    try:
        loc = get_location(src_ip)
        if loc['latitude'] and loc['longitude']:
            # Create a tuple of latitude and longitude for dictionary key
            key = (loc['latitude'], loc['longitude'])
            location_counts[key] += 1
    except Exception as e:
        print(f"Error updating location data: {e}")

def get_marker_sizes():
    sizes = []
    for count in location_counts.values():
        # Base size of 4, scale up by 1 for every 5 additional appearances, cap at 20
        size = min(6 + (count // 5), 20)
        sizes.append(size)
    return sizes

@app.callback(Output('globe-3d', 'figure'),
              Input('graph-update', 'n_intervals'))
def update_globe(n):
    lats = [key[0] for key in location_counts.keys()]
    lons = [key[1] for key in location_counts.keys()]
    sizes = get_marker_sizes()

    map_trace = go.Scattermapbox(
        lat=lats,
        lon=lons,
        mode='markers',
        marker=go.scattermapbox.Marker(
            size=sizes,
            color='blue',
            opacity=0.4
        ),
    )
    
    layout = go.Layout(
        autosize=True,
        hovermode='closest',
        uirevision='constant',
        mapbox=dict(
            style="open-street-map",
            zoom=0,  # Adjust the zoom level here
            center=dict(
                lat=0,  # Center latitude
                lon=0  # Center longitude
            ),
        ),
        title='Real-Time Network Traffic Origins'
    )

    return {'data': [map_trace], 'layout': layout}


if __name__ == '__main__':
    app.run_server(debug=True)
    
        

