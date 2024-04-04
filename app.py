import dash
from dash import dcc, html
import plotly.graph_objs as go
from dash.dependencies import Input, Output
import socket
import threading
import queue
import pandas as pd
from scapy.all import sniff, IP



# Queue to store packet data
packet_queue = queue.Queue()

# Function to capture network packets
def capture_packets():
    def handle_packet(packet):
        if IP in packet:
            packet_details = {
            "src": packet.sprintf("%IP.src%"),
            "dst": packet.sprintf("%IP.dst%"),
            "protocol": packet.sprintf("%IP.proto%")
        }
            ip_src = packet_details['src']
            ip_dst = packet_details['dst']
            proto = packet_details['protocol']
            packet_queue.put({'Source': ip_src, 'Destination': ip_dst, 'Protocol': proto})
            #print(f"src: {ip_src} dst: {ip_dst} proto: {proto}")

    sniff(prn=handle_packet, store=False)



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
        interval=1000,  # Update every second
        n_intervals=0
    )
    
])
def generate_table(dataframe, max_rows=1000):
    return html.Table([
        html.Thead(
            html.Tr([html.Th(col) for col in dataframe.columns])
        ),
        html.Tbody([
            html.Tr([
                html.Td(dataframe.iloc[i][col]) for col in dataframe.columns
            ]) for i in range(min(len(dataframe), max_rows))
        ]),
        
    ])


data = {'Source': [], 'Destination': [], 'Protocol': []}
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
    app.run_server(debug=True)
