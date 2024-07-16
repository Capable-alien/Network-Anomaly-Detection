import streamlit as st
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import nest_asyncio
from datetime import datetime
import time

# Initialize lists for visualization
timestamps = []
anomalies = []

# Define global fig and ax for plotting
fig, ax = plt.subplots()
line, = ax.plot([], [], marker='o', linestyle='-', color='b')
ax.set_title('Real-Time Anomaly Detection')
ax.set_xlabel('Timestamp')
ax.set_ylabel('Anomaly Detected')
ax.set_yticks([0, 1])
ax.set_yticklabels(['Normal', 'Anomaly'])
ax.grid(True)

# Function to read data from sniffed_data.txt and update the lists
def read_data():
    with open('sniffed_data.txt', 'r') as file:
        graph_data = file.read()
    lines = graph_data.split('\n')
    xs = []
    ys = []
    for line in lines:
        if len(line) > 1:
            timestamp, anomaly = line.split(',')
            xs.append(float(timestamp))
            ys.append(float(anomaly))
    return xs, ys

# Streamlit main function
def main():
    st.title("Network Traffic Anomaly Detection")

    # Create a placeholder for the plot
    plot_placeholder = st.empty()

    while True:
        xs, ys = read_data()
        ax.clear()
        ax.plot(xs, ys)
        ax.set_title('Real-Time Anomaly Detection')
        ax.set_xlabel('Timestamp')
        ax.set_ylabel('Anomaly Detected')
        ax.set_yticks([0, 1])
        ax.set_yticklabels(['Normal', 'Anomaly'])
        ax.grid(True)
        
        plot_placeholder.pyplot(fig)
        time.sleep(1)  # Adjust the interval as needed

if __name__ == "__main__":
    nest_asyncio.apply()  # Fix for allowing asyncio in Jupyter/Colab environments
    main()
