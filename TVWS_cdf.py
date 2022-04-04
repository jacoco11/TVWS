import os
import csv
import subprocess
from  matplotlib import pyplot as plt
import numpy as np
import matplotlib.ticker as ticker
import math

#Functions for the vizualization of a CDF graph using a selected filter.
def cdf_graph(directory, filters):
        #get the filter to be graphed
        temp = True
        while temp:
            filter = input("Enter the filter to be graphed: ")
            if filter in filters:
                temp = False
            else:
                print("Filter could not be found.")
        tempIndex = int(filters.index(filter))

        #Create the figure.
        plt.figure()

        #Initialize axis
        xaxis = []
        yaxis = []

        #Go through directory.
        for file in os.listdir(directory):
            #Locate .csv files
            if file.endswith(".csv"):
                #Open csv files
                with open(os.path.join(directory, file)) as f:

                    csv_reader = csv.reader(f, delimiter=',')

                    #CDF for bytes in flight
                    if "tcp.analysis.bytes_in_flight" in filter:
                        #Gets the values of each value for first field that is not empty.
                        proc2 = subprocess.Popen("awk -F \",\" \"BEGIN{$"+str(tempIndex+1)+"}($"+str(tempIndex+1)+"!=\\\"\\\"){print $"+str(tempIndex+1)+"}\" "+ os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                        temp1 = str(proc2.communicate()[0].decode('ascii'))
                        temp2 = temp1.splitlines()
                        for i in temp2:
                            if len(i) < 2:
                                continue
                            elif i == ' ':
                                continue
                            else:
                                if float(i) > 5000.0:
                                    continue
                                else:
                                    xaxis.append(float(i))
                        plt.xlabel(filter + "(Bytes)")
                    #CDF for Round Trip Time
                    elif "tcp.analysis.ack_rtt" in filter:
                        #Gets the values of each value for first field that is not empty.
                        proc2 = subprocess.Popen("awk -F \",\" \"BEGIN{$"+str(tempIndex+1)+"}($"+str(tempIndex+1)+"!=\\\"\\\"){print $"+str(tempIndex+1)+"}\" "+ os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                        temp1 = str(proc2.communicate()[0].decode('ascii'))
                        temp2 = temp1.splitlines()
                        for i in temp2:
                            if len(i) < 2:
                                continue
                            elif i == ' ':
                                continue
                            else:
                                if float(i) > 10:
                                    continue
                                else:
                                    xaxis.append(float(i))
                        plt.xlabel(filter + "(seconds)")
                    #CDF for frame length size.
                    elif "frame.len" in filter:
                        #Gets the values of each value for first field that is not empty.
                        proc2 = subprocess.Popen("awk -F \",\" \"BEGIN{$"+str(tempIndex+1)+"}($"+str(tempIndex+1)+"!=\\\"\\\"){print $"+str(tempIndex+1)+"}\" "+ os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                        temp1 = str(proc2.communicate()[0].decode('ascii'))
                        temp2 = temp1.splitlines()
                        for i in temp2:
                            if len(i) < 2:
                                continue
                            elif i == ' ':
                                continue
                            else:
                                if float(i) > 5000.0:
                                    continue
                                else:
                                    xaxis.append(float(i))
                        plt.xlabel(filter + "(Bytes)")
                    #Generic CDF, gives no unit of measurement.
                    else:
                        #Gets the values of each value for first field that is not empty.
                        proc2 = subprocess.Popen("awk -F \",\" \"BEGIN{$"+str(tempIndex+1)+"}($"+str(tempIndex+1)+"!=\\\"\\\"){print $"+str(tempIndex+1)+"}\" "+ os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                        temp1 = str(proc2.communicate()[0].decode('ascii'))
                        temp2 = temp1.splitlines()
                        for i in temp2:
                            if len(i) < 2:
                                continue
                            elif i == ' ':
                                continue
                            else:
                                xaxis.append(float(i))
                        plt.xlabel(filter)
        #Calulates the CDF.
        width = 0.005
        x  = np.sort(xaxis)
        y  = 0.25 * np.exp((-x ** 2)/8)
        y = y/(np.sum(width * y))
        cdf = np.cumsum(y * width)
        #Plost the elements found within the CDF.
        plt.plot(x, cdf, "o")
        #Sets the label of the y axis.
        plt.ylabel("PDF")
        #Shows the plotted CDF Graph.
        plt.show()  