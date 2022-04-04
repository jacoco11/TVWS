# TVWS_process - Munthir Chater

import os
import subprocess
import csv


# Function to process and output data
def process(directory, filters, displayFilters, filter3, filter4):
    datefilter = False
    if filter3 != "" and filter4 != "": datefilter = True

    # If filters are specified, include those in command, otherwise use default filters
    if len(filters) != 0:
        print("Processing files... ")
        for file in os.listdir(directory):
            if file.endswith(".pcap"):
                if datefilter == True:
                    index = 12
                    date = ""
                    while index < 20:
                        date += file[index]
                        index += 1
                if (datefilter == True and date >= filter3 and date <= filter4) or datefilter == False:
                    filename2 = os.path.splitext(file)[0] + '.csv'
                    with open(directory + "\\" + filename2, "w") as outfile:
                        command = []
                        commandBegin = ["tshark.exe", "-r", os.path.join(directory, file)]
                        for item in commandBegin:
                            command.append(item)
                        # Include display filter if inputted
                        if len(displayFilters) != 0:
                            command.append("-Y")
                            command.append(displayFilters)
                        # Include field filters if inputted
                        for fltr in filters:
                            command.append("-e")
                            command.append(fltr)
                        commandEnd = ["-T", "fields", "-E", "separator=,", "-E", "occurrence=f"]
                        for item in commandEnd:
                            command.append(item)
                        try:
                            subprocess.run(command, stdout=outfile, check=True)
                        except Exception as err:
                            print("ERROR: Unable to run tshark command: ", err)
                            continue
                else: continue
        print("Files processed. ")
    else:
        print("ERROR: No filters specified. ")


# Function to process and output data for TCP and UDP flows
def process_flows(proto, directory, filter3, filter4):
    datefilter = False
    if filter3 != "" and filter4 != "": datefilter = True

    print("Obtaining flows...")
    # Tshark command to obtain flow data via each .pcap file in the directory and put it into a .conv file
    for file in os.listdir(directory):
        if file.endswith(".pcap"):
            if datefilter == True:
                index = 12
                date = ""
                while index < 20:
                    date += file[index]
                    index += 1
            if (datefilter == True and date >= filter3 and date <= filter4) or datefilter == False:
                filename2 = os.path.splitext(file)[0] + '.csv'
                with open(directory + "\\" + filename2, "w") as outfile:
                    if proto == 1: command = ["tshark.exe", "-r", os.path.join(directory, file), "-q", "-z", "conv,tcp"]
                    else: command = ["tshark.exe", "-r", os.path.join(directory, file), "-q", "-z", "conv,udp"]
                    try:
                        subprocess.run(command, stdout=outfile, check=True)
                    except Exception as err:
                        print("ERROR: Unable to run tshark command: ", err)
                        continue
            else: continue

    print("Converting flows...")
    # Convert the .conv file to a .csv file such that calculations can be automated with awk and are easier to perform
    if proto == 1: end = "_tcpflowtemp.csv"
    else: end = "_udpflowtemp.csv"
    for file in os.listdir(directory):
        i = 1
        if file.endswith(".csv"):
            file2 = os.path.splitext(file)[0] + end
            with open(os.path.join(directory, file)) as infile, open(directory + "\\" + file2, "w") as outfile:
                csv_reader = csv.reader(infile, delimiter=',')
                csv_writer = csv.writer(outfile, lineterminator='\n')
                for row in csv_reader:
                    line = row[0]
                    fieldList = line.split()
                    if fieldList[0] != "================================================================================":
                        if i > 5:
                            # Get source IP address and port number
                            endPort = False
                            sourceIP = ""
                            sourcePort = ""
                            index = len(fieldList[0]) - 1
                            while index != -1:
                                char = fieldList[0][index]
                                if char != ":" and endPort == False: sourcePort = char + sourcePort
                                elif char == ":" and endPort == False: endPort = True
                                else: sourceIP = char + sourceIP
                                index -= 1
                            # Get destination IP address and port number
                            endPort = False
                            destIP = ""
                            destPort = ""
                            index = len(fieldList[2]) - 1
                            while index != -1:
                                char = fieldList[2][index]
                                if char != ":" and endPort == False: destPort = char + destPort
                                elif char == ":" and endPort == False: endPort = True
                                else: destIP = char + destIP
                                index -= 1
                            # Get total packets sent in flow
                            totPkts = ""
                            for char in fieldList[8]:
                                if char == 'M':
                                    totPkts = str(int(totPkts) * 1000000)
                                    break
                                elif char == 'k':
                                    totPkts = str(int(totPkts) * 1000)
                                    break
                                elif char == 'b': break
                                else: totPkts += char
                            # Get total packets sent from source to destination
                            sourcePkts = ""
                            for char in fieldList[6]:
                                if char == 'M':
                                    sourcePkts = str(int(sourcePkts) * 1000000)
                                    break
                                elif char == 'k':
                                    sourcePkts = str(int(sourcePkts) * 1000)
                                    break
                                elif char == 'b': break
                                else: sourcePkts += char
                            # Get total packets sent from destination to source
                            destPkts = ""
                            for char in fieldList[4]:
                                if char == 'M':
                                    destPkts = str(int(destPkts) * 1000000)
                                    break
                                elif char == 'k':
                                    destPkts = str(int(destPkts) * 1000)
                                    break
                                elif char == 'b': break
                                else: destPkts += char

                            fieldList2 = [sourceIP, sourcePort, destIP, destPort, fieldList[7], totPkts, fieldList[5],
                                          sourcePkts, fieldList[3], destPkts, fieldList[9], fieldList[10]]
                            csv_writer.writerow(fieldList2)
                            i += 1
                        else: i += 1
                    else: i += 1
            os.remove(os.path.join(directory, file))

    # For TCP flows, determine completion/failure state
    if proto == 1:
        print("Adding additional data to flows...")
        for file in os.listdir(directory):
            if file.endswith(end):
                filename1 = file.replace(end, ".pcap")
                filename2 = "successfulFlows.csv"
                with open(directory + "\\" + filename2, "w") as outfile:
                    try:
                        command = ["tshark.exe", "-r", os.path.join(directory, filename1), "-Y", "tcp.flags.fin==1", "-e", "ip.src",
                                   "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tcp.stream", "-T", "fields", "-E",
                                   "separator=,", "-E", "occurrence=f"]
                        subprocess.run(command, stdout=outfile, check=True)
                    except Exception as err:
                        print(err)

                filename3 = file.replace(end, "_tcpflow.csv")
                with open(os.path.join(directory, file)) as f1, open(os.path.join(directory, filename3), "w") as f3:
                    csv_reader1 = csv.reader(f1, delimiter=',')
                    csv_writer = csv.writer(f3, lineterminator="\n")
                    for row1 in csv_reader1:
                        if row1[4] == "1":
                            list = []
                            for value in row1: list.append(value)
                            list.append("N/A")
                            csv_writer.writerow(list)
                            continue
                        else:
                            with open(os.path.join(directory, filename2)) as f2:
                                csv_reader2 = csv.reader(f2, delimiter=',')
                                fin = False
                                for row2 in csv_reader2:
                                    if row1[0] == row2[0] and row1[1] == row2[1] and row1[2] == row2[2] and row1[3] == row2[3]:
                                        list = []
                                        for value in row1: list.append(value)
                                        list.append("success")
                                        csv_writer.writerow(list)
                                        fin = True
                                        break
                                if fin == False:
                                    list = []
                                    for value in row1: list.append(value)
                                    list.append("fail")
                                    csv_writer.writerow(list)

                os.remove(os.path.join(directory, file))
                os.remove(os.path.join(directory, filename2))
    print("Flows processed.")