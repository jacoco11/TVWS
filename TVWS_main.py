# TVWS_main - Munthir Chater

import os
import TVWS_process
import TVWS_tools1
import TVWS_tools2
import TVWS_main_filters
import TVWS_cdf

# GLOBALS
# Global dictionaries for count, total, and average values. Values are stored here to prevent re-calculating and save time
countCalcs = {}
totalCalcs = {}
avgCalcs = {}
# Global specification values that are inputted by user to run program
directory = None
graph = None
dateFilter1 = ""
dateFilter2 = ""
displayFilter = ""
fieldFilter = []

# Popular websites whose IP addresses are public, thus allowing traffic to their domain to be analyzed.
#  NOTE: Should a website be added here, its list of IP ranges must also be added in the 'TVWS_tools2' script
websiteList = ["Yahoo", "Amazon", "Microsoft", "Bing", "MSN", "Google", "YouTube", "Facebook", "Twitter"]
# HTTP response codes referenced via https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
#  and https://www.tutorialrepublic.com/html-reference/http-status-codes.php
codeList = ["100", "200", "204", "206", "300", "301", "302", "303", "304", "400", "401", "403", "404", "408", "500",
            "501", "503"]
# Port numbers referenced via https://packetlife.net/media/library/23/common_ports.pdf
#  and https://www.godaddy.com/garage/whats-an-ssl-port-a-technical-guide-for-https/
services = {"HTTP": [80], "SSL": [443], "HTTPS": [443], "FTP": [21], "SFTP": [22], "SSH": [22], "FTPs": [990],
            "MySQL": [3306],
            "Telnet": [23], "SMPTP": [25], "DNS": [53],
            "BitTorrent": [6881, 6999], "Napster": [6699, 6701], "Gnutella": [6346, 6347],
            "WinMX": [6257], "eMule": [4672], "WASTE": [1337], "Kazaa": [1214], "Direct": [411, 412]}


# Function to set or update path of current working directory
def set_directory(path):
    global directory
    loop = True

    while loop:
        if path == "exit": loop = False
        elif os.path.isdir(path):
            directory = path
            print("Directory path set. ")
            loop = False
        else: path = input("Directory does not exist, re-renter. ")


# Function to set or update fields to be filtered when processing .pcap files
def set_filters(filterList):
    global fieldFilter
    fieldCount = 0

    if filterList[0] == "clear":
        fieldFilter.clear()
        print("Field filters removed. ")
    else:
        fieldFilter.clear()
        for field in filterList:
            if field != "filter" and field != "field":
                if field in TVWS_main_filters.fieldFilters:
                    fieldFilter.append(field)
                    fieldCount += 1
                else: print("Field: ", field, " not a valid field, or not supported.")
        print(fieldCount, " field(s) added to filter. ")


# Function to set or update display filters to be used when processing .pcap files
def set_displayFilter(disfilter):
    global displayFilter

    if disfilter == "clear":
        displayFilter = ""
        print("Display filter removed. ")
    else:
        displayFilter = ""
        if disfilter in TVWS_main_filters.displayFilters:
            displayFilter = displayFilter + disfilter
            print("Display filter added. ")
        else: print("Field: ", disfilter, " not a valid field, or not supported.")


# Function to set date filter to be used when processing .pcap files
def set_dateFilter(datefilter):
    global dateFilter1
    global dateFilter2
    index = 0
    date1 = True
    year1, year2, month1, month2, day1, day2 = "", "", "", "", "", ""

    if datefilter == "clear":
        check = input("Are you sure? This will reset saved calculations. ")
        if check.lower() == "yes":
            dateFilter1 = ""
            dateFilter2 = ""
            countCalcs.clear()
            totalCalcs.clear()
            avgCalcs.clear()
            print("Date filter removed. ")
    else:
        for char in datefilter:
            if char == "-" and date1 == True: date1 = False
            elif index <= 3 and date1 == True: year1 += char
            elif index >= 4 and index <= 5 and date1 == True: month1 += char
            elif index >= 6 and index <= 7 and date1 == True: day1 += char
            elif index >= 9 and index <= 12 and date1 == False: year2 += char
            elif index >= 13 and index <= 14 and date1 == False: month2 += char
            elif index >= 15 and index <= 16 and date1 == False: day2 += char
            index += 1

        validDates = True
        try:
            if (int(year1) < 2010 or int(year1) > 2022) or (int(year2) < 2010 or int(year2) > 2022): validDates = False
            if (int(month1) < 1 or int(month1) > 12) or (int(month2) < 1 or int(month2) > 12): validDates = False
            if (int(day1) < 1 or int(day1) > 31) or (int(day2) < 1 or int(day2) > 31): validDates = False

            if validDates == True:
                check = input("Are you sure? This will reset saved calculations. ")
                if check.lower() == "yes":
                    dateFilter1 = year1 + month1 + day1
                    dateFilter2 = year2 + month2 + day2
                    countCalcs.clear()
                    totalCalcs.clear()
                    avgCalcs.clear()
                    print("Date filter added. ")
            else: print("Invalid date input. ")
        except:
            print("Invalid date input.")


# Function to set graph type for data visualization
def set_graph():
    global graph
    loop2 = True

    while loop2:
        choice = input("Select graph type: ")
        if choice == "exit":
            loop2 = False
        elif choice == "info":
            print("Process Info: " +
                  "\nInput: " +
                  "\n- 'plot' : Set graph to plot" +
                  "\n- 'scatter' : Set graph to scatter" +
                  "\n- 'bar' : Set graph to bar")
        elif choice == "plot" or choice == "scatter" or choice == "bar":
            graph = choice
            print("Graph set.")
        else: print("Invalid entry, re-renter. ")


# Function for settings menu
def settings():
    loop = True

    while loop:
        print("Settings: ")
        choice = input()
        choiceList = choice.split()
        if len(choiceList) != 0:
            if choiceList[0] == "info":
                print("Settings Info: " +
                      "\nInput: " +
                      "\n- 'clear' <input>: Clear previous filter input (field, display, date)" +
                      "\n- 'dir' <path>: Enter specified directory path from which .pcap files are processed" +
                      "\n- 'filter' <filter type> <filter value>: Filter .pcap files from specified directory" +
                      "\n- 'graph' <graph type>: Enter fields to be present in graph and type of graph")
            elif choiceList[0] == "clear":
                if len(choiceList) > 1:
                    if choiceList[1] == "field": set_filters(choiceList)
                    elif choiceList[1] == "display": set_displayFilter(choiceList[0])
                    elif choiceList[1] == "date": set_dateFilter(choiceList[0])
                    else: print("Invalid input. ")
                else: print("Need additional argument - input to clear. ")
            elif choiceList[0] == "dir":
                if len(choiceList) > 1: set_directory(choiceList[1])
                else: print("Need additional argument - directory path. ")
            elif choiceList[0] == "filter":
                if len(choiceList) >= 3 and choiceList[1] == "field": set_filters(choiceList)
                elif len(choiceList) == 3 and choiceList[1] == "display": set_displayFilter(choiceList[2])
                elif len(choiceList) == 3 and choiceList[1] == "date": set_dateFilter(choiceList[2])
                else: print("Invalid filter command. Enter in the form: 'filter <filter type> <filter value>' ")
            elif choiceList[0] == "graph":
                set_graph()
            elif choiceList[0] == "exit":
                loop = False
            else: print("Invalid command, re-enter. ")
        else: print("Enter a command. ")


# Function for Tools menu
def tools():
    global graph
    loop = True

    while loop:
        repeat = False
        print("Tools: ")
        choice = input()
        choiceList = choice.split()
        codeOrService = ""
        if choiceList[0] == "rep": repeat = True

        if len(choiceList) == 3 and repeat != True:
            tool = choiceList[0]
            func = choiceList[1]
            filt = choiceList[2]
        elif len(choiceList) == 4 and repeat == True:
            tool = choiceList[1]
            func = choiceList[2]
            filt = choiceList[3]
        elif len(choiceList) == 4 and repeat != True:
            tool = choiceList[0]
            func = choiceList[1]
            filt = choiceList[2]
            codeOrService = choiceList[3]
            if codeOrService in websiteList: codeOrService = codeOrService
            elif codeOrService in codeList: codeOrService = codeOrService
            elif codeOrService in services: codeOrService = services[codeOrService]
            else:
                print("Invalid website, code, or service input. ")
                continue
            if filt == "http.response.code":
                if codeOrService not in codeList:
                    print("Invalid code entry. ")
                    continue
            elif filt == "services_tcpflows" or filt == "servicespackets_tcpflows" \
                    or filt == "services_udpflows" or filt == "servicespackets_udpflows":
                if codeOrService not in services:
                    print("Invalid service entry. ")
                    continue
            elif filt in TVWS_main_filters.siteFilters:
                if codeOrService not in websiteList:
                    print("Invalid website entry. ")
                    continue
        elif len(choiceList) == 5 and repeat == True:
            tool = choiceList[1]
            func = choiceList[2]
            filt = choiceList[3]
            codeOrService = choiceList[4]
            if codeOrService in websiteList: codeOrService = codeOrService
            elif codeOrService in codeList: codeOrService = codeOrService
            elif codeOrService in services: codeOrService = services[codeOrService]
            else:
                print("Invalid website, code, or service input. ")
                continue
            if filt == "http.response.code":
                if codeOrService not in codeList:
                    print("Invalid code entry. ")
                    continue
            elif filt == "services_tcpflows" or filt == "servicespackets_tcpflows" \
                    or filt == "services_udpflows" or filt == "servicespackets_udpflows":
                if codeOrService not in services:
                    print("Invalid service entry. ")
                    continue
            elif filt in TVWS_main_filters.siteFilters:
                if codeOrService not in websiteList:
                    print("Invalid website entry. ")
                    continue

        compatibleFunc = False
        if choice == "exit":
            loop = False
        elif choice == "info":
            print("Settings Info: " +
                  "\nInput: " +
                  "\n- 'calc' <function type> <field> <code/service (if necessary)> : Perform calculation on data" +
                  "\n- 'graph' <graph_type> <field> : Output graph of data" +
                  "\n- 'exit' : Exit tools")
        elif (len(choiceList) >= 3 and len(choiceList) <= 5) and tool == "calc":
            if func == "count" or func == "total" or func == "avg":
                if func == "count":
                    if filt in TVWS_main_filters.countFilters: compatibleFunc = True
                elif func == "total":
                    if filt in TVWS_main_filters.totalFilters: compatibleFunc = True
                elif func == "avg":
                    if filt in TVWS_main_filters.averageFilters: compatibleFunc = True
                if compatibleFunc == True:
                    if filt in TVWS_main_filters.fieldFilters or \
                            (filt == "cpkt" and "tcp.analysis.retransmission" in TVWS_main_filters.fieldFilters and
                             "tcp.flags" in TVWS_main_filters.fieldFilters and "tcp.len" in TVWS_main_filters.fieldFilters) \
                            or filt in TVWS_main_filters.tcpflowFilters or filt in TVWS_main_filters.udpflowFilters:
                        if func == "count":
                            if filt in countCalcs and repeat == False: print(countCalcs[filt])
                            else:
                                if filt in TVWS_main_filters.tcpflowFilters: count = \
                                    TVWS_tools1.calc("count", filt, fieldFilter, codeOrService, directory, 1, dateFilter1, dateFilter2)
                                elif filt in TVWS_main_filters.udpflowFilters: count = \
                                    TVWS_tools1.calc("count", filt, fieldFilter, codeOrService, directory, 2, dateFilter1, dateFilter2)
                                else: count = \
                                    TVWS_tools1.calc("count", filt, fieldFilter, codeOrService, directory, 0, dateFilter1, dateFilter2)
                                countCalcs[filt] = count
                                print("COUNT: ", count)
                        elif func == "total":
                            if filt in totalCalcs and repeat == False: print(totalCalcs[filt])
                            else:
                                if filt in TVWS_main_filters.tcpflowFilters: total = \
                                    TVWS_tools1.calc("total", filt, fieldFilter, codeOrService, directory, 1, dateFilter1, dateFilter2)
                                elif filt in TVWS_main_filters.udpflowFilters: total = \
                                    TVWS_tools1.calc("total", filt, fieldFilter, codeOrService, directory, 2, dateFilter1, dateFilter2)
                                else: total = \
                                    TVWS_tools1.calc("total", filt, fieldFilter, codeOrService, directory, 0, dateFilter1, dateFilter2)
                                totalCalcs[filt] = total
                                print("TOTAL: ", total)
                        elif func == "avg":
                            if filt in avgCalcs and repeat == False: print(avgCalcs[filt])
                            else:
                                if filt in TVWS_main_filters.tcpflowFilters: avg = \
                                    TVWS_tools1.calc("avg", filt, fieldFilter, codeOrService, directory, 1, dateFilter1, dateFilter2)
                                elif filt in TVWS_main_filters.udpflowFilters: avg = \
                                    TVWS_tools1.calc("avg", filt, fieldFilter, codeOrService, directory, 2, dateFilter1, dateFilter2)
                                else: avg = \
                                    TVWS_tools1.calc("avg", filt, fieldFilter, codeOrService, directory, 0, dateFilter1, dateFilter2)
                                avgCalcs[filt] = avg
                                print("AVERAGE: ", avg)
                    else: print("Invalid filter, or relevant filter(s) not added in settings menu. ")
                else: print("Invalid function for specified field; they are incompatible. ")
            else: print("Invalid function. Choose from 'count', 'total', or 'avg'. ")
        elif len(choiceList) == 3 and tool == "graph":
            if func == "cdf":
                TVWS_cdf.cdf_graph(directory, fieldFilter)
            else:
                print("Invalid function. Please choose from 'pdf' or 'bar'")
        else: print("Invalid command, re-enter. ")


def main():
    print("PCAP Trace Processing Tool")
    loop = True

    while loop:
        print("Main Menu: ")
        choice = input()
        if choice == "info":
            print("Main Menu Info: " +
                  "\nInput: " +
                  "\n- 'settings' : Settings menu for setting directory path, filters, and graph type" +
                  "\n- 'process' : Processes .pcap files in specified directory with chosen fields, and outputs them" +
                  " into csv files" +
                  "\n- 'process_<tcp/udp>flows' : Processes .pcap files in specified directory in regards to tcp or udp" +
                  " flows and outputs them into csv files" +
                  "\n- 'tools' : Tools menu for performing calculations and visualizing data" +
                  "\n- 'exit' : Exits PCAP Trace Processing Tool")
        elif choice == "settings":
            settings()
        elif choice == "process":
            TVWS_process.process(directory, fieldFilter, displayFilter, dateFilter1, dateFilter2)
        elif choice == "process_tcpflows" or choice == "process_udpflows":
            if choice == "process_tcpflows": TVWS_process.process_flows(1, directory, dateFilter1, dateFilter2)
            else: TVWS_process.process_flows(2, directory, dateFilter1, dateFilter2)
        elif choice == "tools":
            tools()
        elif choice == "exit":
            loop = False
        else: print("Invalid command, re-enter. ")


main()