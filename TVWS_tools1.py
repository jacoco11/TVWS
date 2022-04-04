# TVWS_tools1 - Munthir Chater

import os
import subprocess
import TVWS_tools2

# GLOBALS
count = 0
total = 0
average = []

tcpURIFilters = ["site_tcpflows", "siteSuccess_tcpflows", "siteFail_tcpflows", "sitePackets_tcpflows",
                 "siteSuccessPackets_tcpflows", "siteFailPackets_tcpflows", "siteBytes_tcpflows", "siteSuccessBytes_tcpflows", "siteFailBytes_tcpflows"]
udpURIFilters = ["site_udpflows", "sitePackets_udpflows", "siteBytes_udpflows"]


# Primary calc function which can perform calculations to obtain general packet statistics
def calc(func, filt, filters, codeOrService, directory, proto, filter3, filter4):
    global count
    global total
    global average
    datefilter = False
    if filter3 != "" and filter4 != "": datefilter = True
    if filt in filters:
        indx = (filters.index(filt))
        indx = str(indx + 1)

    count = 0
    total = 0
    average.clear()

    for file in os.listdir(directory):
        if file.endswith(".csv"):
            if datefilter == True:
                index = 12
                date = ""
                while index < 20:
                    date += file[index]
                    index += 1
            if (datefilter == True and date >= filter3 and date <= filter4) or datefilter == False:
                if func == "count":
                    # Count calculations pertaining to various fields in .pcap files
                    if filt in filters and filt != "http.response.code":
                        try:
                            #command = "awk -F \",\" \"BEGIN{count=0}($"+indx+"!=\\\"\\\"){count=count+1}END{print count}\" " + os.path.join(directory, file)
                            #subprocess.run(command)
                            proc = subprocess.Popen("awk -F \",\" \"BEGIN{count=0}($"+indx+"!=\\\"\\\"){count=count+1}END{print count}\" "
                                                    + os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                            count += int(proc.communicate()[0].decode('ascii'))
                            #print("COUNT: ", count)
                        except:
                            print("ERROR: Could not perform calculation a count calculation. ")
                            continue
                    # Count calculations pertaining to HTTP response codes
                    elif filt == "http.response.code":
                        indx1 = filters.index("http.response.code")
                        indx1 = str(indx1 + 1)
                        proc = subprocess.Popen("awk -F \",\" \"BEGIN{count=0}($" + indx1 + "==\\\"" + codeOrService + "\\\"){count=count+1}END{print count}\" "
                            + os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                        codeTotal = int(proc.communicate()[0].decode('ascii'))
                        count += codeTotal
                    # Count calculations pertaining to control packets (ACK, SYNS, FINS, and retransmissions)
                    elif filt == "cpkt":
                        indx1 = filters.index("tcp.analysis.retransmission")
                        indx2 = filters.index("tcp.flags")
                        indx3 = filters.index("tcp.len")
                        indx1, indx2, indx3 = indx1 + 1, indx2 + 1, indx3 + 1
                        indx1, indx2, indx3 = str(indx1), str(indx2), str(indx3)

                        proc = subprocess.Popen(
                            "awk -F \",\" \"BEGIN{count=0}($" + indx1 + "!=\\\"\\\"||(($" + indx2 + "==\\\"0x00000001\\\"||$" + indx2 +
                            "==\\\"0x00000002\\\"||$" + indx2 + "==\\\"0x00000010\\\")&&$" + indx3 + "==\\\"0\\\")){count=count+1}END{print count}\" "
                            + os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                        cpktTotal = int(proc.communicate()[0].decode('ascii'))
                        count += cpktTotal
                    # Count calculations pertaining to services and domains accessed in TCP and UDP conversations
                    elif filt == "services_tcpflows" or filt == "services_udpflows" or filt == "servicespackets_tcpflows" \
                            or filt == "servicespackets_udpflows" or filt in tcpURIFilters or filt in udpURIFilters:
                        if filt not in tcpURIFilters and filt not in udpURIFilters:
                            if filt == "services_tcpflows": count += TVWS_tools2.calc2(func, filt, directory, file, 1, codeOrService)
                            elif filt == "services_udpflows": count += TVWS_tools2.calc2(func, filt, directory, file, 2, codeOrService)
                            elif filt == "servicespackets_tcpflows": count += TVWS_tools2.calc2(func, filt, directory, file, 1, codeOrService)
                            elif filt == "servicespackets_udpflows": count += TVWS_tools2.calc2(func, filt, directory, file, 2, codeOrService)
                        else:
                            if filt in tcpURIFilters: count += TVWS_tools2.calc2(func, filt, directory, file, 1, codeOrService)
                            elif filt in udpURIFilters: count += TVWS_tools2.calc2(func, filt, directory, file, 2, codeOrService)
                    # Count calculations pertaining to TCP and UDP conversations that do not deal with services or domains accessed
                    else:
                        if proto == 1: count += TVWS_tools2.calc2(func, filt, directory, file, 1, None)
                        else: count += TVWS_tools2.calc2(func, filt, directory, file, 2, None)

                elif func == "total":
                    # Total calculations pertaining to various fields in .pcap files
                    if filt in filters:
                        try:
                            #command = ["awk", "-F", ",", "\"BEGIN{sum=0}{sum=sum+$"+indx+"}END{print", "sum}\"", file]
                            #subprocess.run(command)
                            proc = subprocess.Popen("awk -F \",\" \"BEGIN{total=0}($"+indx+"!=\\\"\\\"){total=total+$"+indx+"}END{print total}\" "
                                                    + os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                            total += float(proc.communicate()[0].decode('ascii'))
                            #print("TOTAL: ", total)
                        except:
                            print("ERROR: Could not perform calculation a total calculation. ")
                            continue
                    # Total calculations pertaining to domains accessed in TCP and UDP conversations
                    elif filt in tcpURIFilters or filt in udpURIFilters:
                        if filt in tcpURIFilters: total += TVWS_tools2.calc2(func, filt, directory, file, 1, codeOrService)
                        elif filt in udpURIFilters: total += TVWS_tools2.calc2(func, filt, directory, file, 2, codeOrService)
                    # Total calculations pertaining to TCP and UDP conversations that do not deal with services or domains accessed
                    else:
                        if proto == 1: total += TVWS_tools2.calc2(func, filt, directory, file, 1, None)
                        else: total += TVWS_tools2.calc2(func, filt, directory, file, 2, None)

                elif func == "avg":
                    # Average calculations pertaining to various fields in .pcap files
                    if filt in filters:
                        try:
                            #command = ["awk", "-F", ",", "BEGIN{sum=0;count=0}{sum=sum+$"+indx+";", "count=count+1}END{print", "sum,count}", file]
                            #subprocess.run(command)
                            proc = subprocess.Popen("awk -F \",\" \"BEGIN{total=0;count=0}($"+indx+"!=\\\"\\\"){total=total+$"+indx+";count=count+1}END{print total,count}\" "
                                                    + os.path.join(directory, file), shell=True, stdout=subprocess.PIPE)
                            result = str(proc.communicate()[0].decode('ascii'))
                            results = result.split()
                            total = float(results[0])
                            count = float(results[1])
                            #print("TOTAL: ", total, "COUNT: ", count)
                            average.append([total, count])
                            count = 0
                            total = 0
                        except:
                            print("ERROR: Could not perform calculation an avg calculation. ")
                            continue
                    # Average calculations pertaining to TCP and UDP conversations that do not deal with services or domains accessed
                    else:
                        if proto == 1: total, count = TVWS_tools2.calc2(func, filt, directory, file, 1, None)
                        else: total, count = TVWS_tools2.calc2(func, filt, directory, file, 2, None)
                        average.append([total, count])
                        count = 0
                        total = 0

    if func == "count": return count
    elif func == "total": return total
    elif func == "avg":
        try:
            totalSum = 0
            totalCount = 0
            for item in average:
                totalSum += item[0]
                totalCount += item[1]
            avg = totalSum / totalCount
            return avg
        except:
            print("Error: Unable to perform calculation")
    else: return None